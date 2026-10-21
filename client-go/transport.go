package link

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// The WebSocket seam. A socket is one connection; the default is gorilla/websocket. A
// channel wraps a socket with a writer goroutine and a queue, and says how much it has been
// handed that is not yet written, so data waits in the client's own queue rather than in
// the socket (the TypeScript client's bufferedAmount rule).

// maxControlBytes: control (text) messages are at most 128 KiB (section 4).
const maxControlBytes = 131072

// socketLowWater: data is handed to a socket only while at most this much waits in it.
const socketLowWater = 65536

// closeError is how a socket reports its end: the close code and reason the peer sent, or
// 1006 for a connection that failed or never opened.
type closeError struct {
	code   int
	reason string
}

func (e *closeError) Error() string { return "websocket closed" }

type socket interface {
	// Read returns the next message. A closed or failed connection returns a *closeError.
	Read() (text bool, data []byte, err error)
	Write(text bool, data []byte) error
	// WriteClose sends a close frame, waiting at most a moment for the network.
	WriteClose(code int) error
	Close() error
	// OnPing sets a function called, on the reading goroutine, for every ping or pong the
	// peer sends (which Read does not return): the relay's liveness pings show it is alive.
	OnPing(f func())
}

type socketDialer func(ctx context.Context, url string) (socket, error)

// dialWebSocket is the default socketDialer: gorilla/websocket with a read limit of one
// frame (1 MiB), above which the connection fails rather than buffers.
func dialWebSocket(ctx context.Context, url string) (socket, error) {
	d := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 30 * time.Second,
		ReadBufferSize:   64 << 10,
		WriteBufferSize:  64 << 10,
	}
	c, resp, err := d.DialContext(ctx, url, nil)
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	c.SetReadLimit(maxFrame)
	return &wsSocket{c: c}, nil
}

type wsSocket struct{ c *websocket.Conn }

func (s *wsSocket) Read() (bool, []byte, error) {
	for {
		mt, data, err := s.c.ReadMessage()
		if err != nil {
			var ce *websocket.CloseError
			if errors.As(err, &ce) {
				return false, nil, &closeError{code: ce.Code, reason: ce.Text}
			}
			return false, nil, &closeError{code: 1006, reason: err.Error()}
		}
		switch mt {
		case websocket.TextMessage:
			return true, data, nil
		case websocket.BinaryMessage:
			return false, data, nil
		}
	}
}

func (s *wsSocket) Write(text bool, data []byte) error {
	mt := websocket.BinaryMessage
	if text {
		mt = websocket.TextMessage
	}
	return s.c.WriteMessage(mt, data)
}

func (s *wsSocket) WriteClose(code int) error {
	return s.c.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, ""), time.Now().Add(time.Second))
}

func (s *wsSocket) Close() error { return s.c.Close() }

func (s *wsSocket) OnPing(f func()) {
	s.c.SetPingHandler(func(data string) error {
		f()
		// As gorilla's default handler: answer with a pong, ignoring a connection closing.
		err := s.c.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(time.Second))
		if err == websocket.ErrCloseSent {
			return nil
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return nil
		}
		return err
	})
	s.c.SetPongHandler(func(string) error {
		f()
		return nil
	})
}

// channel is one socket with an outbound queue drained by a writer goroutine.
type channel struct {
	sock socket

	mu       sync.Mutex
	wake     chan struct{}
	queue    []outFrame
	buffered int   // bytes handed over and not yet written
	enqueued int64 // bytes ever queued
	closing  bool  // no more sends
	dead     bool
	overflow bool // the queue would have passed maxChannelBytes

	drainWanted atomic.Bool
	onDrain     func() // called, with no lock held, when buffered falls to the low water

	lastRead atomic.Int64 // when the peer was last heard from (any frame, ping or pong), monotonic ns
	written  atomic.Int64 // bytes written to the socket
}

type outFrame struct {
	text  bool
	data  []byte
	close bool
	code  int
}

func newChannel(sock socket, onDrain func()) *channel {
	ch := &channel{sock: sock, wake: make(chan struct{}, 1), onDrain: onDrain}
	go ch.writer()
	return ch
}

func (c *channel) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// send queues a message; false when the channel is closing.
// maxChannelBytes bounds what one connection may have queued and not yet written: 64 MiB,
// well above a primary's largest honest burst (a full roster to about 440 members, some
// 29 MB). Message
// data never gets near it (fragments wait while 64 KiB is queued); it is a memory backstop for
// control, which the per-peer budgets keep small. Past it the connection is given up and
// redialled: the queue never blocks and never grows beyond it. A variable for tests.
var maxChannelBytes = 64 << 20

// frameOverhead is what each queued message costs besides its bytes (its slot in the queue,
// the slice header), counted against maxChannelBytes so that the bound is one on memory even
// for many small frames (section 11).
const frameOverhead = 64

// send queues a message; false when the channel is closing, or overflowing (then
// overflowed reports true and the connection must be given up).
func (c *channel) send(text bool, data []byte) bool {
	c.mu.Lock()
	if c.closing || c.dead || c.overflow {
		c.mu.Unlock()
		return false
	}
	if c.buffered+len(data)+frameOverhead > maxChannelBytes {
		c.overflow = true
		c.mu.Unlock()
		return false
	}
	c.queue = append(c.queue, outFrame{text: text, data: data})
	c.buffered += len(data) + frameOverhead
	c.enqueued += int64(len(data))
	c.mu.Unlock()
	c.signal()
	return true
}

func (c *channel) overflowed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.overflow
}

// queuedEnd is the position, in bytes queued since the channel opened, just past the last
// message queued; the message is on the network once written reaches it.
func (c *channel) queuedEnd() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.enqueued
}

// unsent reports whether the message that ended at position end is still queued.
func (c *channel) unsent(end int64) bool { return c.written.Load() < end }

func (c *channel) bufferedAmount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buffered
}

// writable: little enough waits in the socket, or it is gone (and a send fails at once).
func (c *channel) writable() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closing || c.dead || c.buffered <= socketLowWater
}

// wantDrain asks for onDrain once the socket is writable; it reports false when it already
// is, so the caller must not wait.
func (c *channel) wantDrain() bool {
	c.drainWanted.Store(true)
	if c.writable() {
		c.drainWanted.Store(false)
		return false
	}
	return true
}

// close sends what is queued, then a close frame with code, then closes the socket; a
// socket that cannot take them within two seconds is closed anyway.
func (c *channel) close(code int) {
	c.mu.Lock()
	if c.closing || c.dead {
		c.mu.Unlock()
		return
	}
	c.closing = true
	c.queue = append(c.queue, outFrame{close: true, code: code})
	c.mu.Unlock()
	c.signal()
	time.AfterFunc(2*time.Second, c.abort)
}

// abort closes the socket at once and stops the writer.
func (c *channel) abort() {
	c.mu.Lock()
	wasDead := c.dead
	c.dead = true
	c.closing = true
	c.queue = nil
	c.mu.Unlock()
	if !wasDead {
		c.sock.Close()
	}
	c.signal()
}

func (c *channel) writer() {
	for {
		c.mu.Lock()
		for len(c.queue) == 0 && !c.dead {
			c.mu.Unlock()
			<-c.wake
			c.mu.Lock()
		}
		if c.dead {
			c.mu.Unlock()
			return
		}
		f := c.queue[0]
		c.queue[0] = outFrame{}
		c.queue = c.queue[1:]
		c.mu.Unlock()
		if f.close {
			c.sock.WriteClose(f.code)
			c.abort()
			return
		}
		err := c.sock.Write(f.text, f.data)
		c.written.Add(int64(len(f.data)))
		c.mu.Lock()
		c.buffered -= len(f.data) + frameOverhead
		low := c.buffered <= socketLowWater
		c.mu.Unlock()
		if err != nil {
			c.abort()
			c.drainWanted.Store(false)
			if c.onDrain != nil {
				c.onDrain() // whoever waits to write learns at once that the socket is gone
			}
			return
		}
		if low && c.drainWanted.CompareAndSwap(true, false) && c.onDrain != nil {
			c.onDrain()
		}
	}
}
