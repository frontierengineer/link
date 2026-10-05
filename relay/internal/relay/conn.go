package relay

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gobwas/ws"

	"github.com/frontierengineer/link/relay/internal/link"
)

// Close codes (section 10, and RFC 6455's protocol error).
const (
	closeNormal      = 1000
	closeGoingAway   = 1001
	closeProtocol    = 1002
	closeBadRequest  = 4000
	closeRateLimited = 4002
	closeReplaced    = 4005
	closeSlowPeer    = 4006
	closeAuth        = 4007
	closeNotMember   = 4008
)

const (
	maxText      = 128 << 10 // a control message (section 4)
	maxBinary    = 1 << 20   // a routed frame, header included (section 6)
	maxPairFrame = 1024      // a pairing newcomer's pair frame (section 6)
	maxEarly     = 16        // frames a connection may send before it is registered (section 4.1)
	replySlack   = 64 << 10  // a connection's own answers queued before its reading pauses (section 9)

	// headroom is kept free in front of every payload the relay holds, so the frame header
	// it writes goes there and a frame leaves in one write: the largest unmasked header.
	headroom = 10
)

type connState uint8

const (
	stateHello connState = iota
	stateRegistered
	statePairing
)

// What a frame being written is, for the queue's accounting.
const (
	kindData  uint8 = iota // relayed, or relay-originated text such as registered and pairing
	kindReply              // an answer to this connection's own request: error, usage, unreachable
	kindCtl                // a ping or a pong, outside the queue
	kindClose              // the close frame
)

type outFrame struct {
	b    []byte // the whole frame as it goes on the wire, header included
	kind uint8
}

// conn is one WebSocket. Memory when idle is the point of its shape: no buffers (a 14-byte
// header scratch), no writer goroutine (frames are written inline when the socket takes them,
// and a writer is started only for one that it does not), and, when parked (poll_linux.go),
// no reader goroutine either.
type conn struct {
	s         *Server
	nc        net.Conn
	rc        syscall.RawConn // non-blocking reads and writes; nil when the relay terminates TLS
	key       uint64          // the connection's id in the server's table and the poller
	ip        string          // the limiter key (section 9), until registered
	ipc       *ipCount        // its address's connection count (section 9)
	ipPending bool            // counted there as not registered
	origin    string          // used once, to check the registration signature
	challenge [32]byte
	early     []byte // bytes read past the upgrade request, consumed before the socket

	// Owned by the reader.
	state     connState
	frames    uint8 // frames read before registered
	rb        [14]byte
	rbOff     uint8
	rbEnd     uint8
	armed     bool  // added to the poller
	noPark    bool  // the poller refused it: read with a goroutine of its own
	holdUntil int64 // s.mono(): the body of the next data frame is not read before this
	network   *network
	id        link.ID
	channel   *channel // a newcomer's pairing channel

	// Fixed at registration, under network.mu.
	primary bool
	pairs   map[link.ID]*channel // a primary's pairing channels, under Server.chmu

	paused       atomic.Bool   // reading is held back by shaping or back-pressure
	awaitingPong atomic.Bool   // a ping went out and no pong has come back
	reading      atomic.Uint32 // readRunning or readParked

	wmu        sync.Mutex // a leaf lock: nothing else is taken while it is held
	cur        []byte     // the rest of the frame being written; never dropped, as part of it is out
	curKind    uint8
	curSize    int64 // the whole frame's size, for the queue's count
	pingDue    bool
	pong       []byte // the latest ping's payload, while its pong is due
	pongDue    bool
	q          []outFrame
	queued     int64 // bytes of data frames queued or being written
	replies    int64 // of which answers to this connection's own requests
	writing    bool  // a writer (inline or goroutine) owns the socket's write side
	closing    bool
	closeFrame []byte
	closeSent  bool
	readerDone bool
	below      chan struct{} // closed whenever the queue shrinks; made on demand
	lastDrain  int64         // s.mono() of the last data frame written
	fullSince  int64
	slowTimer  *time.Timer
	done       chan struct{} // closed when closing starts
}

// frameWire turns p, which has headroom free bytes in front of its payload, into one
// unfragmented, unmasked WebSocket frame, in place.
func frameWire(op ws.OpCode, p []byte) []byte {
	n := len(p) - headroom
	hl := 2
	switch {
	case n > 0xffff:
		hl = 10
	case n >= 126:
		hl = 4
	}
	b := p[headroom-hl:]
	b[0] = 0x80 | byte(op)
	switch hl {
	case 2:
		b[1] = byte(n)
	case 4:
		b[1] = 126
		binary.BigEndian.PutUint16(b[2:], uint16(n))
	default:
		b[1] = 127
		binary.BigEndian.PutUint64(b[2:], uint64(n))
	}
	return b
}

// withHeadroom copies b behind headroom free bytes.
func withHeadroom(b []byte) []byte {
	p := make([]byte, headroom+len(b))
	copy(p[headroom:], b)
	return p
}

// overLocked is the queue's "full" state for the slow-peer rule: above LINK_QUEUE_BYTES,
// which at 0 means anything waiting at all.
func (c *conn) overLocked() bool {
	return c.queued > c.s.cfg.QueueBytes
}

// enqueue queues a data frame (p has headroom in front of its payload) and starts writing.
func (c *conn) enqueue(op ws.OpCode, p []byte, kind uint8) bool {
	b := frameWire(op, p)
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closing {
		return false
	}
	c.queued += int64(len(b))
	if kind == kindReply {
		c.replies += int64(len(b))
	}
	if !c.writing {
		// Nothing ahead of it: it is the frame being written (most often inline, at once).
		c.cur, c.curKind, c.curSize = b, kind, int64(len(b))
	} else {
		c.q = append(c.q, outFrame{b: b, kind: kind})
	}
	c.kickLocked()
	// Judged once the inline write is done: a frame the socket took at once never waited.
	if c.s.cfg.SlowPeer > 0 && c.slowTimer == nil && c.overLocked() {
		c.fullSince = c.s.mono()
		c.slowTimer = time.AfterFunc(c.s.cfg.SlowPeer, c.checkSlow)
	}
	return true
}

// sendBinary relays a routed frame (p has headroom in front of it).
func (c *conn) sendBinary(p []byte) bool {
	return c.enqueue(ws.OpBinary, p, kindData)
}

func (c *conn) sendJSON(v any) bool {
	return c.enqueue(ws.OpText, marshal(v), kindData)
}

func marshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return withHeadroom(b)
}

// reply queues an answer to this connection's own request. A registered member's network is
// charged for it (section 9), so asking cannot draw unmetered traffic out of the relay.
func (c *conn) reply(op ws.OpCode, p []byte) {
	c.charge(wireSize(len(p) - headroom))
	c.enqueue(op, p, kindReply)
}

// wireSize is the size on the wire of a frame the relay sends with an n-byte payload.
func wireSize(n int) int {
	switch {
	case n > 0xffff:
		return 10 + n
	case n >= 126:
		return 4 + n
	}
	return 2 + n
}

type errorMsg struct {
	Type    string `json:"type"`
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
	ID      string `json:"id,omitempty"`
}

func (c *conn) sendError(code, message, id string) {
	c.reply(ws.OpText, marshal(errorMsg{Type: "error", Code: code, Message: message, ID: id}))
}

// ping queues the relay's liveness ping.
func (c *conn) ping() {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closing {
		return
	}
	c.pingDue = true
	c.kickLocked()
}

// answerPing queues a pong for p, replacing one still due: only the latest ping is
// answered (RFC 6455 section 5.5.3), so a flood of pings never grows the queue.
func (c *conn) answerPing(p []byte) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closing {
		return
	}
	c.pong, c.pongDue = p, true
	c.kickLocked()
}

// kickLocked makes sure something writes what is queued. When nothing is being written, the
// caller writes inline, without blocking, for as long as the socket takes whole frames; a
// writer goroutine takes over only from the first write it does not.
func (c *conn) kickLocked() {
	if c.writing {
		return
	}
	c.writing = true
	if c.rc != nil {
		c.wmu.Unlock()
		finished := c.drain(false)
		c.wmu.Lock()
		if finished {
			return
		}
	}
	go c.drain(true)
}

// nextLocked picks what to write next: the rest of a frame already started, then the pong,
// the ping, the data queue, and the close frame last.
func (c *conn) nextLocked() bool {
	if c.cur != nil {
		return true
	}
	switch {
	case c.pongDue:
		c.cur, c.curKind = frameWire(ws.OpPong, withHeadroom(c.pong)), kindCtl
		c.pong, c.pongDue = nil, false
	case c.pingDue:
		c.cur, c.curKind = frameWire(ws.OpPing, make([]byte, headroom)), kindCtl
		c.pingDue = false
	case len(c.q) > 0:
		f := c.q[0]
		c.q[0] = outFrame{}
		if c.q = c.q[1:]; len(c.q) == 0 {
			c.q = nil
		}
		c.cur, c.curKind = f.b, f.kind
	case c.closeFrame != nil && !c.closeSent:
		c.cur, c.curKind = frameWire(ws.OpClose, withHeadroom(c.closeFrame)), kindClose
		c.closeSent = true
	default:
		return false
	}
	c.curSize = int64(len(c.cur))
	return true
}

var errWouldBlock = errors.New("would block")

// write writes b: blocking (the writer goroutine), or one non-blocking attempt that may
// take part of it.
func (c *conn) write(b []byte, block bool) (int, error) {
	if block {
		return c.nc.Write(b)
	}
	n, err := rawIO(c.rc, b, true)
	if err == syscall.EAGAIN || err == syscall.EINTR {
		err = errWouldBlock
	}
	return n, err
}

// drain writes until nothing is left (true), or, when not blocking, until the socket stops
// taking what it is given (false: the caller hands over to a writer goroutine). It runs with
// writing set, so there is one writer at a time.
func (c *conn) drain(block bool) bool {
	for {
		c.wmu.Lock()
		if !c.nextLocked() {
			c.writing = false
			if c.readerDone {
				c.nc.Close()
			}
			c.wmu.Unlock()
			return true
		}
		b := c.cur
		c.wmu.Unlock()

		n, err := c.write(b, block)

		c.wmu.Lock()
		if err != nil && err != errWouldBlock {
			c.beginCloseLocked(false)
			c.cur, c.closeSent, c.writing = nil, true, false
			c.wmu.Unlock()
			c.nc.Close()
			return true
		}
		if n < len(b) {
			c.cur = b[n:]
			c.wmu.Unlock()
			if !block {
				return false
			}
			continue
		}
		c.finishedLocked()
		c.wmu.Unlock()
	}
}

// finishedLocked settles the frame just written whole.
func (c *conn) finishedLocked() {
	switch c.curKind {
	case kindData, kindReply:
		// A close without flush already zeroed the count this frame was part of.
		c.queued = max(0, c.queued-c.curSize)
		if c.curKind == kindReply {
			c.replies = max(0, c.replies-c.curSize)
		}
		c.lastDrain = c.s.mono()
		c.releaseLocked()
	case kindClose:
		// Half-close, so unread input the peer sent does not turn the close into a reset, and
		// give the peer a moment to answer.
		if cw, ok := c.nc.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		c.nc.SetReadDeadline(time.Now().Add(c.s.cfg.CloseGrace))
	}
	c.cur = nil
}

// releaseLocked wakes those waiting for this queue to shrink, and stops the slow-peer timer
// once the queue is no longer full.
func (c *conn) releaseLocked() {
	if c.below != nil {
		close(c.below)
		c.below = nil
	}
	if c.slowTimer != nil && (c.closing || !c.overLocked()) {
		c.slowTimer.Stop()
		c.slowTimer = nil
	}
}

func (c *conn) checkSlow() {
	c.wmu.Lock()
	if c.closing || c.slowTimer == nil {
		c.wmu.Unlock()
		return
	}
	if !c.overLocked() {
		c.slowTimer = nil
		c.wmu.Unlock()
		return
	}
	since := max(c.fullSince, c.lastDrain)
	if left := c.s.cfg.SlowPeer - time.Duration(c.s.mono()-since); left > 0 {
		c.slowTimer.Reset(left)
		c.wmu.Unlock()
		return
	}
	c.slowTimer = nil
	c.wmu.Unlock()
	c.closeWith(closeSlowPeer, "slow peer", false)
}

// beginCloseLocked marks the connection closing. Without flush, whatever is queued is
// dropped; with it, the queue is still written before the close frame. A parked reader is
// woken, so it reads the peer's answer and finishes the connection.
func (c *conn) beginCloseLocked(flush bool) bool {
	if c.closing {
		return false
	}
	c.closing = true
	close(c.done)
	c.pingDue, c.pong, c.pongDue = false, nil, false
	if !flush {
		c.q = nil
		c.queued, c.replies = 0, 0
	}
	c.releaseLocked()
	c.wake()
	return true
}

// closeWith closes the connection with a WebSocket close code (0: none, the peer is gone).
func (c *conn) closeWith(code int, reason string, flush bool) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if !c.beginCloseLocked(flush) {
		return
	}
	if code == 0 {
		return
	}
	c.closeFrame = ws.NewCloseFrameBody(ws.StatusCode(code), reason)
	// Bounds the frame being written now (if the peer is not reading), the flush and the
	// close frame together.
	c.nc.SetWriteDeadline(time.Now().Add(c.s.cfg.CloseGrace))
	c.kickLocked()
}

// abort drops the connection without a close frame.
func (c *conn) abort() {
	c.closeWith(0, "", false)
	c.nc.Close()
}

func (c *conn) isClosing() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// waitFor pauses this connection's reading until full reports false for dst's queue (or
// dst closes).
func (c *conn) waitFor(dst *conn, full func(*conn) bool) {
	for {
		dst.wmu.Lock()
		if dst.closing || !full(dst) {
			dst.wmu.Unlock()
			break
		}
		if dst.below == nil {
			dst.below = make(chan struct{})
		}
		ch := dst.below
		dst.wmu.Unlock()
		c.paused.Store(true)
		select {
		case <-ch:
		case <-c.done:
			c.unpause()
			return
		}
	}
	c.unpause()
}

// waitQueue is back-pressure (section 9): a sender is not read again while the recipient it
// just fed holds more than LINK_QUEUE_BYTES.
func (c *conn) waitQueue(dst *conn) {
	c.waitFor(dst, (*conn).overLocked)
}

// waitReplies pauses a connection that does not read the answers it asks for.
func (c *conn) waitReplies() {
	c.waitFor(c, func(c *conn) bool { return c.replies > replySlack })
}

// sleepUntil pauses this connection's reading until t (s.mono()), for shaping.
func (c *conn) sleepUntil(t int64) {
	d := time.Duration(t - c.s.mono())
	if d <= 0 {
		return
	}
	c.paused.Store(true)
	tm := time.NewTimer(d)
	select {
	case <-tm.C:
	case <-c.done:
	}
	tm.Stop()
	c.unpause()
}

func (c *conn) unpause() {
	if c.paused.Swap(false) {
		// Pongs were not read while paused; do not hold that against the peer.
		c.awaitingPong.Store(false)
	}
}
