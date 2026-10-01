package relay

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"sync"
	"sync/atomic"
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
	maxText   = 1 << 20 // a control message (section 4)
	maxBinary = 1 << 20 // a routed frame, header included (section 6)
)

type connState uint8

const (
	stateHello connState = iota
	stateRegistered
	statePairing
)

type outFrame struct {
	op   ws.OpCode
	p    []byte
	data bool // counts towards the queue
}

// conn is one WebSocket. Memory when idle is the point of its shape: one goroutine blocked
// reading a frame header straight from the socket (no bufio), no writer goroutine (one is
// started when something is queued and exits when the queue is empty), and no buffers.
type conn struct {
	s         *Server
	nc        net.Conn
	r         io.Reader
	ip        string
	shardIx   uint8
	origin    string // used once, to check the registration signature
	challenge [32]byte

	// Owned by the reader goroutine.
	state   connState
	network *network
	id      link.ID
	channel *channel // a newcomer's pairing channel

	// Fixed at registration, under network.mu.
	primary bool
	pairs   map[link.ID]*channel // a primary's pairing channels, under Server.chmu

	paused       atomic.Bool // reading is held back by shaping or back-pressure
	awaitingPong atomic.Bool

	wmu        sync.Mutex // a leaf lock: nothing else is taken while it is held
	ctrl       []outFrame
	q          []outFrame
	queued     int64
	writing    bool
	closing    bool
	closeFrame []byte
	closeSent  bool
	readerDone bool
	below      chan struct{} // closed when queued drops to the threshold; made on demand
	lastDrain  time.Time
	fullSince  time.Time
	slowTimer  *time.Timer
	done       chan struct{} // closed when closing starts
}

func appendHeader(b []byte, op ws.OpCode, n int) []byte {
	b = append(b, 0x80|byte(op))
	switch {
	case n < 126:
		return append(b, byte(n))
	case n <= 0xffff:
		return binary.BigEndian.AppendUint16(append(b, 126), uint16(n))
	default:
		return binary.BigEndian.AppendUint64(append(b, 127), uint64(n))
	}
}

// overLocked is the queue's "full" state: above LINK_QUEUE_BYTES, or with no threshold
// set, anything waiting at all (which is what the slow-peer timer then measures).
func (c *conn) overLocked() bool {
	if lim := c.s.cfg.QueueBytes; lim > 0 {
		return c.queued > lim
	}
	return c.queued > 0
}

func (c *conn) enqueue(f outFrame) bool {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closing {
		return false
	}
	if f.data {
		c.q = append(c.q, f)
		c.queued += int64(len(f.p))
		if c.s.cfg.SlowPeer > 0 && c.slowTimer == nil && c.overLocked() {
			c.fullSince = time.Now()
			c.slowTimer = time.AfterFunc(c.s.cfg.SlowPeer, c.checkSlow)
		}
	} else {
		c.ctrl = append(c.ctrl, f)
	}
	c.kickLocked()
	return true
}

func (c *conn) sendBinary(p []byte) bool {
	return c.enqueue(outFrame{op: ws.OpBinary, p: p, data: true})
}

func (c *conn) sendJSON(v any) bool {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return c.enqueue(outFrame{op: ws.OpText, p: b, data: true})
}

type errorMsg struct {
	Type    string `json:"type"`
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
	ID      string `json:"id,omitempty"`
}

func (c *conn) sendError(code, message, id string) {
	c.sendJSON(errorMsg{Type: "error", Code: code, Message: message, ID: id})
}

func (c *conn) kickLocked() {
	if !c.writing {
		c.writing = true
		go c.writeLoop()
	}
}

func (c *conn) writeLoop() {
	for {
		c.wmu.Lock()
		var f outFrame
		switch {
		case len(c.ctrl) > 0:
			f = c.ctrl[0]
			if c.ctrl = c.ctrl[1:]; len(c.ctrl) == 0 {
				c.ctrl = nil
			}
		case len(c.q) > 0:
			f = c.q[0]
			c.q[0] = outFrame{}
			if c.q = c.q[1:]; len(c.q) == 0 {
				c.q = nil
			}
		case c.closeFrame != nil && !c.closeSent:
			f = outFrame{op: ws.OpClose, p: c.closeFrame}
			c.closeSent = true
		default:
			c.writing = false
			if c.readerDone {
				c.nc.Close()
			}
			c.wmu.Unlock()
			return
		}
		c.wmu.Unlock()

		var hdr [10]byte
		bufs := net.Buffers{appendHeader(hdr[:0], f.op, len(f.p)), f.p}
		_, err := bufs.WriteTo(c.nc)
		if err == nil && f.op == ws.OpClose {
			// Half-close, so unread input the peer sent does not turn the close into a reset,
			// and give the peer a moment to answer.
			if cw, ok := c.nc.(interface{ CloseWrite() error }); ok {
				cw.CloseWrite()
			}
			c.nc.SetReadDeadline(time.Now().Add(c.s.cfg.CloseGrace))
		}

		c.wmu.Lock()
		if f.data {
			// A close without flush already zeroed the count this frame was part of.
			c.queued = max(0, c.queued-int64(len(f.p)))
			c.lastDrain = time.Now()
			c.releaseLocked()
		}
		if err != nil {
			c.beginCloseLocked(false)
			c.closeSent = true
			c.writing = false
			c.wmu.Unlock()
			c.nc.Close()
			return
		}
		c.wmu.Unlock()
	}
}

// releaseLocked wakes senders paused on this queue and stops the slow-peer timer once the
// queue is back at or below the threshold.
func (c *conn) releaseLocked() {
	lim := c.s.cfg.QueueBytes
	if c.below != nil && (c.closing || lim <= 0 || c.queued <= lim) {
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
	since := c.fullSince
	if c.lastDrain.After(since) {
		since = c.lastDrain
	}
	if left := c.s.cfg.SlowPeer - time.Since(since); left > 0 {
		c.slowTimer.Reset(left)
		c.wmu.Unlock()
		return
	}
	c.slowTimer = nil
	c.wmu.Unlock()
	c.closeWith(closeSlowPeer, "slow peer", false)
}

// beginCloseLocked marks the connection closing. Without flush, whatever is queued is
// dropped; with it, the queue is still written before the close frame.
func (c *conn) beginCloseLocked(flush bool) bool {
	if c.closing {
		return false
	}
	c.closing = true
	close(c.done)
	c.ctrl = nil
	if !flush {
		c.q = nil
		c.queued = 0
	}
	c.releaseLocked()
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
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.closing
}

// waitQueue pauses this connection's reading while dst's queue is over the threshold.
func (c *conn) waitQueue(dst *conn) {
	lim := c.s.cfg.QueueBytes
	if lim <= 0 {
		return
	}
	for {
		dst.wmu.Lock()
		if dst.closing || dst.queued <= lim {
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
		}
	}
	c.resume()
}

// sleep pauses this connection's reading for d (network shaping).
func (c *conn) sleep(d time.Duration) {
	if d <= 0 {
		return
	}
	c.paused.Store(true)
	t := time.NewTimer(d)
	select {
	case <-t.C:
	case <-c.done:
	}
	t.Stop()
	c.resume()
}

func (c *conn) resume() {
	if c.paused.Swap(false) {
		// Pongs were not read while paused; do not hold that against the peer.
		c.awaitingPong.Store(false)
	}
}

func (c *conn) readPayload(h ws.Header) ([]byte, error) {
	p := make([]byte, h.Length)
	if _, err := io.ReadFull(c.r, p); err != nil {
		return nil, err
	}
	ws.Cipher(p, h.Mask, 0)
	return p, nil
}

func (c *conn) serve() {
	peerClosed := false
	defer func() { c.finalize(peerClosed) }()
	c.sendJSON(helloMsg{Type: "hello", Version: 1, Challenge: link.B64u.EncodeToString(c.challenge[:])})
	c.nc.SetReadDeadline(time.Now().Add(c.s.cfg.HelloTimeout))
	var msg []byte
	var msgOp ws.OpCode
	inMsg := false
	for {
		h, err := ws.ReadHeader(c.r)
		if ne, ok := err.(net.Error); ok && ne.Timeout() && c.state == stateHello {
			c.closeWith(closeBadRequest, "no register or pair in time", false)
			return
		}
		if err != nil {
			return
		}
		if !h.Masked || h.Rsv != 0 {
			c.closeWith(closeProtocol, "protocol error", false)
			return
		}
		if h.OpCode.IsControl() {
			if !h.Fin || h.Length > 125 {
				c.closeWith(closeProtocol, "protocol error", false)
				return
			}
			p, err := c.readPayload(h)
			if err != nil {
				return
			}
			switch h.OpCode {
			case ws.OpPing:
				c.enqueue(outFrame{op: ws.OpPong, p: p})
			case ws.OpPong:
				c.awaitingPong.Store(false)
			case ws.OpClose:
				code := closeNormal
				if len(p) >= 2 {
					if sc, _ := ws.ParseCloseFrameData(p); sc >= 3000 && sc <= 4999 || sc >= 1000 && sc <= 1003 || sc >= 1007 && sc <= 1011 {
						code = int(sc)
					}
				}
				c.closeWith(code, "", false)
				peerClosed = true
				return
			}
			continue
		}
		if c.isClosing() {
			return // only the peer's close frame matters now
		}
		switch h.OpCode {
		case ws.OpContinuation:
			if !inMsg {
				c.closeWith(closeProtocol, "protocol error", false)
				return
			}
		case ws.OpText, ws.OpBinary:
			if inMsg {
				c.closeWith(closeProtocol, "protocol error", false)
				return
			}
			msgOp, inMsg = h.OpCode, true
		default:
			c.closeWith(closeProtocol, "protocol error", false)
			return
		}
		limit := int64(maxBinary)
		if msgOp == ws.OpText {
			limit = maxText
		}
		if int64(len(msg))+h.Length > limit {
			c.closeWith(closeBadRequest, "message too large", false)
			return
		}
		p, err := c.readPayload(h)
		if err != nil {
			return
		}
		if msg == nil && h.Fin {
			msg = p
		} else {
			msg = append(msg, p...)
		}
		if !h.Fin {
			continue
		}
		data := msg
		msg, inMsg = nil, false
		var ok bool
		if msgOp == ws.OpText {
			ok = c.handleText(data)
		} else {
			ok = c.handleBinary(data)
		}
		if !ok {
			return
		}
		// Answers queued for this connection itself (errors, usage, unreachable) are
		// back-pressure too: a peer that sends but never reads is paused like any other.
		c.waitQueue(c)
	}
}

// finalize runs when the reader stops: the connection leaves every table, input is drained
// until the peer answers our close (unless it already sent its own, or the grace runs out),
// and the socket is closed once the writer is done with it.
func (c *conn) finalize(peerClosed bool) {
	c.closeWith(0, "", false)
	c.s.unregister(c)
	if !peerClosed {
		c.nc.SetReadDeadline(time.Now().Add(c.s.cfg.CloseGrace))
		io.Copy(io.Discard, c.r)
	}
	c.wmu.Lock()
	c.readerDone = true
	writing := c.writing
	c.wmu.Unlock()
	if !writing {
		c.nc.Close()
	}
	c.s.conns.Done()
}
