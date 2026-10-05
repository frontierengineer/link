package relay

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/gobwas/ws"

	"github.com/frontierengineer/link/relay/internal/link"
)

// The reader: frame headers straight from the socket through a 14-byte scratch, payloads into
// buffers that grow as bytes arrive, shaping deferred to the body of the next data frame, and,
// with the poller, no goroutine at all between messages.

// firstChunk is the most a payload buffer starts at; it doubles as bytes arrive, so a peer
// that declares a large frame and sends little of it costs little.
const firstChunk = 16 << 10

// What reads a connection: its own goroutine, or nobody until the poller sees it readable.
const (
	readRunning uint32 = iota
	readParked
)

var errHeader = errors.New("malformed frame header")

type helloMsg struct {
	Type      string   `json:"type"`
	Version   int      `json:"version"`
	Challenge string   `json:"challenge"`
	Features  []string `json:"features"`
}

// serve runs from the upgrade: hello, then the reader.
func (c *conn) serve() {
	c.sendJSON(helloMsg{Type: "hello", Version: 1, Challenge: link.B64u.EncodeToString(c.challenge[:]), Features: []string{"control"}})
	c.nc.SetReadDeadline(time.Now().Add(c.s.cfg.HelloTimeout))
	c.run()
}

// run reads frames until the connection ends, then finishes it; or, between messages of a
// registered connection with nothing to read, parks it and returns.
func (c *conn) run() {
	peerClosed := false
	var msg []byte // a fragmented message being joined, headroom in front
	var msgOp ws.OpCode
	inMsg, wire := false, 0
loop:
	for {
		if !inMsg && c.rbOff == c.rbEnd && c.parkable() {
			err := c.probe()
			if err == errWouldBlock {
				if c.park() {
					return
				}
				continue
			}
			if err != nil {
				break
			}
		}
		h, hl, err := c.readHeader()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && c.state == stateHello && !c.isClosing() {
				c.closeWith(closeBadRequest, "no register or pair in time", false)
			} else if err == errHeader {
				c.closeWith(closeProtocol, "protocol error", false)
			}
			break
		}
		if c.state != stateRegistered {
			if c.frames++; c.frames > maxEarly {
				c.closeWith(closeBadRequest, "too many frames before registering", false)
				break
			}
		}
		if !h.Masked || h.Rsv != 0 {
			c.closeWith(closeProtocol, "protocol error", false)
			break
		}
		size := hl + int(h.Length)
		if h.OpCode.IsControl() {
			if !h.Fin || h.Length > 125 {
				c.closeWith(closeProtocol, "protocol error", false)
				break
			}
			if h.OpCode != ws.OpClose && c.held() {
				c.holdUnless(true, size)
			}
			p, err := c.readBody(h, nil)
			if err != nil {
				break
			}
			p = p[headroom:]
			switch h.OpCode {
			case ws.OpPing:
				c.charge(size + 2 + len(p)) // the ping, and the pong it is owed
				c.answerPing(p)
			case ws.OpPong:
				c.charge(size)
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
			}
			if peerClosed {
				break
			}
			continue
		}
		if c.isClosing() {
			break // only the peer's close frame matters now
		}
		switch h.OpCode {
		case ws.OpContinuation:
			if !inMsg {
				c.closeWith(closeProtocol, "protocol error", false)
				break loop
			}
		case ws.OpText, ws.OpBinary:
			if inMsg {
				c.closeWith(closeProtocol, "protocol error", false)
				break loop
			}
			msgOp, inMsg, wire = h.OpCode, true, 0
		default:
			c.closeWith(closeProtocol, "protocol error", false)
			break loop
		}
		have := int64(0)
		if msg != nil {
			have = int64(len(msg) - headroom)
		}
		if have+h.Length > c.limit(msgOp) {
			c.closeWith(closeBadRequest, "message too large", false)
			break
		}
		// Shaping (section 9): the body of a data frame waits for the network's bucket. Control
		// in one unfragmented frame goes ahead within the network's control budget; a routed
		// frame's type is read from its first 18 bytes, before the rest of its body.
		var peek func(head []byte)
		if c.held() {
			whole := msg == nil && h.Fin
			switch {
			case whole && msgOp == ws.OpText:
				c.holdUnless(true, size)
			case whole && msgOp == ws.OpBinary && h.Length >= frameHeader:
				peek = func(head []byte) { c.holdUnless(controlType(head[1]), size) }
			default:
				c.sleepUntil(c.holdUntil)
			}
		}
		p, err := c.readBody(h, peek)
		if err != nil {
			break
		}
		wire += size
		if msg == nil {
			msg = p
		} else {
			msg = append(msg, p[headroom:]...)
		}
		if !h.Fin {
			continue
		}
		data := msg
		msg, inMsg = nil, false
		var ok bool
		if msgOp == ws.OpText {
			ok = c.handleText(data[headroom:], wire)
		} else {
			ok = c.handleBinary(data, wire)
		}
		if !ok {
			break
		}
		// A connection that asks but does not read its answers stops being read.
		c.waitReplies()
	}
	c.finalize(peerClosed)
}

// controlType is a routed frame type that shaping lets ahead within the control budget.
func controlType(t byte) bool {
	switch t {
	case typeInit, typeResp, typeRefused, typeReset, typeControl, typePair:
		return true
	}
	return false
}

// limit is the largest message of op this connection may send now.
func (c *conn) limit(op ws.OpCode) int64 {
	if op == ws.OpText {
		return maxText
	}
	switch c.state {
	case stateRegistered:
		return maxBinary
	case statePairing:
		return maxPairFrame
	}
	return 0
}

// held reports whether shaping holds this connection back now.
func (c *conn) held() bool {
	return c.state == stateRegistered && c.holdUntil > c.s.mono()
}

// holdUnless holds the body of a frame of size bytes back until the network's bucket allows,
// unless it is control and the network's control budget takes it.
func (c *conn) holdUnless(control bool, size int) {
	if control && c.network.allowControl(c.s, size) {
		return
	}
	c.sleepUntil(c.holdUntil)
}

// charge counts size bytes against a registered member's network (section 9) and defers the
// wait the network's bucket asks for to the next data frame's body.
func (c *conn) charge(size int) {
	n := c.network
	if n == nil || c.state != stateRegistered {
		return
	}
	now := c.s.mono()
	n.mu.Lock()
	wait := c.s.chargeLocked(n, size, now)
	n.mu.Unlock()
	c.holdFor(now, wait)
}

func (c *conn) holdFor(now int64, wait time.Duration) {
	if wait > 0 {
		c.holdUntil = max(c.holdUntil, now+int64(wait))
	}
}

// read reads from the bytes left over from the upgrade, then the socket.
func (c *conn) read(p []byte) (int, error) {
	if len(c.early) > 0 {
		n := copy(p, c.early)
		if c.early = c.early[n:]; len(c.early) == 0 {
			c.early = nil
		}
		return n, nil
	}
	return c.nc.Read(p)
}

// probe fills the header scratch with what the socket holds, without waiting: errWouldBlock
// when it holds nothing. The scratch is empty when it is called.
func (c *conn) probe() error {
	if len(c.early) > 0 {
		return nil
	}
	n, err := rawIO(c.rc, c.rb[:], false)
	switch {
	case err == syscall.EAGAIN || err == syscall.EINTR:
		return errWouldBlock
	case err != nil:
		return err
	case n == 0:
		return io.EOF
	}
	c.rbOff, c.rbEnd = 0, uint8(n)
	return nil
}

// readHeader parses the next frame header from the scratch, reading as needed. A read may
// bring the first payload bytes too (or more frames, when they are small); they stay in the
// scratch for whatever reads next.
func (c *conn) readHeader() (ws.Header, int, error) {
	for {
		h, hl, err := parseHeader(c.rb[c.rbOff:c.rbEnd])
		if err != nil {
			return h, 0, err
		}
		if hl > 0 {
			c.rbOff += uint8(hl)
			return h, hl, nil
		}
		if c.rbOff > 0 {
			n := copy(c.rb[:], c.rb[c.rbOff:c.rbEnd])
			c.rbOff, c.rbEnd = 0, uint8(n)
		}
		n, err := c.read(c.rb[c.rbEnd:])
		c.rbEnd += uint8(n)
		if n == 0 && err != nil {
			return h, 0, err
		}
	}
}

// parseHeader reads a WebSocket frame header (RFC 6455 section 5.2) from the front of b:
// its length in bytes, or 0 when b does not hold all of it yet.
func parseHeader(b []byte) (h ws.Header, hl int, err error) {
	if len(b) < 2 {
		return h, 0, nil
	}
	h.Fin = b[0]&0x80 != 0
	h.Rsv = (b[0] >> 4) & 0x7
	h.OpCode = ws.OpCode(b[0] & 0x0f)
	h.Masked = b[1]&0x80 != 0
	n := int64(b[1] & 0x7f)
	hl = 2
	switch n {
	case 126:
		hl += 2
	case 127:
		hl += 8
	}
	if h.Masked {
		hl += 4
	}
	if len(b) < hl {
		return h, 0, nil
	}
	switch n {
	case 126:
		n = int64(binary.BigEndian.Uint16(b[2:]))
	case 127:
		u := binary.BigEndian.Uint64(b[2:])
		if u>>63 != 0 {
			return h, 0, errHeader
		}
		n = int64(u)
	}
	h.Length = n
	if h.Masked {
		copy(h.Mask[:], b[hl-4:hl])
	}
	return h, hl, nil
}

// readBody reads h's payload, unmasked, into a buffer with headroom free bytes in front of it.
// With peek, the first bytes (up to a Link header's 18) are read and shown to it before the
// rest, so shaping can tell a routed frame's type before holding its body back.
func (c *conn) readBody(h ws.Header, peek func(head []byte)) ([]byte, error) {
	n := int(h.Length)
	b := make([]byte, headroom+min(n, firstChunk))
	got := 0
	fill := func(upto int) error {
		for got < upto {
			if headroom+got == len(b) {
				nb := make([]byte, headroom+min(n, 2*(len(b)-headroom)))
				copy(nb, b)
				b = nb
			}
			dst := b[headroom+got : min(len(b), headroom+upto)]
			var k int
			if c.rbOff < c.rbEnd {
				k = copy(dst, c.rb[c.rbOff:c.rbEnd])
				c.rbOff += uint8(k)
			} else {
				var err error
				if k, err = c.read(dst); k == 0 && err != nil {
					return err
				}
			}
			ws.Cipher(dst[:k], h.Mask, got)
			got += k
		}
		return nil
	}
	if peek != nil {
		if err := fill(min(n, frameHeader)); err != nil {
			return nil, err
		}
		peek(b[headroom : headroom+got])
	}
	if err := fill(n); err != nil {
		return nil, err
	}
	return b, nil
}

// parkable: a registered connection with the poller, between messages, may give its
// goroutine up.
func (c *conn) parkable() bool {
	return c.s.poll != nil && c.rc != nil && !c.noPark && c.state == stateRegistered &&
		len(c.early) == 0 && !c.isClosing()
}

// park hands the connection to the poller, which starts a reader again when the socket is
// readable. It returns false when this goroutine must go on reading after all.
//
// From the moment reading is marked parked, a wake-up (or, once the socket is armed, the
// poller) may start a new reader at once, so everything the reader owns is settled before
// that, and nothing of it is touched after unless reading is taken back.
func (c *conn) park() bool {
	add := !c.armed
	c.armed = true
	c.reading.Store(readParked)
	closing := c.isClosing()
	if !closing && c.s.poll.arm(c, add) {
		return true
	}
	if !c.reading.CompareAndSwap(readParked, readRunning) {
		return true // a wake-up got there first, and its reader reads now
	}
	// Not parked after all, and still this goroutine's.
	if add {
		c.armed = false
	}
	if !closing {
		c.noPark = true // the poller refused it
	}
	return false
}

// wake starts a reader for a parked connection: the poller saw it readable, or it is closing
// and must read the peer's answer and finish.
func (c *conn) wake() {
	if c.reading.CompareAndSwap(readParked, readRunning) {
		go c.run()
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
		var scratch [512]byte
		for {
			if _, err := c.read(scratch[:]); err != nil {
				break
			}
		}
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
