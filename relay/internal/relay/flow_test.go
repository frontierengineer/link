package relay

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// sendAndTime sends frames of size bytes from one member to another and returns how long
// it took for all of them to arrive.
func sendAndTime(t *testing.T, h *harness, frames, size int) time.Duration {
	p, w := keys(t, 1), keys(t, 2)
	r := roster(t, 1, p, w)
	pc, wc := h.register(p, p, r), h.register(w, p, r)
	began := time.Now()
	go func() {
		for range frames {
			if wc.ws.WriteMessage(websocket.BinaryMessage, frame(typeData, p.ID, make([]byte, size-18))) != nil {
				return
			}
		}
	}()
	for range frames {
		pc.frame()
	}
	return time.Since(began)
}

func TestShapingSlowsANetwork(t *testing.T) {
	// 500 kB at 200 kB/s with one second of burst. A frame is relayed and then its debt is
	// waited off, so the last frame arrives once the first 450 kB have been paid: 1.25 s.
	shaped := sendAndTime(t, start(t, func(c *Config) { c.RateBps = 200_000 }), 10, 50_000)
	if shaped < 1150*time.Millisecond || shaped > 4*time.Second {
		t.Fatalf("shaped transfer took %v, want about 1.25 s", shaped)
	}
	free := sendAndTime(t, start(t, nil), 10, 50_000)
	if free > 700*time.Millisecond {
		t.Fatalf("unshaped transfer took %v", free)
	}
	t.Logf("shaped %v, unshaped %v", shaped, free)
}

func TestQuotaTrickleAndUsage(t *testing.T) {
	h := start(t, func(c *Config) {
		c.QuotaBytesHour = 100_000
		c.TrickleBps = 50_000
		c.PingInterval = time.Hour // no pongs in the count
	})
	p, w, absent := keys(t, 1), keys(t, 2), keys(t, 3)
	r := roster(t, 1, p, w, absent)
	pc, wc := h.register(p, p, r), h.register(w, p, r)

	// The quota: 100 kB goes at full speed.
	const size = 10_000
	began := time.Now()
	for range 10 {
		wc.sendBinary(frame(typeData, p.ID, make([]byte, size-18)))
	}
	for range 10 {
		pc.frame()
	}
	if el := time.Since(began); el > 700*time.Millisecond {
		t.Fatalf("within quota took %v", el)
	}
	// Then the trickle: 100 kB at 50 kB/s with one second of burst, at least a second.
	began = time.Now()
	for range 10 {
		wc.sendBinary(frame(typeData, p.ID, make([]byte, size-18)))
	}
	for range 10 {
		pc.frame()
	}
	if el := time.Since(began); el < 800*time.Millisecond {
		t.Fatalf("over quota took only %v", el)
	}

	ask := `{"type":"usage","id":"u1"}`
	pc.ws.WriteMessage(websocket.TextMessage, []byte(ask))
	u := pc.json()
	// Exactly what crossed: every frame at its size on the wire, and the ask itself.
	charged := 20*wire(size) + wire(len(ask))
	want := map[string]any{"type": "usage", "id": "u1", "network": map[string]any{
		"bytesHour": float64(charged), "connections": float64(2), "quotaUsed": float64(charged) / 100_000, "slowed": true,
		"limits": map[string]any{"rateBps": float64(0), "quotaBytesHour": float64(100_000), "trickleBps": float64(50_000)},
	}}
	if !reflect.DeepEqual(u, want) {
		t.Fatalf("usage:\n got %v\nwant %v", u, want)
	}
	// Nothing is pushed: no alert came, and none comes.
	pc.quiet(300 * time.Millisecond)

	// Usage is the primary's only.
	wc.send(map[string]any{"type": "usage", "id": "u2"})
	if m := wc.json(); m["type"] != "error" || m["code"] != "forbidden" || m["id"] != "u2" {
		t.Fatalf("got %v", m)
	}
}

func (c *client) json2(b []byte) map[string]any {
	c.t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		c.t.Fatal(err)
	}
	return m
}

// Everything a member sends is charged, delivered or not, and so is every answer it is sent.
func TestUsageCountsEverything(t *testing.T) {
	h := start(t, func(c *Config) { c.PingInterval = time.Hour })
	p, w, absent := keys(t, 1), keys(t, 2), keys(t, 3)
	r := roster(t, 1, p, w, absent)
	pc, wc := h.register(p, p, r), h.register(w, p, r)
	for range 3 {
		wc.sendBinary(frame(typeData, p.ID, make([]byte, 100)))
		pc.frame()
	}
	pc.sendBinary(frame(typeData, w.ID, make([]byte, 2)))
	wc.frame()
	// To a member that is not connected: the frame, and the unreachable answer.
	pc.sendBinary(frame(typeData, absent.ID, make([]byte, 50)))
	if f := pc.frame(); f[1] != typeUnreachable {
		t.Fatalf("got %x", f)
	}
	// A control message the relay does not know, and its error.
	dance := `{"type":"dance"}`
	pc.ws.WriteMessage(websocket.TextMessage, []byte(dance))
	_, answer, _ := pc.next(5 * time.Second)
	// A ping, and its pong.
	pc.ws.WriteControl(websocket.PingMessage, []byte("hi"), time.Now().Add(time.Second))
	// (gorilla consumes the pong while reading the usage answer.)
	ask := `{"type":"usage","id":"x"}`
	pc.ws.WriteMessage(websocket.TextMessage, []byte(ask))
	_, answered, _ := pc.next(5 * time.Second)
	u := pc.json2(answered)
	want := 3*wire(118) + wire(20) + wire(68) + wireSize(18) + wire(len(dance)) + wireSize(len(answer)) +
		wire(2) + wireSize(2) + wire(len(ask))
	if got := u["network"].(map[string]any)["bytesHour"]; got != float64(want) {
		t.Fatalf("bytesHour %v, want %d", got, want)
	}
	// The answer to that ask counts too.
	pc.ws.WriteMessage(websocket.TextMessage, []byte(ask))
	want += wireSize(len(answered)) + wire(len(ask))
	if got := pc.json()["network"].(map[string]any)["bytesHour"]; got != float64(want) {
		t.Fatalf("bytesHour %v, want %d", got, want)
	}
}

// Asks are limited per network: three at once, then refused with the request's id, not queued.
func TestUsageAskBudget(t *testing.T) {
	h := start(t, nil)
	p := keys(t, 1)
	pc := h.register(p, p, roster(t, 1, p))
	for i := range usageBurst {
		pc.send(map[string]any{"type": "usage", "id": strconv.Itoa(i)})
		if m := pc.json(); m["type"] != "usage" || m["id"] != strconv.Itoa(i) {
			t.Fatalf("ask %d: %v", i, m)
		}
	}
	pc.send(map[string]any{"type": "usage", "id": "over"})
	if m := pc.json(); m["type"] != "error" || m["code"] != "rate_limited" || m["id"] != "over" {
		t.Fatalf("got %v", m)
	}
	// The budget is the network's: the primary reconnecting does not refill it.
	pc2 := h.register(p, p, roster(t, 1, p))
	pc2.send(map[string]any{"type": "usage", "id": "again"})
	if m := pc2.json(); m["code"] != "rate_limited" {
		t.Fatalf("got %v", m)
	}
}

// A recipient that does not read: the relay stops reading its sender once the recipient's
// queue passes LINK_QUEUE_BYTES; with the default 0, as soon as a frame is not taken by the
// recipient's socket, so the relay holds at most one frame for it. Nothing is dropped once it
// reads again.
func TestBackPressurePausesTheSender(t *testing.T) {
	const frames, size = 400, 64 << 10
	for _, queue := range []int64{0, 256 << 10} {
		h := start(t, func(c *Config) { c.QueueBytes = queue })
		p, w := keys(t, 1), keys(t, 2)
		r := roster(t, 1, p, w)
		pc := h.register(p, p, r, smallBuffers)
		wc := h.register(w, p, r, smallBuffers)
		var sent atomic.Int64
		go func() {
			for i := range frames {
				body := make([]byte, size-18)
				binary.BigEndian.PutUint32(body, uint32(i))
				if wc.ws.WriteMessage(websocket.BinaryMessage, frame(typeData, p.ID, body)) != nil {
					return
				}
				sent.Add(1)
			}
		}()
		// Wait until the sender stops making progress (or finishes).
		last, still, most := int64(-1), time.Now(), int64(0)
		for time.Since(still) < time.Second && sent.Load() < frames {
			if n := sent.Load(); n != last {
				last, still = n, time.Now()
			}
			most = max(most, h.s.queuedFor(p.ID, p.ID))
			time.Sleep(5 * time.Millisecond)
		}
		if most > queue+int64(wireSize(size)) {
			t.Fatalf("queue %d: the recipient's queue reached %d bytes", queue, most)
		}
		stalled := sent.Load()
		if stalled >= frames {
			t.Fatalf("queue %d: the sender was never paused", queue)
		}
		t.Logf("queue %d: sender paused after %d of %d frames (%d MB in kernel buffers), relay queue peaked at %d", queue, stalled, frames, stalled*size>>20, most)
		// Reading resumes the sender, and every frame arrives in order.
		for i := range frames {
			f := pc.frame()
			if len(f) != size || binary.BigEndian.Uint32(f[18:]) != uint32(i) {
				t.Fatalf("frame %d: %d bytes, index %d", i, len(f), binary.BigEndian.Uint32(f[18:]))
			}
		}
		if sent.Load() != frames {
			t.Fatalf("sent %d", sent.Load())
		}
	}
}

// A recipient that drains nothing with a full queue for LINK_SLOW_PEER_SEC is closed 4006,
// and the senders it held back go on (to unreachable).
func TestSlowPeerIsClosed(t *testing.T) {
	h := start(t, func(c *Config) {
		c.QueueBytes = 128 << 10
		c.SlowPeer = time.Second
		c.CloseGrace = 10 * time.Second
	})
	p, w := keys(t, 1), keys(t, 2)
	r := roster(t, 1, p, w)
	pc := h.register(p, p, r, smallBuffers)
	wc := h.register(w, p, r)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if wc.ws.WriteMessage(websocket.BinaryMessage, frame(typeData, p.ID, make([]byte, 32<<10))) != nil {
				return
			}
		}
	}()
	defer close(stop)
	began := time.Now()
	for {
		f := wc.frame()
		if f[1] == typeUnreachable && peerOf(f) == p.ID {
			break
		}
	}
	if el := time.Since(began); el < time.Second {
		t.Fatalf("recipient dropped after %v, before LINK_SLOW_PEER_SEC", el)
	}
	// The slow peer, reading at last, finds the 4006 after what was already on the wire.
	pc.expectClose(4006)
}

func TestNetworkForgottenAfterTTL(t *testing.T) {
	h := start(t, func(c *Config) { c.NetworkTTL = 300 * time.Millisecond })
	p := keys(t, 1)
	pc := h.register(p, p, roster(t, 5, p))
	pc.ws.Close()
	time.Sleep(50 * time.Millisecond)
	// Still remembered: presenting version 3, it is handed the 5 the relay holds.
	c := h.dial()
	c.send(h.registerMsg(c, p, p.ID.String(), roster(t, 3, p)))
	if m := c.json(); m["rosterVersion"] != float64(5) || m["roster"] == nil {
		t.Fatalf("got %v", m)
	}
	c.ws.Close()
	time.Sleep(700 * time.Millisecond)
	c = h.dial()
	c.send(h.registerMsg(c, p, p.ID.String(), roster(t, 3, p)))
	if m := c.json(); m["type"] != "registered" || m["rosterVersion"] != float64(3) || m["roster"] != nil {
		t.Fatalf("got %v", m)
	}
}

func TestNetworkKeptWhileAMemberIsConnected(t *testing.T) {
	h := start(t, func(c *Config) { c.NetworkTTL = 200 * time.Millisecond })
	p, w := keys(t, 1), keys(t, 2)
	r5 := roster(t, 5, p, w)
	h.register(w, p, r5)
	time.Sleep(600 * time.Millisecond)
	c := h.dial()
	c.send(h.registerMsg(c, p, p.ID.String(), roster(t, 3, p, w)))
	if m := c.json(); m["rosterVersion"] != float64(5) {
		t.Fatalf("got %v", m)
	}
}

func TestPingClosesASilentPeer(t *testing.T) {
	h := start(t, func(c *Config) { c.PingInterval = 200 * time.Millisecond })
	p, w := keys(t, 1), keys(t, 2)
	r := roster(t, 1, p, w)
	silent := h.register(p, p, r)
	silent.ws.SetPingHandler(func(string) error { return nil }) // never answers
	alive := h.register(w, p, r)
	aliveErr := make(chan error, 1)
	go func() { // gorilla answers pings while it reads
		_, _, err := alive.next(1500 * time.Millisecond)
		aliveErr <- err
	}()
	began := time.Now()
	if code := silent.closeCode(3 * time.Second); code != websocket.CloseAbnormalClosure {
		t.Fatalf("closed %d", code)
	}
	// Pinged at most an interval after registering, it is dropped once the next ping finds
	// the first unanswered: one to two intervals in.
	if el := time.Since(began); el < 190*time.Millisecond {
		t.Fatalf("dropped after %v", el)
	}
	var ne net.Error
	if err := <-aliveErr; !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("the answering peer: %v", err)
	}
}

func TestShutdownClosesGoingAway(t *testing.T) {
	h := start(t, nil)
	p, w := keys(t, 1), keys(t, 2)
	r := roster(t, 1, p, w)
	pc, wc := h.register(p, p, r), h.register(w, p, r)
	n := h.dial()
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		done <- h.s.Shutdown(ctx)
	}()
	pc.expectClose(1001)
	wc.expectClose(1001)
	n.expectClose(1001)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// A peer that sends to absent members but never reads its unreachable answers stops being
// read once its own answers queued in the relay pass 64 KiB.
func TestBackPressureOnAnswersToTheSender(t *testing.T) {
	h := start(t, nil)
	p, w := keys(t, 1), keys(t, 2)
	pc := h.register(p, p, roster(t, 1, p, w), smallBuffers)
	c := h.s.networkOf(p.ID).members[p.ID]
	go func() {
		f := frame(typeData, w.ID, nil)
		for range 10_000_000 {
			if pc.ws.WriteMessage(websocket.BinaryMessage, f) != nil {
				return
			}
		}
	}()
	deadline := time.Now().Add(30 * time.Second)
	for {
		c.wmu.Lock()
		q, r := c.queued, c.replies
		c.wmu.Unlock()
		if q > int64(replySlack+wireSize(18)) {
			t.Fatalf("own queue reached %d bytes", q)
		}
		if r > replySlack && c.paused.Load() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("never paused: %d bytes of answers queued", r)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
