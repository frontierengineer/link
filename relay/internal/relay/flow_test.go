package relay

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
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

func TestQuotaTrickleUsageAndAlerts(t *testing.T) {
	h := start(t, func(c *Config) {
		c.QuotaBytesHour = 100_000
		c.TrickleBps = 50_000
	})
	p, w, absent := keys(t, 1), keys(t, 2), keys(t, 3)
	r := roster(t, 1, p, w, absent)
	pc, wc := h.register(p, p, r), h.register(w, p, r)

	var alerts []map[string]any
	readFrames := func(n int) {
		for n > 0 {
			typ, b, err := pc.next(10 * time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if typ == websocket.BinaryMessage {
				n--
				continue
			}
			m := pc.json2(b)
			if m["type"] != "usageAlert" {
				t.Fatalf("got %v", m)
			}
			alerts = append(alerts, m)
		}
	}
	// The quota: 100 kB goes at full speed.
	began := time.Now()
	for range 10 {
		wc.sendBinary(frame(typeData, p.ID, make([]byte, 10_000-18)))
	}
	readFrames(10)
	if el := time.Since(began); el > 700*time.Millisecond {
		t.Fatalf("within quota took %v", el)
	}
	// Then the trickle: 100 kB at 50 kB/s with one second of burst, at least a second.
	began = time.Now()
	for range 10 {
		wc.sendBinary(frame(typeData, p.ID, make([]byte, 10_000-18)))
	}
	readFrames(10)
	if el := time.Since(began); el < 800*time.Millisecond {
		t.Fatalf("over quota took only %v", el)
	}

	pc.send(map[string]any{"type": "usage", "id": "u1"})
	var u map[string]any
	for u == nil {
		m := pc.json()
		switch m["type"] {
		case "usage":
			u = m
		case "usageAlert":
			alerts = append(alerts, m)
		default:
			t.Fatalf("got %v", m)
		}
	}
	nw := u["network"].(map[string]any)
	if u["id"] != "u1" || nw["bytesHour"] != float64(200_000) || nw["bytesDay"] != float64(200_000) ||
		nw["connections"] != float64(2) || nw["quotaUsed"] != float64(2) || nw["slowed"] != true {
		t.Fatalf("usage: %v", u)
	}
	lim := nw["limits"].(map[string]any)
	if lim["rateBps"] != float64(0) || lim["quotaBytesHour"] != float64(100_000) || lim["trickleBps"] != float64(50_000) {
		t.Fatalf("limits: %v", lim)
	}
	members := u["members"].([]any)
	if len(members) != 3 {
		t.Fatalf("members: %v", members)
	}
	for _, mv := range members {
		m := mv.(map[string]any)
		switch m["id"] {
		case w.ID.String():
			if m["bytesHour"] != float64(200_000) || m["bytesDay"] != float64(200_000) || m["connected"] != true {
				t.Fatalf("w: %v", m)
			}
		case p.ID.String():
			if m["bytesHour"] != float64(0) || m["connected"] != true {
				t.Fatalf("p: %v", m)
			}
		case absent.ID.String():
			if m["connected"] != false {
				t.Fatalf("absent: %v", m)
			}
		default:
			t.Fatalf("unknown member %v", m)
		}
	}
	// The alerts: at most one a second, the last saying the network is slowed. Wait for the
	// one the once-a-second rule held back.
	deadline := time.Now().Add(3 * time.Second)
	for len(alerts) == 0 || alerts[len(alerts)-1]["slowed"] != true {
		if time.Now().After(deadline) {
			t.Fatalf("alerts: %v", alerts)
		}
		m := pc.json()
		if m["type"] == "usageAlert" {
			alerts = append(alerts, m)
		}
	}
	if alerts[0]["quotaUsed"].(float64) < 0.5 {
		t.Fatalf("first alert %v", alerts[0])
	}
	t.Logf("alerts: %v", alerts)

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

func TestUsageWithoutLimits(t *testing.T) {
	h := start(t, nil)
	p, w := keys(t, 1), keys(t, 2)
	r := roster(t, 1, p, w)
	pc, wc := h.register(p, p, r), h.register(w, p, r)
	for range 3 {
		wc.sendBinary(frame(typeData, p.ID, make([]byte, 100)))
		pc.frame()
	}
	pc.sendBinary(frame(typeData, w.ID, make([]byte, 2)))
	wc.frame()
	pc.send(map[string]any{"type": "usage", "id": "x"})
	u := pc.json()
	nw := u["network"].(map[string]any)
	if nw["bytesHour"] != float64(3*118+20) || nw["quotaUsed"] != float64(0) || nw["slowed"] != false {
		t.Fatalf("usage %v", u)
	}
	for _, mv := range u["members"].([]any) {
		m := mv.(map[string]any)
		want := float64(3 * 118)
		if m["id"] == p.ID.String() {
			want = 20
		}
		if m["bytesHour"] != want {
			t.Fatalf("member %v", m)
		}
	}
}

// A recipient that does not read: its queue fills to LINK_QUEUE_BYTES and the relay stops
// reading the sender, which then cannot write; nothing is dropped once it reads again.
func TestBackPressurePausesTheSender(t *testing.T) {
	const frames, size = 400, 64 << 10
	run := func(queue int64) (stalledAt int64, h *harness, pc *client, sent *atomic.Int64) {
		h = start(t, func(c *Config) { c.QueueBytes = queue })
		p, w := keys(t, 1), keys(t, 2)
		r := roster(t, 1, p, w)
		pc = h.register(p, p, r, smallBuffers)
		wc := h.register(w, p, r, smallBuffers)
		sent = &atomic.Int64{}
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
		last, still := int64(-1), time.Now()
		for time.Since(still) < time.Second && sent.Load() < frames {
			if n := sent.Load(); n != last {
				last, still = n, time.Now()
			}
			if q := h.s.queuedFor(p.ID, p.ID); queue > 0 && q > queue+size {
				t.Fatalf("queue for the recipient reached %d bytes", q)
			}
			time.Sleep(10 * time.Millisecond)
		}
		return sent.Load(), h, pc, sent
	}

	// Without a threshold the relay keeps reading: the sender finishes though nobody reads.
	if n, _, _, _ := run(0); n != frames {
		t.Fatalf("without back-pressure the sender stalled at %d frames", n)
	}

	stalled, _, pc, sent := run(256 << 10)
	if stalled >= frames {
		t.Fatal("the sender was never paused")
	}
	t.Logf("sender paused after %d of %d frames (%d MB)", stalled, frames, stalled*size>>20)
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
	if el := time.Since(began); el < 300*time.Millisecond {
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

// A peer that sends to absent members but never reads its unreachable answers is paused
// once its own queue passes the threshold.
func TestBackPressureOnAnswersToTheSender(t *testing.T) {
	h := start(t, func(c *Config) { c.QueueBytes = 64 << 10 })
	p, w := keys(t, 1), keys(t, 2)
	pc := h.register(p, p, roster(t, 1, p, w), smallBuffers)
	var sent atomic.Int64
	go func() {
		f := frame(typeData, w.ID, nil)
		for range 1_000_000 {
			if pc.ws.WriteMessage(websocket.BinaryMessage, f) != nil {
				return
			}
			sent.Add(1)
		}
	}()
	last, still := int64(-1), time.Now()
	for time.Since(still) < time.Second {
		if n := sent.Load(); n != last {
			last, still = n, time.Now()
		}
		if q := h.s.queuedFor(p.ID, p.ID); q > 64<<10+18 {
			t.Fatalf("own queue reached %d bytes", q)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if last >= 1_000_000 {
		t.Fatal("never paused")
	}
	t.Logf("paused after %d frames", last)
}
