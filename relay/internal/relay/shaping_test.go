package relay

import (
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// Section 9: the relay tells every member of a network its shaping, at registration and
// whenever it changes, and its own answers to a member go ahead of the routed frames queued
// for it.

// A member that has its queue in the relay full of routed frames still has its usage answered
// at once: the answer goes ahead of those frames, not behind them.
func TestOwnMessagesAheadOfRoutedFrames(t *testing.T) {
	const queue = 4 << 20
	h := start(t, func(c *Config) { c.QueueBytes = queue })
	p, w := keys(t, 1), keys(t, 2)
	r := roster(t, 1, p, w)
	pc := h.register(p, p, r, smallBuffers) // reads nothing until asked
	wc := h.register(w, p, r)
	var stop atomic.Bool
	go func() {
		for !stop.Load() {
			if wc.ws.WriteMessage(websocket.BinaryMessage, frame(typeData, p.ID, make([]byte, 64<<10-18))) != nil {
				return
			}
		}
	}()
	defer stop.Store(true)
	pn := netKeys(t, p).ID
	deadline := time.Now().Add(10 * time.Second)
	for h.s.queuedFor(pn, p.ID) < queue-(256<<10) {
		if time.Now().After(deadline) {
			t.Fatalf("the relay queued only %d bytes for the primary", h.s.queuedFor(pn, p.ID))
		}
		time.Sleep(10 * time.Millisecond)
	}
	pc.send(map[string]any{"type": "usage", "id": "u"})
	pc.send(map[string]any{"type": "nonsense", "id": "n"})
	// What comes before the answers is only what had left the relay's queue already: the frame
	// being written and the small socket buffers, never the megabytes queued behind them.
	var before int
	var texts []map[string]any
	for len(texts) < 2 {
		typ, b, err := pc.next(10 * time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if typ == websocket.TextMessage {
			texts = append(texts, pc.json2(b))
			continue
		}
		before += len(b)
	}
	if texts[0]["type"] != "usage" || texts[1]["type"] != "error" || texts[1]["code"] != "bad_request" {
		t.Fatalf("answers %v", texts)
	}
	if before > 1<<20 {
		t.Fatalf("%d bytes of routed frames came before the answers, with %d queued", before, queue)
	}
	t.Logf("%d bytes of routed frames before the answers", before)
}

// The trickle is announced when the quota is spent, to every member and to one that registers
// while it holds; and its end is announced too, once the hour's charges are below the quota
// again, with no traffic needed to notice.
func TestShapingNoticeWhenTheTrickleBeginsAndLifts(t *testing.T) {
	h := start(t, func(c *Config) {
		c.RateBps = 1_000_000
		c.QuotaBytesHour = 50_000
		c.TrickleBps = 20_000
		c.PingInterval = time.Hour
	})
	p, w, x := keys(t, 1), keys(t, 2), keys(t, 3)
	r := roster(t, 1, p, w, x)
	pc, wc := h.register(p, p, r), h.register(w, p, r)
	normal := map[string]any{"type": "shaping", "rateBps": float64(1_000_000), "slowed": false}
	slowed := map[string]any{"type": "shaping", "rateBps": float64(20_000), "slowed": true}
	if !reflect.DeepEqual(pc.shaping, normal) || !reflect.DeepEqual(wc.shaping, normal) {
		t.Fatalf("at registration: %v and %v", pc.shaping, wc.shaping)
	}
	began := time.Now()
	for range 6 {
		wc.sendBinary(frame(typeData, p.ID, make([]byte, 10_000)))
	}
	for _, c := range []*client{pc, wc} {
		for {
			typ, b, err := c.next(5 * time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if typ == websocket.TextMessage {
				if m := c.json2(b); !reflect.DeepEqual(m, slowed) {
					t.Fatalf("told %v", m)
				}
				break
			}
		}
	}
	if el := time.Since(began); el > time.Second {
		t.Fatalf("told after %v", el)
	}
	// A member registering now is told the trickle holds.
	if xc := h.register(x, p, r); !reflect.DeepEqual(xc.shaping, slowed) {
		t.Fatalf("x told %v at registration", xc.shaping)
	}

	// An hour later the charges have aged out of the window (here: the window emptied, as the
	// clock would): within about a second every member is told, without sending anything.
	n := h.s.networkOf(netKeys(t, p).ID)
	n.mu.Lock()
	n.hour = hourWindow{}
	n.mu.Unlock()
	lifted := time.Now()
	if m := wc.json(); !reflect.DeepEqual(m, normal) {
		t.Fatalf("told %v", m)
	}
	if el := time.Since(lifted); el > 2*time.Second {
		t.Fatalf("lift told after %v", el)
	}
	// The primary still has the frames it was sent to read first: they came before the lift.
	for {
		typ, b, err := pc.next(5 * time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if typ == websocket.TextMessage {
			if m := pc.json2(b); !reflect.DeepEqual(m, normal) {
				t.Fatalf("primary told %v", m)
			}
			break
		}
	}
	pc.quiet(300 * time.Millisecond)
}
