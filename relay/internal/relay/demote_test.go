package relay

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/frontierengineer/link/relay/internal/link"
)

// Section 4.2: the primary is whichever member the relay's roster names primary. When a newer
// roster names another, the former primary's connection is demoted in place: never closed, no
// close code, still registered and routing; its pairing channels end, and its usage asks are
// refused. The new primary's connection is the primary connection at once.
func TestNewPrimaryDemotesTheFormerInPlace(t *testing.T) {
	h := start(t, nil)
	p, w, x := keys(t, 1), keys(t, 2), keys(t, 3)
	nk := netKeys(t, p)
	r1 := roster(t, 1, p, w, x)
	pc, wc, xc := h.register(p, p, r1), h.register(w, p, r1), h.register(x, p, r1)

	// A pairing in flight on the primary's connection.
	code := b64([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	n := h.dial()
	n.send(map[string]any{"type": "pair", "network": netID(p), "code": code})
	if m := pc.json(); m["type"] != "pairing" {
		t.Fatalf("primary got %v", m)
	}
	nm := n.json()

	// w, given the network seed, claims the primary: it pushes the roster naming itself primary
	// with p an ordinary member, from a connection that is not yet the relay's primary.
	r2 := rosterOf(t, 2, nk, w, p, x)
	wc.send(map[string]any{"type": "roster", "roster": json.RawMessage(r2)})

	// Its pairing channel ends, both sides told, the newcomer closed 1000; the former primary is not.
	if m := pc.json(); m["type"] != "pairEnd" || m["channel"] != nm["channel"] {
		t.Fatalf("former primary got %v", m)
	}
	if m := n.json(); m["type"] != "pairEnd" {
		t.Fatalf("newcomer got %v", m)
	}
	n.expectClose(1000)

	// Nobody is disconnected: the former primary still routes both ways, as a member.
	pc.sendBinary(frame(typeData, w.ID, []byte("from the former primary")))
	if f := wc.frame(); string(f[18:]) != "from the former primary" || peerOf(f) != p.ID {
		t.Fatalf("w got %q", f)
	}
	xc.sendBinary(frame(typeData, p.ID, []byte("to the former primary")))
	if f := pc.frame(); string(f[18:]) != "to the former primary" || peerOf(f) != x.ID {
		t.Fatalf("p got %q", f)
	}

	// Usage is the new primary's now, and no longer the former primary's.
	pc.send(map[string]any{"type": "usage", "id": "u1"})
	if m := pc.json(); m["type"] != "error" || m["code"] != "forbidden" || m["id"] != "u1" {
		t.Fatalf("former primary's usage: %v", m)
	}
	wc.send(map[string]any{"type": "usage", "id": "u2"})
	if m := wc.json(); m["type"] != "usage" || m["id"] != "u2" {
		t.Fatalf("new primary's usage: %v", m)
	}

	// Pairing reaches the new primary.
	n2 := h.dial()
	n2.send(map[string]any{"type": "pair", "network": netID(p), "code": code})
	if m := wc.json(); m["type"] != "pairing" || m["code"] != code {
		t.Fatalf("new primary got %v", m)
	}
	n2m := n2.json()

	// Any member may deliver a newer roster: x, primary in neither, delivers one naming p again.
	// w is demoted in place in its turn, its pairing channel ended.
	r3 := rosterOf(t, 3, nk, p, w, x)
	xc.send(map[string]any{"type": "roster", "roster": json.RawMessage(r3)})
	if m := wc.json(); m["type"] != "pairEnd" || m["channel"] != n2m["channel"] {
		t.Fatalf("w got %v", m)
	}
	n2.json()
	n2.expectClose(1000)
	pc.send(map[string]any{"type": "usage", "id": "u3"})
	if m := pc.json(); m["type"] != "usage" {
		t.Fatalf("p's usage once named again: %v", m)
	}
	wc.send(map[string]any{"type": "usage", "id": "u4"})
	if m := wc.json(); m["code"] != "forbidden" {
		t.Fatalf("w's usage after it was demoted: %v", m)
	}

	// A new primary the relay learns at a registration demotes in place too: a member, y,
	// registers presenting version 4, which names x primary.
	y := keys(t, 4)
	r4 := rosterOf(t, 4, nk, x, p, w, y)
	yc := h.dial()
	yc.send(h.registerMsg(yc, y, netID(p), r4))
	if m := yc.json(); m["type"] != "registered" || m["rosterVersion"] != float64(4) {
		t.Fatalf("y got %v", m)
	}
	pc.send(map[string]any{"type": "usage", "id": "u5"})
	if m := pc.json(); m["code"] != "forbidden" {
		t.Fatalf("p's usage after the registration's roster: %v", m)
	}
	xc.send(map[string]any{"type": "usage", "id": "u6"})
	if m := xc.json(); m["type"] != "usage" {
		t.Fatalf("x's usage: %v", m)
	}

	// Through all three changes of primary, no connection was closed: each still routes, and none is closed
	// after (quiet ends a gorilla connection's reads, so it comes last).
	id := map[*client]link.ID{pc: p.ID, wc: w.ID, xc: x.ID, yc: y.ID}
	for i, pair := range [][2]*client{{pc, yc}, {wc, pc}, {yc, xc}} {
		from, to := pair[0], pair[1]
		from.sendBinary(frame(typeData, id[to], []byte("still connected")))
		if f := to.frame(); string(f[18:]) != "still connected" {
			t.Fatalf("pair %d: got %q", i, f)
		}
	}
	for _, c := range []*client{pc, wc, xc, yc} {
		c.quiet(200 * time.Millisecond)
	}
}
