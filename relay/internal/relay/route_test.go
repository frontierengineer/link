package relay

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/frontierengineer/link/relay/internal/link"
)

func TestRoutingWithinANetwork(t *testing.T) {
	h := start(t, nil)
	p, w, s := keys(t, 1), keys(t, 2), keys(t, 3)
	r := roster(t, 1, p, w, s)
	pc, wc := h.register(p, p, r), h.register(w, p, r)

	for _, typ := range []byte{typeInit, typeResp, typeData, typeRefused, typeReset} {
		body := []byte{typ, 0, 0, 0, 7, 'x'}
		wc.sendBinary(frame(typ, p.ID, body))
		f := pc.frame()
		if f[0] != 1 || f[1] != typ || peerOf(f) != w.ID || !bytes.Equal(f[18:], body) {
			t.Fatalf("type %d: got %x", typ, f)
		}
	}
	pc.sendBinary(frame(typeData, w.ID, []byte("back")))
	if f := wc.frame(); peerOf(f) != p.ID || string(f[18:]) != "back" {
		t.Fatalf("got %x", f)
	}
	// An empty body is still a frame.
	wc.sendBinary(frame(typeData, p.ID, nil))
	if f := pc.frame(); len(f) != 18 {
		t.Fatalf("got %x", f)
	}
	// A member on the roster that is not connected: unreachable, naming that peer.
	wc.sendBinary(frame(typeData, s.ID, []byte("x")))
	if f := wc.frame(); f[1] != typeUnreachable || peerOf(f) != s.ID || len(f) != 18 {
		t.Fatalf("got %x", f)
	}
	pc.quiet(100 * time.Millisecond)
}

func TestNoRoutingAcrossNetworks(t *testing.T) {
	h := start(t, nil)
	a, aw := keys(t, 1), keys(t, 2)
	b := keys(t, 3)
	ra := roster(t, 1, a, aw)
	ac, awc := h.register(a, a, ra), h.register(aw, a, ra)
	bc := h.register(b, b, roster(t, 1, b))

	bc.sendBinary(frame(typeData, a.ID, []byte("intruder")))
	if f := bc.frame(); f[1] != typeUnreachable || peerOf(f) != a.ID {
		t.Fatalf("got %x", f)
	}
	ac.sendBinary(frame(typeData, b.ID, []byte("out")))
	if f := ac.frame(); f[1] != typeUnreachable || peerOf(f) != b.ID {
		t.Fatalf("got %x", f)
	}
	ac.quiet(100 * time.Millisecond)
	awc.quiet(10 * time.Millisecond)
	bc.quiet(10 * time.Millisecond)
}

func TestFrameRules(t *testing.T) {
	h := start(t, nil)
	p, w := keys(t, 1), keys(t, 2)
	r := roster(t, 1, p, w)
	pc, wc := h.register(p, p, r), h.register(w, p, r)

	// Exactly 1 MiB, header included, is routed (gorilla sends it fragmented).
	big := frame(typeData, p.ID, bytes.Repeat([]byte{0xab}, maxBinary-18))
	wc.sendBinary(big)
	if f := pc.frame(); len(f) != maxBinary || peerOf(f) != w.ID || f[maxBinary-1] != 0xab {
		t.Fatalf("got %d bytes", len(f))
	}

	cases := map[string]func(*client){
		"one byte over 1 MiB":     func(c *client) { c.sendBinary(frame(typeData, p.ID, make([]byte, maxBinary-17))) },
		"shorter than a header":   func(c *client) { c.sendBinary([]byte{1, typeData, 0}) },
		"wrong version":           func(c *client) { c.sendBinary(append([]byte{2, typeData}, make([]byte, 16)...)) },
		"unreachable from a node": func(c *client) { c.sendBinary(frame(typeUnreachable, p.ID, nil)) },
		"unknown type":            func(c *client) { c.sendBinary(frame(0x08, p.ID, nil)) },
		"control message over 1 MiB": func(c *client) {
			c.ws.WriteMessage(websocket.TextMessage, []byte(`{"type":"usage","id":"`+strings.Repeat("x", 1<<20)+`"}`))
		},
		"malformed control message": func(c *client) { c.ws.WriteMessage(websocket.TextMessage, []byte(`{"type":`)) },
	}
	for name, send := range cases {
		t.Run(name, func(t *testing.T) {
			c := h.register(w, p, r)
			c.t = t
			send(c)
			c.expectClose(4000)
		})
	}
	// Non-fatal problems are answered with an error.
	pc2 := h.register(p, p, r)
	// A control message of exactly 1 MiB is accepted (here a usage request with a long id).
	head, tail := `{"type":"usage","id":"`, `"}`
	longID := strings.Repeat("y", 1<<20-len(head)-len(tail))
	pc2.ws.WriteMessage(websocket.TextMessage, []byte(head+longID+tail))
	if m := pc2.json(); m["type"] != "usage" || m["id"] != longID {
		t.Fatalf("1 MiB control message: got type %v", m["type"])
	}
	pc2.send(map[string]any{"type": "dance", "id": "7"})
	if m := pc2.json(); m["type"] != "error" || m["code"] != "bad_request" || m["id"] != "7" {
		t.Fatalf("got %v", m)
	}
}

func TestRosterPushAndRevocation(t *testing.T) {
	h := start(t, nil)
	p, w1, w2 := keys(t, 1), keys(t, 2), keys(t, 3)
	r1 := roster(t, 1, p, w1, w2)
	pc, c1, c2 := h.register(p, p, r1), h.register(w1, p, r1), h.register(w2, p, r1)

	// Only the primary pushes.
	c1.send(map[string]any{"type": "roster", "roster": json.RawMessage(roster(t, 9, p, w1))})
	if m := c1.json(); m["code"] != "forbidden" {
		t.Fatalf("got %v", m)
	}
	// An invalid roster is refused.
	var bad map[string]any
	json.Unmarshal(roster(t, 2, p, w1), &bad)
	bad["version"] = 3
	pc.send(map[string]any{"type": "roster", "roster": bad})
	if m := pc.json(); m["code"] != "bad_request" {
		t.Fatalf("got %v", m)
	}

	// Version 2 drops w2: its connection is closed 4008, w1 is untouched.
	pc.send(map[string]any{"type": "roster", "roster": json.RawMessage(roster(t, 2, p, w1))})
	c2.expectClose(4008)
	pc.sendBinary(frame(typeData, w1.ID, []byte("still here")))
	if f := c1.frame(); string(f[18:]) != "still here" {
		t.Fatalf("got %q", f)
	}
	pc.sendBinary(frame(typeData, w2.ID, []byte("gone")))
	if f := pc.frame(); f[1] != typeUnreachable {
		t.Fatalf("got %x", f)
	}
	// An older roster is refused.
	pc.send(map[string]any{"type": "roster", "roster": json.RawMessage(roster(t, 1, p, w1, w2))})
	if m := pc.json(); m["code"] != "bad_request" {
		t.Fatalf("got %v", m)
	}
	// w2 cannot come back: whichever roster it presents, the relay's version 2 does not list it.
	for _, rr := range [][]byte{r1, roster(t, 2, p, w1)} {
		c := h.dial()
		c.send(h.registerMsg(c, w2, p.ID.String(), rr))
		c.expectClose(4008)
	}
	// A newer roster presented at registration is adopted too, and has the same effect.
	r3 := roster(t, 3, p)
	c := h.dial()
	c.send(h.registerMsg(c, p, p.ID.String(), r3))
	if m := c.json(); m["rosterVersion"] != float64(3) {
		t.Fatalf("got %v", m)
	}
	pc.expectClose(4005)
	c1.expectClose(4008)
}

func TestPairing(t *testing.T) {
	h := start(t, nil)
	p := keys(t, 1)
	pc := h.register(p, p, roster(t, 1, p))
	code := b64([]byte{1, 2, 3, 4, 5, 6, 7, 8})

	n := h.dial()
	n.send(map[string]any{"type": "pair", "network": p.ID.String(), "code": code})
	pm := pc.json()
	nm := n.json()
	if pm["type"] != "pairing" || pm["code"] != code || nm["type"] != "pairing" || nm["channel"] != pm["channel"] {
		t.Fatalf("primary %v, newcomer %v", pm, nm)
	}
	if _, has := nm["code"]; has {
		t.Fatalf("newcomer was told the code id: %v", nm)
	}
	raw, ok := link.DecodeKey(nm["channel"].(string), 16)
	if !ok {
		t.Fatalf("channel %v is not 16 bytes", nm["channel"])
	}
	ch := link.ID(raw)

	// P1..P4 shaped exchange, forwarded unchanged with the channel id in the peer field.
	n.sendBinary(frame(typePair, ch, bytes.Repeat([]byte{4}, 65)))
	if f := pc.frame(); f[1] != typePair || peerOf(f) != ch || len(f) != 18+65 {
		t.Fatalf("got %x", f)
	}
	pc.sendBinary(frame(typePair, ch, bytes.Repeat([]byte{5}, 65)))
	if f := n.frame(); peerOf(f) != ch || f[18] != 5 {
		t.Fatalf("got %x", f)
	}
	// A pair frame for a channel that is not the primary's: unreachable.
	var stray link.ID
	pc.sendBinary(frame(typePair, stray, []byte{1}))
	if f := pc.frame(); f[1] != typeUnreachable || peerOf(f) != stray {
		t.Fatalf("got %x", f)
	}
	// The primary's last frame reaches the newcomer before pairEnd closes it 1000.
	pc.sendBinary(frame(typePair, ch, []byte("P6")))
	pc.send(map[string]any{"type": "pairEnd", "channel": nm["channel"]})
	if f := n.frame(); string(f[18:]) != "P6" {
		t.Fatalf("got %q", f)
	}
	// The newcomer, still connected, is told too.
	if m := n.json(); m["type"] != "pairEnd" || m["channel"] != nm["channel"] {
		t.Fatalf("got %v", m)
	}
	n.expectClose(1000)
	pc.sendBinary(frame(typePair, ch, []byte("late")))
	if f := pc.frame(); f[1] != typeUnreachable {
		t.Fatalf("got %x", f)
	}

	// The newcomer ending it: the primary hears pairEnd.
	n2 := h.dial()
	n2.send(map[string]any{"type": "pair", "network": p.ID.String(), "code": code})
	ch2 := pc.json()["channel"]
	n2.json()
	n2.send(map[string]any{"type": "pairEnd", "channel": ch2})
	n2.expectClose(1000)
	if m := pc.json(); m["type"] != "pairEnd" || m["channel"] != ch2 {
		t.Fatalf("got %v", m)
	}

	// The newcomer disconnecting: the primary hears pairEnd.
	n3 := h.dial()
	n3.send(map[string]any{"type": "pair", "network": p.ID.String(), "code": code})
	ch3 := pc.json()["channel"]
	n3.json()
	n3.ws.Close()
	if m := pc.json(); m["type"] != "pairEnd" || m["channel"] != ch3 {
		t.Fatalf("got %v", m)
	}

	// Anything but pair frames on its channel closes a newcomer 4000.
	n4 := h.dial()
	n4.send(map[string]any{"type": "pair", "network": p.ID.String(), "code": code})
	pc.json()
	n4.json()
	n4.sendBinary(frame(typeData, p.ID, []byte("x")))
	n4.expectClose(4000)
	if m := pc.json(); m["type"] != "pairEnd" {
		t.Fatalf("got %v", m)
	}
}

func TestPairingTimeout(t *testing.T) {
	h := start(t, func(c *Config) { c.PairTimeout = 300 * time.Millisecond })
	p := keys(t, 1)
	pc := h.register(p, p, roster(t, 1, p))
	n := h.dial()
	n.send(map[string]any{"type": "pair", "network": p.ID.String(), "code": b64(make([]byte, 8))})
	ch := pc.json()["channel"]
	n.json()
	began := time.Now()
	if m := n.json(); m["type"] != "pairEnd" || m["channel"] != ch {
		t.Fatalf("newcomer got %v", m)
	}
	n.expectClose(1000)
	if el := time.Since(began); el < 200*time.Millisecond {
		t.Fatalf("closed after %v", el)
	}
	if m := pc.json(); m["type"] != "pairEnd" || m["channel"] != ch {
		t.Fatalf("got %v", m)
	}
}

func TestPairingUnreachableAndLimited(t *testing.T) {
	h := start(t, func(c *Config) { c.IPPairPerMin = 2 })
	p := keys(t, 1)
	code := b64(make([]byte, 8))
	// No primary connected.
	n := h.dial()
	n.send(map[string]any{"type": "pair", "network": p.ID.String(), "code": code})
	if m := n.json(); m["type"] != "error" || m["code"] != "unreachable" {
		t.Fatalf("got %v", m)
	}
	n.expectClose(1000)
	// A malformed pair.
	n = h.dial()
	n.send(map[string]any{"type": "pair", "network": p.ID.String(), "code": "short"})
	n.expectClose(4000)
	// The third attempt from this address within the minute.
	n = h.dial()
	n.send(map[string]any{"type": "pair", "network": p.ID.String(), "code": code})
	if m := n.json(); m["code"] != "unreachable" {
		t.Fatalf("got %v", m)
	}
	n = h.dial()
	n.send(map[string]any{"type": "pair", "network": p.ID.String(), "code": code})
	if m := n.json(); m["code"] != "rate_limited" {
		t.Fatalf("got %v", m)
	}
	n.expectClose(4002)
}

func TestPrimaryLeavingEndsItsChannels(t *testing.T) {
	h := start(t, nil)
	p := keys(t, 1)
	pc := h.register(p, p, roster(t, 1, p))
	n := h.dial()
	n.send(map[string]any{"type": "pair", "network": p.ID.String(), "code": b64(make([]byte, 8))})
	ch := pc.json()["channel"]
	n.json()
	pc.ws.Close()
	if m := n.json(); m["type"] != "pairEnd" || m["channel"] != ch {
		t.Fatalf("got %v", m)
	}
	n.expectClose(1000)
}
