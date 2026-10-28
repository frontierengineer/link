package link

// The default code (section 5.1): one per primary, id 8 zero bytes, replaced by the next one
// opened; codes opened Separate sit beside it. Driven by the fake relay, and live.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestTheDefaultCode(t *testing.T) {
	tn := newTestNet(t, 2)
	pm := tn.start(0)
	p := &Primary{Member: pm}
	log := record(pm)
	conn := tn.relay.conn(pm.ID())
	pairing := func(channel byte) {
		msg, _ := json.Marshal(map[string]string{"type": "pairing", "channel": b64u(append(make([]byte, 15), channel)), "code": DefaultCodeID})
		conn.push(fakeMsg{text: true, data: msg})
		p.Usage(context.Background()) // a round trip: the pairing is handled
		pm.Settle()
	}
	failed := func(code string) (n int) {
		for _, e := range log.all() {
			if f, ok := e.(PairingFailedEvent); ok && f.CodeID == DefaultCodeID && f.Code == code {
				n++
			}
		}
		return n
	}

	// Before any default code is opened, its id was never issued: no event.
	pairing(1)
	if n := failed(FailUnknownCode); n != 0 {
		t.Fatalf("%d events for a default code never opened", n)
	}

	first, err := p.OpenPairingCode(PairingCodeOptions{})
	if err != nil || first.CodeID != DefaultCodeID || strings.Contains(first.Link, "i=") {
		t.Fatalf("%+v %v", first, err)
	}
	if l, err := ParsePairingLink(first.Link); err != nil || l.CodeID != DefaultCodeID {
		t.Fatalf("%+v %v", l, err)
	}
	sep, err := p.OpenPairingCode(PairingCodeOptions{Separate: true})
	if err != nil || sep.CodeID == DefaultCodeID || !strings.Contains(sep.Link, "&i="+sep.CodeID+"&") {
		t.Fatalf("%+v %v", sep, err)
	}

	// A second default code closes the first and ends its pairing channels; the separate
	// code stays open.
	pairing(2)
	var old *openCode
	locked(pm, func() { old = pm.prim.codes[DefaultCodeID] })
	if old == nil || old.inFlight != 1 {
		t.Fatal("the pairing did not open a channel on the default code")
	}
	second, err := p.OpenPairingCode(PairingCodeOptions{Code: "2222-2222"})
	if err != nil || second.CodeID != DefaultCodeID || second.Code != "2222-2222" {
		t.Fatalf("%+v %v", second, err)
	}
	pm.Settle()
	locked(pm, func() {
		now := pm.prim.codes[DefaultCodeID]
		if now == nil || now == old || now.code != "22222222" || !old.burned || old.inFlight != 0 || len(pm.prim.channels) != 0 || pm.prim.codes[sep.CodeID] == nil {
			t.Fatalf("after the second default code: %+v (first %+v)", now, old)
		}
	})
	if n := failed(FailUnknownCode); n != 1 {
		t.Fatalf("%d events for the replaced default code's channel", n)
	}

	// A default code that expires with a channel in flight, its last attempt left, and a
	// default code opened after it: the channel's last attempt burns the expired code, never
	// the one opened since.
	if _, err := p.OpenPairingCode(PairingCodeOptions{Lifetime: time.Second}); err != nil {
		t.Fatal(err)
	}
	pairing(5)
	locked(pm, func() {
		old = pm.prim.codes[DefaultCodeID]
		old.failed = CodeAttempts - 1
	})
	tn.clock.Advance(2 * time.Second)
	if _, err := p.OpenPairingCode(PairingCodeOptions{}); err != nil {
		t.Fatal(err)
	}
	frame, _ := encodeFrame(framePair, [16]byte{15: 5}, []byte("not a share"))
	conn.push(fakeMsg{data: frame})
	p.Usage(context.Background())
	pm.Settle()
	if n := failed(FailMalformed); n != 1 {
		t.Fatalf("%d malformed events", n)
	}
	locked(pm, func() {
		if now := pm.prim.codes[DefaultCodeID]; now == nil || now == old || now.burned {
			t.Fatalf("the expired code's last attempt closed the default code: %+v", now)
		}
	})

	// Cancelled with no id, the default code is refused as closed, with an event naming it.
	p.CancelPairingCode("")
	locked(pm, func() {
		if pm.prim.codes[DefaultCodeID] != nil || pm.prim.codes[sep.CodeID] == nil {
			t.Fatal("cancelling the default code")
		}
	})
	tn.clock.Advance(time.Second)
	pairing(3)
	if n := failed(FailUnknownCode); n != 2 {
		t.Fatalf("%d events for the closed default code", n)
	}

	// However many codes close after it, the default code's id stays issued.
	for range closedCodes + 1 {
		c, err := p.OpenPairingCode(PairingCodeOptions{Separate: true})
		if err != nil || c.CodeID == DefaultCodeID {
			t.Fatalf("%+v %v", c, err)
		}
		p.CancelPairingCode(c.CodeID)
	}
	tn.clock.Advance(time.Second)
	pairing(4)
	if n := failed(FailUnknownCode); n != 3 {
		t.Fatalf("%d events for the closed default code after %d codes closed", n, closedCodes+1)
	}
	locked(pm, func() {
		if pm.prim.issued[sep.CodeID] == nil || len(pm.prim.closed) > closedCodes {
			t.Fatalf("closed codes kept: %d", len(pm.prim.closed))
		}
	})
}

func TestLiveTheDefaultCode(t *testing.T) {
	n := startLiveNet(t, nil, fast)
	pLog := record(n.primary.Member)
	first, err := n.primary.OpenPairingCode(PairingCodeOptions{Code: "1111-1111"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := n.primary.OpenPairingCode(PairingCodeOptions{Code: "2222-2222"})
	if err != nil {
		t.Fatal(err)
	}
	sep, err := n.primary.OpenPairingCode(PairingCodeOptions{Separate: true})
	if err != nil {
		t.Fatal(err)
	}
	// The first default code admits nobody: its link reaches the second, which it does not match.
	a, _ := NewIdentity()
	if _, err := Pair(ctxT(t, 10*time.Second), PairOptions{Link: first.Link, Identity: a}); CodeOf(err) != CodePairing {
		t.Fatalf("a replaced default code paired: %v", err)
	}
	// A newcomer with the code and no id pairs with the default code.
	l, _ := ParsePairingLink(second.Link)
	l.CodeID = ""
	if _, err := Pair(ctxT(t, 10*time.Second), PairOptions{Target: &l, Identity: a}); err != nil {
		t.Fatal(err)
	}
	// The separate code is open beside it.
	b, _ := NewIdentity()
	if _, err := Pair(ctxT(t, 10*time.Second), PairOptions{Link: sep.Link, Identity: b}); err != nil {
		t.Fatal(err)
	}
	// Used, the default code is closed; nothing is open in its place.
	c, _ := NewIdentity()
	if _, err := Pair(ctxT(t, 10*time.Second), PairOptions{Link: second.Link, Identity: c}); CodeOf(err) != CodePairing {
		t.Fatalf("a used default code paired: %v", err)
	}
	eventually(t, "the events", func() bool {
		var paired []string
		wrong := false
		for _, e := range pLog.all() {
			switch e := e.(type) {
			case PairedEvent:
				paired = append(paired, e.CodeID)
			case PairingFailedEvent:
				wrong = wrong || (e.CodeID == DefaultCodeID && e.Code == FailWrongCode)
			}
		}
		return wrong && len(paired) == 2 && paired[0] == DefaultCodeID && paired[1] == sep.CodeID
	})
	if v := n.primary.Roster().Version; v != 3 {
		t.Fatalf("version %d", v)
	}
}
