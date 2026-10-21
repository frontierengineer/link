package link

import (
	"testing"
	"time"
)

func (l *eventLog) has(match func(Event) bool) bool {
	for _, e := range l.all() {
		if match(e) {
			return true
		}
	}
	return false
}

// Section 3.1, "Becoming the primary", against the real relay: a alice started with the
// network seed claims the primary once registered. It signs the roster naming itself primary,
// the members unchanged, publishes it, and is the primary. The relay demotes the
// former primary's connection in place: it stays connected, exchanges messages both ways, and
// is no longer the primary.
func TestLiveClaimPrimary(t *testing.T) {
	n := startLiveNet(t, nil, fast)
	p := n.primary
	if n.primary.Network() == p.ID() {
		t.Fatal("the network id is the primary's node id")
	}
	w := n.add()
	s := n.add()
	wID, wRoster := w.Identity(), w.Roster()
	w.Close()
	pLog := record(p.Member)

	// Without the seed it cannot start as the primary.
	if _, err := NewPrimary(MemberOptions{Identity: wID, Roster: wRoster, Timing: fast}); CodeOf(err) != CodeInvalid {
		t.Fatalf("a primary without the seed: %v", err)
	}
	claimer, err := ConnectPrimary(ctxT(t, 15*time.Second), MemberOptions{Identity: wID, Roster: wRoster, Timing: fast, NetworkSeed: n.seed})
	if err != nil {
		t.Fatal(err)
	}
	c := n.track(claimer.Member)
	eventually(t, "the claim", func() bool { return c.IsPrimary() && !p.IsPrimary() && s.Roster().PrimaryID() == c.ID() })
	claimed := c.Roster()
	if claimed.Version != wRoster.Version+1 || claimed.Network != wRoster.Network || claimed.NetworkKey != wRoster.NetworkKey {
		t.Fatalf("claimed roster %+v", claimed.UnsignedRoster)
	}
	if claimed.Primary != c.ID() || claimed.member(p.ID()) == nil || len(claimed.Members) != len(wRoster.Members) {
		t.Fatal("the claim changed the membership, or does not name the claimer primary")
	}
	for i := range claimed.Members {
		if claimed.Members[i].ID != wRoster.Members[i].ID || claimed.Members[i].Ed25519 != wRoster.Members[i].Ed25519 {
			t.Fatal("the claim changed a member")
		}
	}

	// The new primary does what a primary does: the relay answers its usage, it pairs, revokes.
	if u, err := c.Usage(ctxT(t, 5*time.Second)); err != nil || u.Network.Connections != 3 {
		t.Fatalf("usage %+v %v", u, err)
	}
	n.primary = claimer
	x := n.add()
	if x.Roster().PrimaryID() != c.ID() {
		t.Fatal("pairing through the new primary")
	}
	eventually(t, "the former primary to learn the newcomer", func() bool { return p.Roster().Version == x.Roster().Version })
	if _, err := c.Revoke(x.ID()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the revocation", func() bool { return x.State() == StateRevoked })

	// The former primary: still connected, never disconnected, and an ordinary member.
	p.Settle()
	if pLog.has(func(e Event) bool { _, d := e.(DisconnectEvent); _, st := e.(StateEvent); return d || st }) {
		t.Fatalf("the claim changed the former primary's connection: %v", pLog.all())
	}
	if p.State() != StateConnected || !p.HoldsNetworkSeed() {
		t.Fatal("the former primary: not connected, or its seed taken")
	}
	for _, call := range []func() error{
		func() error { _, err := p.OpenPairingCode(PairingCodeOptions{}); return err },
		func() error { _, err := p.Revoke(s.ID()); return err },
		func() error { _, err := p.Usage(ctxT(t, 5*time.Second)); return err },
	} {
		if err := call(); CodeOf(err) != CodeInvalid {
			t.Fatalf("a primary capability on the former primary: %v", err)
		}
	}
	if err := p.Send(ctxT(t, 5*time.Second), c.ID(), []byte("from the former primary")); err != nil {
		t.Fatal(err)
	}
	if m := recv(t, c); string(m.Bytes) != "from the former primary" {
		t.Fatal(m)
	}
	if err := c.Send(ctxT(t, 5*time.Second), p.ID(), []byte("to the former primary")); err != nil {
		t.Fatal(err)
	}
	if m := recv(t, p.Member); string(m.Bytes) != "to the former primary" {
		t.Fatal(m)
	}
	if err := c.Resign(ctxT(t, 5*time.Second)); CodeOf(err) != CodeInvalid {
		t.Fatalf("the primary resigned: %v", err)
	}
}

// A node claims only at its first registration (section 3.1): one whose roster later names
// another member primary stops acting as the primary in place, its codes closed and its
// connection untouched, and claims nothing back, whatever seed it holds.
func TestNoClaimAfterStart(t *testing.T) {
	tn := newTestNet(t, 2)
	tn.roster = tn.sign(2, tn.ids[1], tn.ids[0]) // naming w primary: p, given the seed, claims
	w := tn.start(1)
	p := tn.start(0)
	pLog := record(p)
	eventually(t, "the claim", func() bool { return p.IsPrimary() && w.Roster().PrimaryID() == p.ID() })
	if v := p.Roster().Version; v != 3 {
		t.Fatalf("claimed at version %d", v)
	}
	if _, err := p.OpenPairingCode(PairingCodeOptions{}); err != nil {
		t.Fatal(err)
	}
	// Another holder of the seed signs a roster naming w primary again; p accepts it.
	moved := tn.sign(4, tn.ids[1], tn.ids[0])
	var took bool
	locked(p, func() { took = p.offerRoster(moved) })
	if !took {
		t.Fatal("not accepted")
	}
	if p.IsPrimary() || !p.HoldsNetworkSeed() {
		t.Fatal("still primary, or the seed dropped")
	}
	locked(p, func() {
		if len(p.roster.Members) != 2 || p.prim != nil {
			t.Error("primary state kept")
		}
	})
	// A reconnect is not a start: no claim.
	tn.relay.conn(p.ID()).kick(1001)
	eventually(t, "the reconnect", func() bool {
		tn.clock.Advance(50 * time.Millisecond)
		return pLog.has(func(e Event) bool { x, ok := e.(StateEvent); return ok && x.State == StateDisconnected }) && p.State() == StateConnected
	})
	time.Sleep(50 * time.Millisecond)
	if p.Roster().Version != 4 || p.IsPrimary() {
		t.Fatal("claimed again after the start")
	}
	if _, err := p.OpenPairingCode(PairingCodeOptions{}); CodeOf(err) != CodeInvalid {
		t.Fatal("a code from a node no longer the primary")
	}
	// A seed that does not derive the roster's network key is refused at construction.
	other, _ := NewNetworkSeed()
	o := tn.opts(1, moved)
	o.NetworkSeed = other
	if _, err := NewMember(o); CodeOf(err) != CodeInvalid {
		t.Fatal("a seed of another network at construction")
	}
}
