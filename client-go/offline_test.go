package link

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"
)

// A member must never crash for want of a network: with its relay unreachable (connection
// refused, a name that does not resolve, an address with no route), with its relay going away
// mid-session, and on a roster with no relay yet, it keeps running and says so through its
// states, events and the errors of the calls made on it, retrying where it retries. A panic
// anywhere ends the test binary, so each passing test is also the proof that none happened.

// offlineTiming reconnects fast and gives up a send to a peer it cannot reach in a second.
var offlineTiming = Timing{BackoffInitial: 20 * time.Millisecond, BackoffMax: 200 * time.Millisecond, RequestTimeout: time.Second, HandshakeTimeout: time.Second}

func refusedURL(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return "ws://" + addr + "/v1"
}

type offlineNet struct {
	primary, member *Identity
	roster          *Roster
	seed            []byte
}

func newOfflineNet(t *testing.T, relay string) offlineNet {
	t.Helper()
	p, _ := NewIdentity()
	m, _ := NewIdentity()
	r, seed, err := CreateNetworkWith(NetworkOptions{Primary: p, Relay: relay, Members: []RosterMember{MemberFromIdentity(m)}})
	if err != nil {
		t.Fatal(err)
	}
	return offlineNet{p, m, r, seed}
}

func countState(l *eventLog, s State) int {
	n := 0
	for _, x := range l.states() {
		if x == s {
			n++
		}
	}
	return n
}

func TestOfflineTheRelayUnreachable(t *testing.T) {
	cases := []struct {
		name  string
		url   func(t *testing.T) string
		hangs bool // a dial to an address with no route may wait out its own timeout
	}{
		{"connection refused", refusedURL, false},
		{"a name that does not resolve", func(*testing.T) string { return "ws://link-relay.invalid/v1" }, false},
		{"an address with no route", func(*testing.T) string { return "ws://192.0.2.1:9/v1" }, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			n := newOfflineNet(t, c.url(t))
			p, err := NewPrimary(MemberOptions{Identity: n.primary, Roster: n.roster, NetworkSeed: n.seed, Timing: offlineTiming})
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			m, err := NewMember(MemberOptions{Identity: n.member, Roster: n.roster, Timing: offlineTiming})
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			log := record(m)
			ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
			defer cancel()
			if err := m.WaitConnected(ctx); err == nil {
				t.Fatal("connected to an unreachable relay")
			}
			if !c.hangs {
				eventually(t, "a second dial", func() bool { return countState(log, StateConnecting) >= 2 })
			}
			if s := m.State(); s != StateConnecting && s != StateDisconnected {
				t.Fatalf("state %v", s)
			}
			if err := m.Send(ctxT(t, 5*time.Second), n.primary.ID(), []byte("x")); CodeOf(err) == "" {
				t.Fatalf("send: %v, want a link error", err)
			}
			if _, err := p.Usage(ctxT(t, 5*time.Second)); CodeOf(err) == "" {
				t.Fatalf("usage: %v, want a link error", err)
			}
			// What needs no relay still works.
			code, err := p.OpenPairingCode(PairingCodeOptions{})
			if err != nil || !regexp.MustCompile(`^[0-9A-Z]{4}-[0-9A-Z]{4}$`).MatchString(code.Code) {
				t.Fatalf("code %+v %v", code, err)
			}
			m.Close()
			if m.State() != StateClosed {
				t.Fatalf("state %v after close", m.State())
			}
		})
	}
}

func TestOfflineTheRelayGoingAwayMidSession(t *testing.T) {
	r := startRelay(t, nil)
	addr := strings.TrimSuffix(strings.TrimPrefix(r.url, "ws://"), "/v1")
	n := newOfflineNet(t, r.url)
	p, err := ConnectPrimary(ctxT(t, 15*time.Second), MemberOptions{Identity: n.primary, Roster: n.roster, NetworkSeed: n.seed, Timing: offlineTiming})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	m, err := ConnectMember(ctxT(t, 15*time.Second), MemberOptions{Identity: n.member, Roster: n.roster, Timing: offlineTiming})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := p.Send(ctxT(t, 10*time.Second), m.ID(), []byte("before")); err != nil {
		t.Fatal(err)
	}
	if got := recv(t, m); string(got.Bytes) != "before" {
		t.Fatalf("%+v", got)
	}
	log := record(m)
	r.cmd.Process.Kill() // gone, as a crash or a lost network would leave it
	eventually(t, "both to see the relay gone", func() bool {
		return m.State() != StateConnected && p.State() != StateConnected
	})
	if countState(log, StateDisconnected) == 0 {
		t.Fatalf("states %v", log.states())
	}
	if err := p.Send(ctxT(t, 5*time.Second), m.ID(), []byte("lost")); CodeOf(err) == "" {
		t.Fatalf("send: %v, want a link error", err)
	}
	eventually(t, "the member to dial again", func() bool { return countState(log, StateConnecting) >= 2 })
	startRelay(t, map[string]string{"LINK_ADDR": addr})
	if err := m.WaitConnected(ctxT(t, 10*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := p.WaitConnected(ctxT(t, 10*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := p.Send(ctxT(t, 10*time.Second), m.ID(), []byte("after")); err != nil {
		t.Fatal(err)
	}
	if got := recv(t, m); string(got.Bytes) != "after" {
		t.Fatalf("%+v", got)
	}
}

func TestOfflineAnUnplacedRosterOrARelayURLThatIsNotOne(t *testing.T) {
	n := newOfflineNet(t, "")
	if _, err := NewPrimary(MemberOptions{Identity: n.primary, Roster: n.roster, NetworkSeed: n.seed}); !errors.Is(err, ErrInvalid) {
		t.Errorf("primary: %v", err)
	}
	if _, err := ConnectMember(ctxT(t, time.Second), MemberOptions{Identity: n.member, Roster: n.roster}); !errors.Is(err, ErrInvalid) {
		t.Errorf("member: %v", err)
	}
	if _, err := NewMember(MemberOptions{Identity: n.member, Roster: n.roster, RelayURL: "not a url"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("a relay URL that is not one: %v", err)
	}
}

func TestOfflineARelayTheNetworkMovesToThatIsNotAURL(t *testing.T) {
	tn := newTestNet(t, 2)
	tn.start(0)
	m := tn.start(1, func(o *MemberOptions) {
		o.ResolveRelay = func(context.Context, string) (string, error) { return "not a url", nil }
	})
	// 4009: the member looks the network up again, is told something that is not a URL, keeps
	// the URL it had, and reconnects to it.
	tn.relay.conn(m.ID()).kick(CloseMoved)
	eventually(t, "disconnected", func() bool { return m.State() == StateDisconnected })
	tn.clock.Advance(100 * time.Millisecond)
	eventually(t, "reconnected", func() bool { return m.State() == StateConnected })
	if m.RelayURL() != testRelayURL {
		t.Fatalf("relay URL %q", m.RelayURL())
	}
	// The dialler itself refuses what is not a URL with an error, never a panic.
	for _, u := range []string{"not a url", "", "ws://", "ws://a b/v1"} {
		if _, err := dialWebSocket(ctxT(t, 5*time.Second), u); err == nil {
			t.Errorf("dialled %q", u)
		}
	}
}

func TestOfflinePairingWithTheRelayUnreachable(t *testing.T) {
	n := newOfflineNet(t, "")
	for _, relay := range []string{refusedURL(t), "ws://link-relay.invalid/v1", "not a url"} {
		id, _ := NewIdentity()
		target := &PairingLink{Network: n.roster.Network, Code: "7K2M9QXZ", CodeID: "AQIDBAUGBwg", Relay: relay}
		if _, err := Pair(ctxT(t, 10*time.Second), PairOptions{Identity: id, Target: target, Timeout: 3 * time.Second}); CodeOf(err) == "" {
			t.Errorf("%s: %v, want a link error", relay, err)
		}
	}
}
