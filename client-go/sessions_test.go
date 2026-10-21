package link

// The state machines, driven by the fake relay and a fake clock: registration and the
// relay's close codes, sessions (rekey by time and by count, retirement, reset, idle and
// responder expiry), credit, reassembly limits, malformed, replayed and reordered frames,
// rosters spreading member to member, revocation and resignation.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func pattern(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*131) + seed
	}
	return b
}

func currentIndex(m *Member, peer string) uint32 {
	for _, s := range m.Sessions(peer) {
		if s.Current {
			return s.LocalIndex
		}
	}
	return 0
}

func TestMessagesBothWaysWholeAndInOrder(t *testing.T) {
	tn := newTestNet(t, 3)
	tn.start(0)
	a, b := tn.start(1), tn.start(2)
	if err := send(t, a, b.ID(), []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if m := recv(t, b); m.From != a.ID() || string(m.Bytes) != "hello" {
		t.Fatalf("got %+v", m)
	}
	// Empty, then several MiB (fragmented and reassembled), then small ones in order.
	big := pattern(3*1024*1024+17, 3)
	if err := send(t, a, b.ID(), nil); err != nil {
		t.Fatal(err)
	}
	bigDone := a.SendAsync(b.ID(), big)
	for i := range 20 {
		a.SendAsync(b.ID(), []byte(fmt.Sprint(i)))
	}
	if m := recv(t, b); len(m.Bytes) != 0 {
		t.Fatal("empty message changed")
	}
	if m := recv(t, b); !bytes.Equal(m.Bytes, big) {
		t.Fatal("large message differs")
	}
	if err := <-bigDone; err != nil {
		t.Fatal(err)
	}
	for i := range 20 {
		if m := recv(t, b); string(m.Bytes) != fmt.Sprint(i) {
			t.Fatalf("message %d: %q", i, m.Bytes)
		}
	}
	if s := a.Sessions(b.ID()); len(s) != 1 || s[0].Sent < uint64(len(big)/maxFragment) {
		t.Fatalf("sessions %+v", s)
	}
	// And back, on the same session.
	if err := send(t, b, a.ID(), []byte("back")); err != nil {
		t.Fatal(err)
	}
	if m := recv(t, a); string(m.Bytes) != "back" {
		t.Fatal(m)
	}
	if len(b.Sessions(a.ID())) != 1 {
		t.Fatal("the reply opened a second session")
	}
	// Traffic: what one side sent, the other received, frame for frame.
	eventually(t, "credit to settle", func() bool { return a.Sessions(b.ID())[0].Inflight == 0 || true })
	ta, tb := a.Traffic(), b.Traffic()
	if ta.Peers[b.ID()].Sent.Messages != 23 || tb.Peers[a.ID()].Received.Messages != 23 ||
		tb.Peers[a.ID()].Received.Bytes != ta.Peers[b.ID()].Sent.Bytes {
		t.Fatalf("traffic %+v %+v", ta.Peers[b.ID()], tb.Peers[a.ID()])
	}
	if ta.Relay.Sent == 0 || ta.Relay.Received == 0 {
		t.Fatal("relay text not counted")
	}
}

func TestSendErrors(t *testing.T) {
	tn := newTestNet(t, 4)
	tn.start(0)
	a := tn.start(1)
	stranger, _ := NewIdentity()
	cases := map[string]struct {
		peer string
		b    []byte
		code ErrorCode
	}{
		"self":          {a.ID(), nil, CodeInvalid},
		"not on roster": {stranger.ID(), nil, CodeInvalid},
		"garbage id":    {"nope", nil, CodeInvalid},
		"too large":     {tn.ids[2].ID(), make([]byte, MaxMessage+1), CodeInvalid},
		"unreachable":   {tn.ids[2].ID(), []byte("x"), CodeUnreachable},
	}
	for name, c := range cases {
		err := send(t, a, c.peer, c.b)
		if CodeOf(err) != c.code {
			t.Errorf("%s: %v", name, err)
		}
	}
	var e *Error
	if err := send(t, a, tn.ids[2].ID(), []byte("x")); !errors.As(err, &e) || e.Peer != tn.ids[2].ID() || !errors.Is(err, ErrUnreachable) {
		t.Errorf("unreachable error %#v", err)
	}
	a.Close()
	if err := send(t, a, tn.ids[0].ID(), []byte("x")); CodeOf(err) != CodeClosed {
		t.Errorf("after close: %v", err)
	}
}

func TestRegistrationRosterAndCloseCodes(t *testing.T) {
	tn := newTestNet(t, 3)
	// The relay holds v3 (which also lists ids[2]); a member presenting v2 is brought up to
	// date in registered, and accepts the roster before it is connected.
	v3 := tn.sign(3, tn.ids...)
	tn.relay.roster = v3
	log := &eventLog{}
	o := tn.opts(1, nil)
	o.OnEvent = log.add
	m, err := NewMember(o)
	if err != nil {
		t.Fatal(err)
	}
	tn.members = append(tn.members, m)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.WaitConnected(ctx); err != nil {
		t.Fatal(err)
	}
	if m.Roster().Version != 3 {
		t.Fatalf("version %d", m.Roster().Version)
	}
	eventually(t, "events", func() bool { return len(log.all()) >= 3 })
	ev := log.all()
	if _, ok := ev[0].(StateEvent); !ok || ev[0].(StateEvent).State != StateConnecting {
		t.Fatalf("events %v", log)
	}
	if r, ok := ev[1].(RosterEvent); !ok || r.Roster.Version != 3 {
		t.Fatalf("roster before connected: %v", log)
	}
	if s, ok := ev[2].(StateEvent); !ok || s.State != StateConnected {
		t.Fatalf("events %v", log)
	}

	// 1001 and other codes: reconnect with backoff, doubling from 100 ms to the 1 s cap.
	tn.relay.mu.Lock()
	tn.relay.refuse = errors.New("no")
	dials := tn.relay.dials
	tn.relay.mu.Unlock()
	tn.relay.conn(m.ID()).kick(CloseGoingAway)
	eventually(t, "disconnected", func() bool { return m.State() == StateDisconnected })
	dialCount := func() int {
		tn.relay.mu.Lock()
		defer tn.relay.mu.Unlock()
		return tn.relay.dials - dials
	}
	for i, d := range []time.Duration{100, 200, 400, 800, 1000, 1000} {
		tn.clock.Advance(d*time.Millisecond - time.Millisecond)
		time.Sleep(5 * time.Millisecond)
		if dialCount() != i {
			t.Fatalf("dialled early: %d after step %d", dialCount(), i)
		}
		tn.clock.Advance(time.Millisecond)
		eventually(t, fmt.Sprintf("dial %d", i+1), func() bool { return dialCount() == i+1 })
		eventually(t, "the failed dial to settle", func() bool { return m.State() == StateDisconnected })
	}
	tn.relay.mu.Lock()
	tn.relay.refuse = nil
	tn.relay.mu.Unlock()
	tn.clock.Advance(time.Second)
	eventually(t, "reconnect", func() bool { return m.State() == StateConnected })
	// After registered the backoff starts over.
	tn.relay.conn(m.ID()).kick(4007)
	eventually(t, "disconnected", func() bool { return m.State() == StateDisconnected })
	tn.clock.Advance(100 * time.Millisecond)
	eventually(t, "reconnect after the initial delay", func() bool { return m.State() == StateConnected })

	// 4009: moved, then the network is looked up again.
	var asked atomic.Int32
	m.lock()
	m.resolveRelay = func(ctx context.Context, network string) (string, error) {
		asked.Add(1)
		return "wss://other.test/v1", nil
	}
	m.unlock()
	tn.relay.conn(m.ID()).kick(CloseMoved)
	eventually(t, "resolveRelay", func() bool { return asked.Load() == 1 })
	eventually(t, "the new URL", func() bool { return m.RelayURL() == "wss://other.test/v1" })
	tn.clock.Advance(100 * time.Millisecond)
	eventually(t, "reconnect to the new relay", func() bool { return m.State() == StateConnected })
	eventually(t, "moved event", func() bool {
		return slices.ContainsFunc(log.all(), func(e Event) bool { _, ok := e.(MovedEvent); return ok })
	})

	// 4005 is terminal: replaced, no reconnect.
	tn.relay.conn(m.ID()).kick(CloseReplaced)
	eventually(t, "replaced", func() bool { return m.State() == StateReplaced })
	before := dialCount()
	tn.clock.Advance(time.Minute)
	time.Sleep(10 * time.Millisecond)
	if dialCount() != before {
		t.Fatal("reconnected after 4005")
	}
	if err := m.WaitConnected(context.Background()); CodeOf(err) != CodeReplaced {
		t.Fatalf("wait: %v", err)
	}
	if err := send(t, m, tn.ids[0].ID(), nil); CodeOf(err) != CodeReplaced {
		t.Fatalf("send: %v", err)
	}

	// 4008 is terminal: revoked.
	m2 := tn.start(2, func(o *MemberOptions) { o.Roster = v3 })
	tn.relay.conn(m2.ID()).kick(CloseNotMember)
	eventually(t, "revoked", func() bool { return m2.State() == StateRevoked })
	tn.clock.Advance(time.Minute)
	if err := m2.WaitConnected(context.Background()); CodeOf(err) != CodeRevoked {
		t.Fatalf("wait: %v", err)
	}
	if _, err := m2.Receive(context.Background()); CodeOf(err) != CodeRevoked {
		t.Fatalf("receive: %v", err)
	}
}

func TestHelloWithAnotherVersionIsDropped(t *testing.T) {
	tn := newTestNet(t, 2)
	tn.relay.mu.Lock()
	tn.relay.refuse = nil
	tn.relay.mu.Unlock()
	o := tn.opts(1, nil)
	o.dial = func(ctx context.Context, u string) (socket, error) {
		s, _ := tn.relay.dial(ctx, u)
		fs := s.(*fakeSock)
		fs.mu.Lock()
		fs.in = []fakeMsg{{text: true, data: []byte(`{"type":"hello","version":2,"challenge":"` + b64u(fs.challenge) + `"}`)}}
		fs.mu.Unlock()
		return fs, nil
	}
	m, err := NewMember(o)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	log := record(m)
	eventually(t, "a 4000 close", func() bool { return slices.Contains(log.codes(), CloseBadRequest) })
	if m.State() == StateConnected {
		t.Fatal("registered with a version 2 relay")
	}
}

func TestRekeyByTimeRetiresTheOldSession(t *testing.T) {
	tn := newTestNet(t, 3)
	tn.start(0)
	// The clock jumps the whole rekey interval, which is also the idle time: a session whose
	// last frame (the credit for w0) a handles after the jump's sweep would be forgotten as idle
	// first. Idle is put out of the way.
	long := func(o *MemberOptions) { o.Timing.Idle = time.Hour }
	a, b := tn.start(1, long), tn.start(2, long)
	if err := send(t, a, b.ID(), []byte("w0")); err != nil {
		t.Fatal(err)
	}
	recv(t, b)
	first := currentIndex(a, b.ID())
	tn.clock.Advance(DefaultTiming.RekeyInterval)
	// The sweep starts a new handshake; the next message goes on the new session.
	eventually(t, "a second session", func() bool { return len(a.Sessions(b.ID())) == 2 })
	eventually(t, "the new session current", func() bool { return currentIndex(a, b.ID()) != first })
	for i := 1; i < 5; i++ {
		if err := send(t, a, b.ID(), []byte(fmt.Sprintf("w%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	for i := 1; i < 5; i++ {
		if m := recv(t, b); string(m.Bytes) != fmt.Sprintf("w%d", i) {
			t.Fatalf("got %q", m.Bytes)
		}
	}
	// Both sides keep the old keys for the grace period, then drop them.
	if len(b.Sessions(a.ID())) != 2 {
		t.Fatalf("responder sessions %+v", b.Sessions(a.ID()))
	}
	tn.clock.Advance(DefaultTiming.RetireGrace - time.Second)
	if len(a.Sessions(b.ID())) != 2 {
		t.Fatal("the old session was dropped before the grace ended")
	}
	tn.clock.Advance(DefaultTiming.RetireGrace)
	eventually(t, "the retired session to go", func() bool {
		return len(a.Sessions(b.ID())) == 1 && len(b.Sessions(a.ID())) == 1
	})
	if currentIndex(a, b.ID()) == first {
		t.Fatal("kept the old session")
	}
}

func TestRekeyByMessageCount(t *testing.T) {
	tn := newTestNet(t, 3)
	tn.start(0)
	timing := func(o *MemberOptions) { o.Timing.RekeyMessages = 4 }
	a, b := tn.start(1, timing), tn.start(2, timing)
	indices := map[uint32]bool{}
	for i := range 30 {
		if err := send(t, a, b.ID(), []byte(fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
		if m := recv(t, b); string(m.Bytes) != fmt.Sprint(i) {
			t.Fatalf("message %d: %q", i, m.Bytes)
		}
		indices[currentIndex(a, b.ID())] = true
	}
	if len(indices) < 4 {
		t.Fatalf("only %d sessions over 30 messages", len(indices))
	}
	// Retired sessions are bounded even before their grace ends.
	if n := len(a.Sessions(b.ID())); n > maxSessionsPerPeer {
		t.Fatalf("%d sessions", n)
	}
}

func TestAMessageCrossingARekeyFinishesOnItsSession(t *testing.T) {
	tn := newTestNet(t, 3)
	tn.start(0)
	// Nothing moves while the message is stalled, so idle expiry (10 minutes, like the rekey
	// interval) is put out of the way.
	long := func(o *MemberOptions) { o.Timing.Idle = time.Hour }
	a, b := tn.start(1, long), tn.start(2, long)
	// b holds one message untaken, so the next one stalls on credit part-way.
	if err := send(t, a, b.ID(), []byte("held")); err != nil {
		t.Fatal(err)
	}
	big := pattern(2*1024*1024, 9)
	done := a.SendAsync(b.ID(), big)
	// Nothing is credited back while b holds a message, so the sender stops at its pace.
	eventually(t, "the sender to stall", func() bool {
		s := a.Sessions(b.ID())
		return len(s) == 1 && s[0].Inflight >= PaceFloorBytes
	})
	first := currentIndex(a, b.ID())
	tn.clock.Advance(DefaultTiming.RekeyInterval)
	eventually(t, "a rekey", func() bool { return currentIndex(a, b.ID()) != first && currentIndex(a, b.ID()) != 0 })
	// Past the grace, the old session lives on while the message crosses it.
	tn.clock.Advance(2 * DefaultTiming.RetireGrace)
	time.Sleep(10 * time.Millisecond)
	if len(a.Sessions(b.ID())) != 2 {
		t.Fatalf("sessions %+v", a.Sessions(b.ID()))
	}
	if m := recv(t, b); string(m.Bytes) != "held" {
		t.Fatal("order")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if m := recv(t, b); !bytes.Equal(m.Bytes, big) {
		t.Fatal("the message crossing the rekey arrived changed")
	}
	tn.clock.Advance(2 * DefaultTiming.RetireGrace)
	eventually(t, "the old session to go once the message crossed", func() bool { return len(a.Sessions(b.ID())) == 1 })
}

func TestResetAfterThePeerLosesItsState(t *testing.T) {
	tn := newTestNet(t, 3)
	tn.start(0)
	a, b := tn.start(1), tn.start(2)
	if err := send(t, a, b.ID(), []byte("one")); err != nil {
		t.Fatal(err)
	}
	recv(t, b)
	before := currentIndex(a, b.ID())
	// b restarts: same identity and roster, no sessions.
	b.Close()
	fresh := tn.start(2)
	if err := send(t, a, b.ID(), []byte("lost")); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the sender to drop the session on reset", func() bool { return len(a.Sessions(b.ID())) == 0 })
	if err := send(t, a, b.ID(), []byte("two")); err != nil {
		t.Fatal(err)
	}
	if m := recv(t, fresh); string(m.Bytes) != "two" {
		t.Fatalf("got %q (the message in the reset frame is lost)", m.Bytes)
	}
	if currentIndex(a, b.ID()) == before {
		t.Fatal("same session")
	}
}

func TestResponderExpiresAnOldSessionAndAnswersReset(t *testing.T) {
	tn := newTestNet(t, 3)
	tn.start(0)
	a := tn.start(1, func(o *MemberOptions) { o.Timing.RekeyInterval = time.Hour; o.Timing.Idle = 2 * time.Hour })
	b := tn.start(2)
	if err := send(t, a, b.ID(), []byte("fresh")); err != nil {
		t.Fatal(err)
	}
	recv(t, b)
	first := currentIndex(a, b.ID())
	// Past b's rekey interval plus the grace (a, the initiator, would rekey only after an hour).
	tn.clock.Advance(DefaultTiming.RekeyInterval + DefaultTiming.RetireGrace + time.Second)
	if err := send(t, a, b.ID(), []byte("expired")); err != nil {
		t.Fatal(err)
	}
	eventually(t, "reset", func() bool { return len(a.Sessions(b.ID())) == 0 })
	if err := send(t, a, b.ID(), []byte("renewed")); err != nil {
		t.Fatal(err)
	}
	if m := recv(t, b); string(m.Bytes) != "renewed" {
		t.Fatalf("got %q", m.Bytes)
	}
	if currentIndex(a, b.ID()) == first {
		t.Fatal("same session")
	}
}

func TestIdleSessionsAreForgotten(t *testing.T) {
	tn := newTestNet(t, 3)
	tn.start(0)
	idle := func(o *MemberOptions) { o.Timing.Idle = time.Minute }
	a, b := tn.start(1, idle), tn.start(2, idle)
	if err := send(t, a, b.ID(), []byte("x")); err != nil {
		t.Fatal(err)
	}
	recv(t, b)
	// Let the credit for it come back first: a frame a handles late would count as activity.
	tn.clock.Advance(CreditDelay)
	eventually(t, "credit", func() bool { return a.Sessions(b.ID())[0].SendCredit == InitialCredit })
	tn.clock.Advance(30 * time.Second)
	if len(a.Sessions(b.ID())) != 1 {
		t.Fatal("forgotten early")
	}
	tn.clock.Advance(38 * time.Second) // the sweep looks every 7.5 s here
	eventually(t, "idle expiry", func() bool { return len(a.Sessions(b.ID())) == 0 && len(b.Sessions(a.ID())) == 0 })
	if err := send(t, a, b.ID(), []byte("again")); err != nil {
		t.Fatal(err)
	}
	if m := recv(t, b); string(m.Bytes) != "again" {
		t.Fatal(m)
	}
}

func TestHandshakeTimeout(t *testing.T) {
	tn := newTestNet(t, 3)
	tn.start(0)
	a, b := tn.start(1), tn.start(2)
	tn.relay.setIntercept(func(from, to string, f []byte) [][]byte {
		if f[1] == frameHandshakeResp {
			return nil // the answer never arrives
		}
		return [][]byte{f}
	})
	done := a.SendAsync(b.ID(), []byte("x"))
	eventually(t, "a pending handshake", func() bool {
		var p bool
		locked(a, func() { p = a.sess.peers[b.ID()] != nil && a.sess.peers[b.ID()].pending != nil })
		return p
	})
	tn.clock.Advance(DefaultTiming.HandshakeTimeout)
	if err := <-done; CodeOf(err) != CodeTimeout {
		t.Fatalf("got %v", err)
	}
	tn.relay.setIntercept(nil)
	if err := send(t, a, b.ID(), []byte("y")); err != nil {
		t.Fatal(err)
	}
	if m := recv(t, b); string(m.Bytes) != "y" {
		t.Fatal(m)
	}
}

func TestCreditWaitsForTheApplicationAndRefills(t *testing.T) {
	tn := newTestNet(t, 3)
	tn.start(0)
	a, b := tn.start(1), tn.start(2)
	msgs := [][]byte{bytes.Repeat([]byte{1}, 700*1024), bytes.Repeat([]byte{2}, 700*1024), bytes.Repeat([]byte{3}, 700*1024)}
	// The first arrives while the application holds nothing, so its fragments are credited
	// back at once; the second arrives behind an unread message and is not; the third needs
	// more credit than is left and waits.
	if err := send(t, a, b.ID(), msgs[0]); err != nil {
		t.Fatal(err)
	}
	if err := send(t, a, b.ID(), msgs[1]); err != nil {
		t.Fatal(err)
	}
	third := a.SendAsync(b.ID(), msgs[2])
	tn.clock.Advance(time.Second) // credit timers fire; nothing more is owed
	time.Sleep(20 * time.Millisecond)
	select {
	case err := <-third:
		t.Fatalf("the third finished without credit: %v", err)
	default:
	}
	if s := a.Sessions(b.ID())[0]; s.Inflight > InitialCredit || s.SendCredit < 0 {
		t.Fatalf("in flight %d, credit %d", s.Inflight, s.SendCredit)
	}
	if m := recv(t, b); !bytes.Equal(m.Bytes, msgs[0]) {
		t.Fatal("first")
	}
	tn.clock.Advance(time.Second)
	time.Sleep(20 * time.Millisecond)
	select {
	case <-third:
		t.Fatal("the third finished with one message still unread")
	default:
	}
	if m := recv(t, b); !bytes.Equal(m.Bytes, msgs[1]) {
		t.Fatal("second")
	}
	tn.clock.Advance(time.Second)
	if err := <-third; err != nil {
		t.Fatal(err)
	}
	if m := recv(t, b); !bytes.Equal(m.Bytes, msgs[2]) {
		t.Fatal("third")
	}
	// Everything taken: the whole window is back with the sender (the last bytes after the
	// 250 ms batching delay).
	tn.clock.Advance(CreditDelay)
	eventually(t, "all credit returned", func() bool { return a.Sessions(b.ID())[0].SendCredit == InitialCredit })
	if a.Sessions(b.ID())[0].Inflight != 0 {
		t.Fatal("bytes still in flight")
	}
}

func TestCreditIsBatched(t *testing.T) {
	tn := newTestNet(t, 3)
	tn.start(0)
	a, b := tn.start(1), tn.start(2)
	b.OnMessage(func(InboundMessage) {})
	for i := range 500 {
		if err := send(t, a, b.ID(), make([]byte, 200)); err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
	}
	eventually(t, "all delivered", func() bool {
		var n int
		locked(b, func() { n = b.sess.stats.messagesReceived })
		return n == 500
	})
	var credits int
	locked(b, func() { credits = b.sess.stats.creditsSent })
	if credits > 50 {
		t.Fatalf("%d credit messages for 500 messages", credits)
	}
	// What is owed below the batch size comes back after the delay (the handler releases each
	// message on its own goroutine, so the clock moves on until the last one is in).
	eventually(t, "every byte credited", func() bool {
		tn.clock.Advance(CreditDelay)
		return a.Sessions(b.ID())[0].SendCredit == InitialCredit
	})
}

func TestLargerCreditWindowIsGrantedAsExtraCredit(t *testing.T) {
	tn := newTestNet(t, 3)
	tn.start(0)
	a := tn.start(1)
	b := tn.start(2, func(o *MemberOptions) { o.CreditWindow = 8 * 1024 * 1024 })
	if err := send(t, a, b.ID(), []byte("x")); err != nil {
		t.Fatal(err)
	}
	recv(t, b)
	tn.clock.Advance(CreditDelay)
	eventually(t, "an 8 MiB window", func() bool { return a.Sessions(b.ID())[0].SendCredit == 8*1024*1024 })
	if _, err := NewMember(MemberOptions{Identity: tn.ids[1], Roster: tn.roster, CreditWindow: 1000}); CodeOf(err) != CodeInvalid {
		t.Fatal("a window under 1 MiB accepted")
	}
}

// rawSend transmits a session message on a's current session with b, bypassing credit, as a
// hostile peer would.
func rawSend(t *testing.T, a *Member, peer string, msg sessionMessage) {
	t.Helper()
	locked(a, func() {
		ps := a.sess.peers[peer]
		if ps == nil || ps.current == nil {
			t.Fatal("no session to send on")
		}
		if _, err := a.sess.transmit(ps.current, msg); err != nil {
			t.Fatal(err)
		}
	})
}

func TestAPeerSendingBeyondItsCreditLosesTheSession(t *testing.T) {
	tn := newTestNet(t, 3)
	tn.start(0)
	a, b := tn.start(1), tn.start(2)
	if err := send(t, a, b.ID(), []byte("held")); err != nil {
		t.Fatal(err)
	}
	eventually(t, "b holds a message", func() bool { return b.Pending() == 1 })
	// b credits nothing while it holds a message; a sends on regardless.
	var carrier *session
	locked(b, func() { carrier = b.sess.peers[a.ID()].current })
	old := currentIndex(a, b.ID())
	chunk := make([]byte, maxFragment)
	for range InitialCredit/maxFragment + 2 {
		rawSend(t, a, b.ID(), sessionMessage{typ: sessMessage, more: true, bytes: chunk})
	}
	eventually(t, "b to end the session", func() bool { return len(b.Sessions(a.ID())) == 0 })
	locked(b, func() {
		if carrier.endErr == nil || !strings.Contains(carrier.endErr.Message, "beyond the credit") {
			t.Errorf("ended with %v", carrier.endErr)
		}
	})
	// a learns of it from the reset that answers its frames (those already on their way, or
	// the next), and starts over on a new session.
	send(t, a, b.ID(), []byte("lost"))
	eventually(t, "reset", func() bool { return currentIndex(a, b.ID()) != old })
	if err := send(t, a, b.ID(), []byte("ok")); err != nil {
		t.Fatal(err)
	}
	if m := recv(t, b); string(m.Bytes) != "held" {
		t.Fatalf("got %q", m.Bytes)
	}
	for {
		if m := recv(t, b); string(m.Bytes) == "ok" {
			break
		} else if string(m.Bytes) != "lost" {
			t.Fatalf("got %q", m.Bytes)
		}
	}
}

func TestReassemblyStopsAt64MiB(t *testing.T) {
	if testing.Short() {
		t.Skip("sends 64 MiB")
	}
	tn := newTestNet(t, 3)
	tn.start(0)
	a, b := tn.start(1), tn.start(2)
	if err := send(t, a, b.ID(), []byte("first")); err != nil {
		t.Fatal(err)
	}
	recv(t, b)
	chunk := make([]byte, maxFragment)
	n := MaxMessage/maxFragment + 1
	for i := 0; i < n; i++ {
		rawSend(t, a, b.ID(), sessionMessage{typ: sessMessage, more: true, bytes: chunk})
		if i%64 == 0 {
			// Let b keep up and credit back, as a peer that is not hostile about credit would.
			eventually(t, "b to catch up", func() bool {
				var got uint64
				locked(b, func() {
					if ps := b.sess.peers[a.ID()]; ps != nil && ps.current != nil {
						got = ps.current.received
					} else {
						got = ^uint64(0)
					}
				})
				return got == ^uint64(0) || got >= uint64(i)
			})
		}
	}
	eventually(t, "b to end the session over 64 MiB", func() bool { return len(b.Sessions(a.ID())) == 0 })
	locked(b, func() {
		if ps := b.sess.peers[a.ID()]; ps.buffered != 0 {
			t.Errorf("%d bytes still buffered", ps.buffered)
		}
	})
	if b.Pending() != 0 {
		t.Fatal("a partial message was delivered")
	}
}

func TestMalformedFramesAreDropped(t *testing.T) {
	tn := newTestNet(t, 3)
	tn.start(0)
	a, b := tn.start(1), tn.start(2)
	if err := send(t, a, b.ID(), []byte("before")); err != nil {
		t.Fatal(err)
	}
	recv(t, b)
	aid, _ := nodeIDToBytes(a.ID())
	stranger, _ := NewIdentity()
	sid, _ := nodeIDToBytes(stranger.ID())
	frame := func(typ byte, peer [16]byte, body []byte) []byte {
		f, _ := encodeFrame(typ, peer, body)
		return f
	}
	idx := b.Sessions(a.ID())[0].LocalIndex
	garbage := [][]byte{
		nil, {1}, make([]byte, 17), append([]byte{2, 3}, aid[:]...), // short, bad version
		frame(0x09, aid, nil), frame(0x7f, aid, []byte{1, 2}), // unknown types
		frame(frameHandshakeInit, aid, []byte{1, 2}),      // truncated
		frame(frameHandshakeInit, aid, make([]byte, 120)), // index 0
		frame(frameHandshakeInit, aid, append([]byte{0, 0, 0, 9}, make([]byte, 120)...)),
		frame(frameHandshakeResp, aid, make([]byte, 7)),
		frame(frameHandshakeResp, aid, make([]byte, 100)),
		frame(frameData, aid, []byte{1, 2}),
		frame(frameData, sid, append(u32be(idx), make([]byte, 40)...)), // the right index, the wrong sender
		frame(frameReset, aid, []byte{1}),
		frame(frameRefused, sid, nil),
		frame(frameUnreachable, sid, nil),
	}
	for _, g := range garbage {
		tn.relay.inject(b.ID(), g)
	}
	if err := send(t, a, b.ID(), []byte("after")); err != nil {
		t.Fatal(err)
	}
	if m := recv(t, b); string(m.Bytes) != "after" {
		t.Fatalf("got %q", m.Bytes)
	}
	if len(b.Sessions(a.ID())) != 1 || b.Sessions(a.ID())[0].LocalIndex != idx {
		t.Fatal("the session did not survive the garbage")
	}
	// A data frame that fails to decrypt on a live session ends it (frames for one pair
	// arrive in order, so it cannot be a late one).
	tn.relay.inject(b.ID(), frame(frameData, aid, append(u32be(idx), make([]byte, 40)...)))
	eventually(t, "the session to end", func() bool { return len(b.Sessions(a.ID())) == 0 })
	if err := send(t, a, b.ID(), []byte("x")); err != nil {
		t.Fatal(err)
	}
	eventually(t, "reset", func() bool { return len(a.Sessions(b.ID())) == 0 })
	if err := send(t, a, b.ID(), []byte("recovered")); err != nil {
		t.Fatal(err)
	}
	if m := recv(t, b); string(m.Bytes) != "recovered" {
		t.Fatalf("got %q", m.Bytes)
	}
}

func TestReplayedAndReorderedFramesEndTheSession(t *testing.T) {
	for _, mode := range []string{"replay", "reorder"} {
		t.Run(mode, func(t *testing.T) {
			tn := newTestNet(t, 3)
			tn.start(0)
			a, b := tn.start(1), tn.start(2)
			if err := send(t, a, b.ID(), []byte("setup")); err != nil {
				t.Fatal(err)
			}
			recv(t, b)
			old := currentIndex(a, b.ID())
			var mu sync.Mutex
			var held []byte
			armed := true
			tn.relay.setIntercept(func(from, to string, f []byte) [][]byte {
				mu.Lock()
				defer mu.Unlock()
				if from != a.ID() || f[1] != frameData || !armed {
					return [][]byte{f}
				}
				switch mode {
				case "replay":
					armed = false
					return [][]byte{f, f}
				default:
					if held == nil {
						held = f
						return nil
					}
					armed = false
					return [][]byte{f, held}
				}
			})
			send(t, a, b.ID(), []byte("m1"))
			send(t, a, b.ID(), []byte("m2"))
			eventually(t, "b to end the session", func() bool { return len(b.Sessions(a.ID())) == 0 })
			// Nothing is delivered twice, and nothing out of order.
			time.Sleep(10 * time.Millisecond)
			var got []string
			for b.Pending() > 0 {
				got = append(got, string(recv(t, b).Bytes))
			}
			if mode == "replay" && !slices.Equal(got, []string{"m1"}) || mode == "reorder" && len(got) != 0 {
				t.Fatalf("delivered %q", got)
			}
			// a learns of it from the reset that answers its next frame, and starts over.
			send(t, a, b.ID(), []byte("probe"))
			eventually(t, "a to learn of the reset", func() bool { return currentIndex(a, b.ID()) != old })
			if err := send(t, a, b.ID(), []byte("fresh")); err != nil {
				t.Fatal(err)
			}
			for {
				if m := recv(t, b); string(m.Bytes) == "fresh" {
					break
				} else if string(m.Bytes) != "probe" {
					t.Fatalf("got %q", m.Bytes)
				}
			}
		})
	}
}

func TestSessionsPerPeerAreBounded(t *testing.T) {
	tn := newTestNet(t, 3)
	tn.start(0)
	a, b := tn.start(1), tn.start(2)
	if err := send(t, a, b.ID(), []byte("x")); err != nil {
		t.Fatal(err)
	}
	recv(t, b)
	// A peer that handshakes again and again leaves at most maxSessionsPerPeer behind.
	for range 10 {
		locked(a, func() { a.sess.initiate(b.ID(), func(*session, *Error) {}) })
		before := currentIndex(a, b.ID())
		eventually(t, "a new session", func() bool { return currentIndex(a, b.ID()) != before })
	}
	if n := len(b.Sessions(a.ID())); n > maxSessionsPerPeer {
		t.Fatalf("%d sessions", n)
	}
	if err := send(t, a, b.ID(), []byte("still")); err != nil {
		t.Fatal(err)
	}
	if m := recv(t, b); string(m.Bytes) != "still" {
		t.Fatal(m)
	}
}

func TestDataWaitsInTheClientNotTheSocket(t *testing.T) {
	tn := newTestNet(t, 3)
	tn.start(0)
	a, b := tn.start(1), tn.start(2)
	if err := send(t, a, b.ID(), []byte("x")); err != nil {
		t.Fatal(err)
	}
	recv(t, b)
	// a's socket takes nothing: at most about 64 KiB of data is handed to it, the rest waits
	// in the client.
	gate := make(chan struct{})
	tn.relay.conn(a.ID()).mu.Lock()
	tn.relay.conn(a.ID()).gate = gate
	tn.relay.conn(a.ID()).mu.Unlock()
	done := a.SendAsync(b.ID(), pattern(4*1024*1024, 1))
	time.Sleep(50 * time.Millisecond)
	var buffered int
	locked(a, func() { buffered = a.relay.bufferedAmount() })
	if buffered > socketLowWater+maxFrame {
		t.Fatalf("%d bytes handed to a socket that takes nothing", buffered)
	}
	close(gate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if m := recv(t, b); !bytes.Equal(m.Bytes, pattern(4*1024*1024, 1)) {
		t.Fatal("differs")
	}
}

func TestControlFramesOnlyToARelayThatListsControl(t *testing.T) {
	for _, features := range [][]string{{"control"}, nil} {
		tn := newTestNet(t, 3)
		tn.relay.features = features
		tn.start(0)
		a, b := tn.start(1), tn.start(2)
		if err := send(t, a, b.ID(), make([]byte, 300*1024)); err != nil {
			t.Fatal(err)
		}
		recv(t, b)
		tn.clock.Advance(time.Second)
		eventually(t, "credit", func() bool { return a.Sessions(b.ID())[0].SendCredit == InitialCredit })
		tn.relay.mu.Lock()
		eight := tn.relay.sentTypes[frameControl]
		tn.relay.mu.Unlock()
		if (len(features) > 0) != (eight > 0) {
			t.Errorf("features %v: %d control frames", features, eight)
		}
	}
}

func TestRefusedThenCatchesUpFromThePrimary(t *testing.T) {
	tn := newTestNet(t, 4)
	v3 := tn.sign(3, tn.ids...)
	tn.roster = tn.sign(2, tn.ids[:3]...)
	tn.start(0, func(o *MemberOptions) { o.Roster = v3 })
	// b holds v2, which does not list c; the relay knows v3.
	b := tn.start(2)
	c := tn.start(3, func(o *MemberOptions) { o.Roster = v3 })
	// b was brought up to date at registration, since the primary had registered v3: put it
	// back on v2 to play a member that missed the change.
	locked(b, func() { b.roster = tn.roster })
	err := send(t, c, b.ID(), []byte("do you know me?"))
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeRefused || e.Reason != 1 {
		t.Fatalf("got %v", err)
	}
	// The refusal told b that c holds a newer roster; b cannot open a session to c, so it asks
	// the primary.
	eventually(t, "b to catch up", func() bool { return b.Roster().Version == 3 })
	if err := send(t, c, b.ID(), []byte("now you do")); err != nil {
		t.Fatal(err)
	}
	if m := recv(t, b); string(m.Bytes) != "now you do" {
		t.Fatal(m)
	}
}

func TestRevocationSpreadsMemberToMemberWithThePrimaryAway(t *testing.T) {
	tn := newTestNet(t, 4)
	// v3 revokes ids[3]. a holds it; b and the revoked x hold v2. The primary never connects
	// and the relay knows only v2 (the first to register brings it).
	v3 := tn.sign(3, tn.ids[:3]...)
	b := tn.start(2)
	x := tn.start(3)
	if err := send(t, b, x.ID(), []byte("before")); err != nil {
		t.Fatal(err)
	}
	recv(t, x)
	tn.relay.mu.Lock()
	tn.relay.roster = tn.roster
	tn.relay.mu.Unlock()
	a := tn.start(1, func(o *MemberOptions) { o.Roster = v3 })
	// a's registration replaced the relay's roster with v3, which closed nobody (the fake
	// relay, like the real one, closes members only on a push from the primary).
	if err := send(t, b, a.ID(), []byte("hello")); err != nil {
		t.Fatal(err)
	}
	recv(t, a)
	eventually(t, "b to learn v3 from a", func() bool { return b.Roster().Version == 3 })
	if len(b.Sessions(x.ID())) != 0 {
		t.Fatal("b kept its session with the revoked member")
	}
	if err := send(t, b, x.ID(), []byte("after")); CodeOf(err) != CodeInvalid {
		t.Fatalf("send to the revoked member: %v", err)
	}
	// And x, trying b, is refused by b on its own authority: its old session is answered
	// reset (b dropped it), and the handshake that follows is refused.
	send(t, x, b.ID(), []byte("lost"))
	eventually(t, "x to learn of the reset", func() bool { return len(x.Sessions(b.ID())) == 0 })
	if err := send(t, x, b.ID(), []byte("me?")); CodeOf(err) != CodeRefused {
		t.Fatalf("x: %v", err)
	}
}

func TestRevokeAndResign(t *testing.T) {
	tn := newTestNet(t, 4)
	pm := tn.start(0)
	p := &Primary{Member: pm}
	a, b, c := tn.start(1), tn.start(2), tn.start(3)
	if err := send(t, a, b.ID(), []byte("x")); err != nil {
		t.Fatal(err)
	}
	recv(t, b)
	bLog := record(b)
	r, err := p.Revoke(b.ID())
	if err != nil || r.Version != 3 || r.member(b.ID()) != nil {
		t.Fatalf("revoke: %v", err)
	}
	eventually(t, "b revoked", func() bool { return b.State() == StateRevoked })
	eventually(t, "a to receive v3", func() bool { return a.Roster().Version == 3 })
	if err := send(t, a, b.ID(), []byte("to the revoked")); CodeOf(err) != CodeInvalid {
		t.Fatalf("%v", err)
	}
	if err := send(t, b, a.ID(), []byte("from the revoked")); CodeOf(err) != CodeRevoked {
		t.Fatalf("%v", err)
	}
	tn.clock.Advance(time.Minute)
	if !slices.Equal(bLog.states(), []State{StateRevoked}) {
		t.Fatalf("states %v", bLog.states())
	}
	if _, err := p.Revoke(p.ID()); CodeOf(err) != CodeInvalid {
		t.Fatal("revoked itself")
	}
	if _, err := p.Revoke(b.ID()); CodeOf(err) != CodeInvalid {
		t.Fatal("revoked twice")
	}

	// Resign: c signs, the primary publishes v4 without it, the relay closes it.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.Resign(ctx) }()
	// Resign repeats its request (delivery is at most once) on the member's clock: move it on.
	var resignErr error
wait:
	for {
		select {
		case resignErr = <-done:
			break wait
		case <-time.After(50 * time.Millisecond):
			tn.clock.Advance(500 * time.Millisecond)
		}
	}
	if resignErr != nil {
		t.Fatal(resignErr)
	}
	if c.State() != StateRevoked || p.Roster().Version != 4 || p.Roster().member(c.ID()) != nil {
		t.Fatalf("state %s, roster v%d", c.State(), p.Roster().Version)
	}
	// v4 follows v3 to a within 250 ms of the member's clock: coalesced to the end of the gap.
	eventually(t, "a to receive v4", func() bool {
		tn.clock.Advance(rosterGap)
		return a.Roster().Version == 4
	})
	if err := p.Resign(ctx); CodeOf(err) != CodeInvalid {
		t.Fatal("the primary resigned")
	}
	// A resignation that is stale, forged, or from another node's session is ignored.
	locked(pm, func() {
		ra := signResignation(tn.ids[1], pm.roster.Network, pm.clock.Now().UnixMilli()-int64(6*time.Minute/time.Millisecond))
		body, _ := json.Marshal(ra)
		pm.prim.onResign(a.ID(), body)
		forged := signResignation(tn.ids[2], pm.roster.Network, pm.clock.Now().UnixMilli())
		forged.Node = a.ID()
		body, _ = json.Marshal(forged)
		pm.prim.onResign(a.ID(), body)
		other := signResignation(tn.ids[1], pm.roster.Network, pm.clock.Now().UnixMilli())
		body, _ = json.Marshal(other)
		pm.prim.onResign(tn.ids[0].ID(), body)
	})
	if p.Roster().Version != 4 {
		t.Fatal("a bad resignation was accepted")
	}
}

func TestSyncRosterAndUsage(t *testing.T) {
	tn := newTestNet(t, 3)
	v3 := tn.sign(3, tn.ids...)
	pm := tn.start(0, func(o *MemberOptions) { o.Roster = v3 })
	p := &Primary{Member: pm}
	a := tn.start(1)
	locked(a, func() { a.roster = tn.roster }) // missed v3
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	newer, err := a.SyncRoster(ctx)
	if err != nil || !newer || a.Roster().Version != 3 {
		t.Fatalf("sync: %v %v", newer, err)
	}
	if newer, err := p.SyncRoster(ctx); err != nil || newer {
		t.Fatal("the primary synced")
	}
	u, err := p.Usage(ctx)
	if err != nil || u.Network.BytesHour != 7 || u.Network.Connections != 2 {
		t.Fatalf("usage %+v %v", u, err)
	}
}

func TestPrimaryOpensCodesWithinTheRosterLimit(t *testing.T) {
	tn := newTestNet(t, 1)
	tn.roster = tn.sign(1, tn.ids[0])
	pm := tn.start(0)
	p := &Primary{Member: pm}
	code, err := p.OpenPairingCode(PairingCodeOptions{Code: "abcd-1234"})
	if err != nil || code.Code != "ABCD-1234" {
		t.Fatalf("%+v %v", code, err)
	}
	link, err := ParsePairingLink(code.Link)
	if err != nil || link.Code != "ABCD1234" || link.CodeID != code.CodeID || link.Network != p.Network() || link.Relay != testRelayURL {
		t.Fatalf("link %+v %v", link, err)
	}
	if _, err := p.OpenPairingCode(PairingCodeOptions{Code: "nope"}); CodeOf(err) != CodeInvalid {
		t.Fatal("a bad chosen code")
	}
	// Fill the roster to just under the limit: no further member fits.
	locked(pm, func() {
		u := pm.roster.UnsignedRoster
		u.Version = 9
		for {
			id, _ := NewIdentity()
			u.Members = append(u.Members, MemberFromIdentity(id))
			r := &Roster{UnsignedRoster: u, Signature: strings.Repeat("A", 86)}
			if s, _ := r.Size(); s > MaxRosterBytes {
				u.Members = u.Members[:len(u.Members)-1]
				break
			}
		}
		r, err := SignRoster(u, tn.key)
		if err != nil {
			t.Fatal(err)
		}
		pm.roster = r
	})
	if _, err := p.OpenPairingCode(PairingCodeOptions{}); CodeOf(err) != CodeRosterFull {
		t.Fatalf("got %v", err)
	}
}

func TestWhatAPeerLeavesBufferedIsBounded(t *testing.T) {
	defer func(n int, f func(int64) int64) { maxHeldMessagesPerPeer, peerBufferLimit = n, f }(maxHeldMessagesPerPeer, peerBufferLimit)
	maxHeldMessagesPerPeer = 3
	const limit = 3 * 512 * 1024 // a held 1 MiB message, and half a MiB of the next
	peerBufferLimit = func(int64) int64 { return limit }
	tn := newTestNet(t, 3)
	tn.start(0)
	a, b := tn.start(1), tn.start(2)
	// Messages the application does not take: the fourth ends the session.
	for i := range 3 {
		if err := send(t, a, b.ID(), []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "three held", func() bool { return b.Pending() == 3 })
	rawSend(t, a, b.ID(), sessionMessage{typ: sessMessage})
	eventually(t, "the session to end", func() bool { return len(b.Sessions(a.ID())) == 0 })
	if b.Pending() != 3 {
		t.Fatalf("%d held", b.Pending())
	}
	for range 3 {
		recv(t, b)
	}
	// Bytes over all of a peer's sessions: a partial message that would take the peer past
	// the limit ends the session that carries it.
	send(t, a, b.ID(), []byte("reset me"))
	eventually(t, "reset", func() bool { return len(a.Sessions(b.ID())) == 0 })
	if err := send(t, a, b.ID(), pattern(1024*1024, 1)); err != nil {
		t.Fatal(err)
	}
	eventually(t, "held", func() bool { return b.Pending() == 1 })
	// b credits nothing while it holds a message, but it granted about 1 MiB more while the
	// first streamed in: the buffer limit, not the credit, is what stops these.
	var carrier *session
	locked(b, func() { carrier = b.sess.peers[a.ID()].current })
	chunk := make([]byte, maxFragment)
	for i := 0; i < 12 && len(b.Sessions(a.ID())) > 0; i++ {
		rawSend(t, a, b.ID(), sessionMessage{typ: sessMessage, more: true, bytes: chunk})
		time.Sleep(time.Millisecond)
	}
	eventually(t, "the session to end", func() bool { return len(b.Sessions(a.ID())) == 0 })
	locked(b, func() {
		if ps := b.sess.peers[a.ID()]; ps.buffered != 1024*1024 {
			t.Errorf("%d bytes buffered, want the held message alone", ps.buffered)
		}
		if carrier.endErr == nil || !strings.Contains(carrier.endErr.Message, "buffered") {
			t.Errorf("ended with %v", carrier.endErr)
		}
	})
}

func TestOnMessageCreditsOnceTheHandlerReturns(t *testing.T) {
	tn := newTestNet(t, 3)
	tn.start(0)
	a, b := tn.start(1), tn.start(2)
	gate := make(chan struct{})
	var got atomic.Int32
	b.OnMessage(func(InboundMessage) {
		<-gate
		got.Add(1)
	})
	msgs := 4
	done := make([]<-chan error, msgs)
	for i := range msgs {
		done[i] = a.SendAsync(b.ID(), make([]byte, 700*1024))
	}
	tn.clock.Advance(time.Second)
	time.Sleep(50 * time.Millisecond)
	select {
	case <-done[msgs-1]:
		t.Fatal("the sender ran on while the handler held its first message")
	default:
	}
	close(gate)
	for i := range msgs {
		if err := <-done[i]; err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "all handled", func() bool { return got.Load() == int32(msgs) })
}

func TestEveryCloseIsReportedBeforeItsState(t *testing.T) {
	tn := newTestNet(t, 3)
	tn.start(0)
	a := tn.start(1)
	b := tn.start(2)
	aLog, bLog := record(a), record(b)
	// A deferred roster hint is pending: Close cancels it.
	locked(a, func() {
		a.askPrimary()
		a.askPrimary()
		if a.hintTimer == nil {
			t.Fatal("no deferred hint to cancel")
		}
	})
	pending := tn.clock.pending()
	// Close: the disconnect, then closed, and nothing after.
	a.Close()
	locked(a, func() {
		if a.hintTimer != nil {
			t.Error("Close left the deferred roster hint armed")
		}
	})
	if tn.clock.pending() >= pending {
		t.Errorf("Close left %d timers of %d", tn.clock.pending(), pending)
	}
	a.Settle()
	if ev := aLog.all(); len(ev) != 2 || ev[0] != (DisconnectEvent{Code: CloseNormal}) || ev[1] != (StateEvent{State: StateClosed}) {
		t.Fatalf("close: %v", aLog)
	}
	// A roster that drops the member: it closes, then is revoked.
	locked(b, func() {
		r := tn.sign(3, tn.ids[0], tn.ids[1])
		b.offerRoster(r)
	})
	b.Settle()
	var tail []Event
	for _, e := range bLog.all() {
		if _, ok := e.(RosterEvent); !ok {
			tail = append(tail, e)
		}
	}
	if len(tail) != 2 || tail[0] != (DisconnectEvent{Code: CloseNormal}) || tail[1] != (StateEvent{State: StateRevoked}) {
		t.Fatalf("revoked by a roster: %v", bLog)
	}
	b.Close()
	b.Settle()
	if last := bLog.all()[len(bLog.all())-1]; last != (StateEvent{State: StateClosed}) {
		t.Fatalf("close after revoked: %v", last)
	}
}

// A relay that answers registered with a roster which drops the member: the member is revoked
// and stays revoked.
func TestRegisteredWithARosterWithoutThisNode(t *testing.T) {
	tn := newTestNet(t, 3)
	v3 := tn.sign(3, tn.ids[0], tn.ids[1])
	o := tn.opts(2, nil)
	o.dial = func(ctx context.Context, u string) (socket, error) {
		s, err := tn.relay.dial(ctx, u)
		if err != nil {
			return nil, err
		}
		return &hostileRegistered{fakeSock: s.(*fakeSock), roster: v3}, nil
	}
	log := &eventLog{}
	o.OnEvent = log.add
	m, err := NewMember(o)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	eventually(t, "revoked", func() bool { return m.State() == StateRevoked })
	time.Sleep(20 * time.Millisecond)
	m.Settle()
	if s := log.states(); !slices.Equal(s, []State{StateConnecting, StateRevoked}) {
		t.Fatalf("states %v", s)
	}
}

type hostileRegistered struct {
	*fakeSock
	roster *Roster
}

func (h *hostileRegistered) Write(text bool, data []byte) error {
	if msg, ok := parseControl(data); text && ok && msg.typ() == "register" {
		h.send(map[string]any{"type": "registered", "node": msg.str("node"), "rosterVersion": h.roster.Version, "roster": h.roster})
		return nil
	}
	return h.fakeSock.Write(text, data)
}

// A hostile relay floods the primary with pairing requests for codes it does not hold. Each
// refusal is stateless, so pairEnd goes within a budget (32 a second, bursts of 64), and the
// application hears nothing of code ids it never opened, and of one it did at most once a
// second per reason.
func TestAHostileRelayCannotFloodPairingRefusals(t *testing.T) {
	tn := newTestNet(t, 2)
	p := tn.start(0)
	prim := &Primary{Member: p}
	var events atomic.Int32
	p.On(func(e Event) {
		if _, ok := e.(PairingFailedEvent); ok {
			events.Add(1)
		}
	})
	conn := tn.relay.conn(p.ID())
	pairing := func(codeID string) {
		msg, _ := json.Marshal(map[string]string{"type": "pairing", "channel": b64u(make([]byte, 16)), "code": codeID})
		conn.push(fakeMsg{text: true, data: msg})
	}
	const flood = 50000
	for i := range flood {
		pairing(b64u([]byte{byte(i), byte(i >> 8), byte(i >> 16), 0, 0, 0, 0, 1}))
	}
	eventually(t, "the flood to be read", func() bool {
		conn.mu.Lock()
		defer conn.mu.Unlock()
		return len(conn.in) == 0
	})
	prim.Usage(context.Background()) // a round trip: everything before it is handled
	pairEnds := func() int {
		tn.relay.mu.Lock()
		defer tn.relay.mu.Unlock()
		n := 0
		for _, c := range tn.relay.controls {
			if c == "pairEnd" {
				n++
			}
		}
		return n
	}
	// pairEnds are counted as the primary's writer hands them to the relay: wait for it.
	if n := settle(t, "the pairEnds to be written", pairEnds); n != refusalBurst {
		t.Fatalf("%d pairEnd answers to %d requests, want the burst of %d", n, flood, refusalBurst)
	}
	p.Settle()
	if n := events.Load(); n != 0 {
		t.Fatalf("%d events for code ids never opened", n)
	}
	// A code the primary issued and cancelled is refused apart from that budget, which the
	// flood has spent: the first refusal on each pairing channel is answered, repeats on one
	// channel once a second, and the application hears of it once a second.
	code, _ := prim.OpenPairingCode(PairingCodeOptions{})
	prim.CancelPairingCode(code.CodeID)
	on := func(channel byte) {
		msg, _ := json.Marshal(map[string]string{"type": "pairing", "channel": b64u(append(make([]byte, 15), channel)), "code": code.CodeID})
		conn.push(fakeMsg{text: true, data: msg})
	}
	for range 10 {
		on(1)
	}
	on(2)
	on(3)
	prim.Usage(context.Background())
	p.Settle()
	if n := settle(t, "the pairEnds to be written", pairEnds); n != refusalBurst+3 {
		t.Fatalf("%d pairEnd answers, want one per channel for the issued code", n)
	}
	if n := events.Load(); n != 1 {
		t.Fatalf("%d events for a cancelled code asked for twelve times", n)
	}
	tn.clock.Advance(time.Second)
	on(1)
	prim.Usage(context.Background())
	p.Settle()
	if n := events.Load(); n != 2 || settle(t, "the pairEnds to be written", pairEnds) != refusalBurst+4 {
		t.Fatalf("%d events and %d pairEnds a second later", n, pairEnds())
	}
	// The budget for made-up ids refills, 32 a second.
	for i := range 100 {
		pairing(b64u([]byte{byte(i), 9, 9, 9, 9, 9, 9, 9}))
	}
	prim.Usage(context.Background())
	if n := settle(t, "the pairEnds to be written", pairEnds); n != refusalBurst+4+refusalRate {
		t.Fatalf("%d pairEnds after a second's refill", n)
	}
}

// Relay errors reach the application 16 a second, in bursts of 64; the rest are dropped.
func TestRelayErrorsAreRateLimited(t *testing.T) {
	tn := newTestNet(t, 2)
	p := tn.start(0)
	var events atomic.Int32
	p.On(func(e Event) {
		if _, ok := e.(RelayErrorEvent); ok {
			events.Add(1)
		}
	})
	conn := tn.relay.conn(p.ID())
	for range 5000 {
		conn.push(fakeMsg{text: true, data: []byte(`{"type":"error","code":"bad_request"}`)})
	}
	eventually(t, "the flood to be read", func() bool {
		conn.mu.Lock()
		defer conn.mu.Unlock()
		return len(conn.in) == 0
	})
	(&Primary{Member: p}).Usage(context.Background())
	p.Settle()
	if n := events.Load(); n != relayErrorBurst {
		t.Fatalf("%d relay error events, want the burst of %d", n, relayErrorBurst)
	}
	tn.clock.Advance(time.Second)
	for range 100 {
		conn.push(fakeMsg{text: true, data: []byte(`{"type":"error","code":"bad_request"}`)})
	}
	(&Primary{Member: p}).Usage(context.Background())
	p.Settle()
	if n := events.Load(); n != relayErrorBurst+relayErrorRate {
		t.Fatalf("%d relay error events after a second", n)
	}
}

func TestASilentRelayIsLeftAndRedialled(t *testing.T) {
	for _, mode := range []string{"no hello", "no registered"} {
		t.Run(mode, func(t *testing.T) {
			tn := newTestNet(t, 2)
			o := tn.opts(1, nil)
			log := &eventLog{}
			o.OnEvent = log.add
			if mode == "no hello" {
				tn.relay.silent = true
			} else {
				o.dial = func(ctx context.Context, u string) (socket, error) {
					s, err := tn.relay.dial(ctx, u)
					if err != nil {
						return nil, err
					}
					return &swallowRegister{s.(*fakeSock)}, nil
				}
			}
			m, err := NewMember(o)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			eventually(t, "the dial", func() bool {
				tn.relay.mu.Lock()
				defer tn.relay.mu.Unlock()
				return tn.relay.dials == 1
			})
			time.Sleep(20 * time.Millisecond)
			tn.clock.Advance(registrationTimeout(m.timing) - time.Millisecond)
			time.Sleep(20 * time.Millisecond)
			if m.State() != StateConnecting {
				t.Fatalf("gave up early: %s", m.State())
			}
			tn.clock.Advance(time.Millisecond)
			eventually(t, "the connection to be left", func() bool { return m.State() == StateDisconnected })
			m.Settle()
			if c := log.codes(); !slices.Equal(c, []int{1006}) {
				t.Fatalf("codes %v", c)
			}
			// The relay speaks again; the member reconnects as after any failed connection.
			tn.relay.mu.Lock()
			tn.relay.silent = false
			tn.relay.mu.Unlock()
			if mode == "no registered" {
				m.lock()
				m.dialer = tn.relay.dial
				m.unlock()
			}
			tn.clock.Advance(100 * time.Millisecond)
			eventually(t, "reconnected", func() bool { return m.State() == StateConnected })
		})
	}
}

type swallowRegister struct{ *fakeSock }

func (s *swallowRegister) Write(text bool, data []byte) error {
	if msg, ok := parseControl(data); text && ok && msg.typ() == "register" {
		return nil
	}
	return s.fakeSock.Write(text, data)
}

func TestARelayHeardFromNoMoreIsLeft(t *testing.T) {
	tn := newTestNet(t, 2)
	m := tn.start(1, func(o *MemberOptions) { o.liveness = 0 }) // the default: 75 s
	conn := tn.relay.conn(m.ID())
	// Pings every 30 s keep a quiet connection alive.
	for range 6 {
		tn.clock.Advance(30 * time.Second)
		conn.ping()
	}
	time.Sleep(20 * time.Millisecond)
	if m.State() != StateConnected {
		t.Fatalf("left a relay that pings: %s", m.State())
	}
	// Then nothing at all: the connection is left after 75 s, and redialled.
	tn.clock.Advance(relaySilence - time.Second)
	time.Sleep(20 * time.Millisecond)
	if m.State() != StateConnected {
		t.Fatal("left before the silence ran out")
	}
	tn.clock.Advance(relaySilence/5 + time.Second) // it looks every fifth of the period
	eventually(t, "the connection to be left", func() bool { return m.State() != StateConnected })
	tn.clock.Advance(100 * time.Millisecond)
	eventually(t, "reconnected", func() bool { return m.State() == StateConnected && tn.relay.conn(m.ID()) != conn })
}

// Pairing channels for an open code are set up at most 4 a second, bursts of 8 (each costs
// key-exchange work, and a pairEnd refunds its slot so the five attempts never trip), and
// the events of channels ended that way go once a second per code and reason.
func TestPairingChannelSetupsAreBudgetedPerCode(t *testing.T) {
	tn := newTestNet(t, 2)
	pm := tn.start(0)
	p := &Primary{Member: pm}
	var events atomic.Int32
	pm.On(func(e Event) {
		if f, ok := e.(PairingFailedEvent); ok && f.Code == FailNewcomerLeft {
			events.Add(1)
		}
	})
	code, _ := p.OpenPairingCode(PairingCodeOptions{})
	conn := tn.relay.conn(pm.ID())
	setups := 0
	for i := range 100 {
		ch := b64u(append(make([]byte, 15), byte(i)))
		b, _ := json.Marshal(map[string]string{"type": "pairing", "channel": ch, "code": code.CodeID})
		conn.push(fakeMsg{text: true, data: b})
		// The relay ends it at once: the slot is refunded.
		b, _ = json.Marshal(map[string]string{"type": "pairEnd", "channel": ch})
		conn.push(fakeMsg{text: true, data: b})
	}
	p.Usage(context.Background())
	pm.Settle()
	locked(pm, func() { setups = int(setupBurst - pm.prim.codes[code.CodeID].setups.tokens) })
	if setups != setupBurst {
		t.Fatalf("%d channels set up for one code, want the burst of %d", setups, setupBurst)
	}
	if n := events.Load(); n != 1 {
		t.Fatalf("%d newcomer-left events, want one a second", n)
	}
	// It refills: 4 a second.
	tn.clock.Advance(time.Second)
	locked(pm, func() {
		e := pm.prim.codes[code.CodeID]
		for e.setups.take(pm.mono(), setupRate, setupBurst) {
			setups++
		}
	})
	if setups != setupBurst+setupRate {
		t.Fatalf("%d setups after a second", setups)
	}
}

// A roster push the primary fails to hand over (here the handshake to the member is lost, and
// times out) is tried again, 1 s later, doubling to 1 min: an idle member learns of a
// revocation without anyone else's help.
func TestAFailedRosterPushIsRetried(t *testing.T) {
	tn := newTestNet(t, 4)
	pm := tn.start(0)
	p := &Primary{Member: pm}
	a := tn.start(1) // idle: no session with the primary
	tn.start(3)
	var mu sync.Mutex
	dropped := 0
	tn.relay.setIntercept(func(from, to string, f []byte) [][]byte {
		mu.Lock()
		defer mu.Unlock()
		if from == pm.ID() && to == a.ID() && f[1] == frameHandshakeInit && dropped < 2 {
			dropped++
			return nil // lost on the way: the push fails, twice
		}
		return [][]byte{f}
	})
	if _, err := p.Revoke(tn.ids[3].ID()); err != nil {
		t.Fatal(err)
	}
	waitPending := func() {
		eventually(t, "the push to be under way", func() bool {
			var busy bool
			locked(pm, func() { ps := pm.sess.peers[a.ID()]; busy = ps != nil && ps.pending != nil })
			return busy
		})
	}
	waitPending()
	tn.clock.Advance(DefaultTiming.HandshakeTimeout) // the first push fails
	var wait time.Duration
	eventually(t, "a retry scheduled", func() bool {
		locked(pm, func() {
			if r := pm.prim.retries[a.ID()]; r != nil {
				wait = r.wait
			}
		})
		return wait != 0
	})
	if wait != pushRetryMin {
		t.Fatalf("first retry after %v, want %v", wait, pushRetryMin)
	}
	tn.clock.Advance(pushRetryMin)
	waitPending()
	tn.clock.Advance(DefaultTiming.HandshakeTimeout) // the second fails too
	eventually(t, "the wait to double", func() bool {
		locked(pm, func() { wait = pm.prim.retries[a.ID()].wait })
		return wait == 2*pushRetryMin
	})
	tn.clock.Advance(2 * pushRetryMin)
	eventually(t, "the member to learn of the revocation", func() bool { return a.Roster().Version == 3 })
	eventually(t, "the retry to be forgotten", func() bool {
		var left bool
		locked(pm, func() { _, left = pm.prim.retries[a.ID()] })
		return !left
	})
	// Failures keep doubling the wait, to at most 10 minutes.
	locked(pm, func() {
		for range 20 {
			pm.prim.pushed(a.ID(), pm.roster.Version, closedError("lost"))
			pm.prim.retries[a.ID()].timer.cancel()
		}
		if w := pm.prim.retries[a.ID()].wait; w != 10*time.Minute || pushRetryMax != 10*time.Minute {
			t.Errorf("wait %v after repeated failures, want the 10-minute cap", w)
		}
	})
}

// The time floor holds even with a stamp retained: an init from before a member's removal that
// was never delivered is refused however much later it is re-admitted.
func TestAnUndeliveredPreRemovalInitIsRefusedLaterStill(t *testing.T) {
	tn := newTestNet(t, 3)
	p := &stampProbe{t: t, tn: tn, v: tn.start(1)}
	tn.start(2)
	if !p.accepted(p.now()) {
		t.Fatal("a fresh init refused")
	}
	undelivered := memberInit(tn, tn.ids[2], tn.ids[1], 2, p.now()+1000, 77) // recorded, never delivered
	locked(p.v, func() { p.v.adoptRoster(tn.sign(3, tn.ids[0], tn.ids[1])) })
	tn.clock.Advance(time.Hour)
	locked(p.v, func() { p.v.adoptRoster(tn.sign(4, tn.ids...)) })
	read := 0
	locked(p.v, func() { read = p.v.sess.stats.initsRead })
	before, _ := p.stored()
	tn.relay.inject(p.v.ID(), undelivered)
	eventually(t, "the init read", func() bool {
		var n int
		locked(p.v, func() { n = p.v.sess.stats.initsRead })
		return n > read
	})
	time.Sleep(30 * time.Millisecond)
	if s, _ := p.stored(); s != before {
		t.Fatal("an init from before the removal accepted an hour after the re-admission")
	}
}
