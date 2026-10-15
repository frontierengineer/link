package link

// An in-memory relay for state-machine tests: registration (with the signature checked as the
// relay checks it), routing with the peer field rewritten, unreachable answers, roster
// pushes, and hooks to drop, repeat, reorder or inject frames and to close connections with
// any code. Members run on a fake clock.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"testing"
	"time"
)

type fakeMsg struct {
	text bool
	data []byte
}

type fakeRelay struct {
	t        *testing.T
	mu       sync.Mutex
	features []string
	conns    map[string]*fakeSock
	roster   *Roster
	dials    int
	refuse   error // dials fail with it
	silent   bool  // new connections hear nothing from the relay, hello included
	// intercept sees every routed frame (after the peer rewrite) and returns what to deliver.
	intercept func(from, to string, frame []byte) [][]byte
	controls  []string     // control message types received from registered members
	sentTypes map[byte]int // routed frame types as members sent them
}

func newFakeRelay(t *testing.T) *fakeRelay {
	return &fakeRelay{t: t, features: []string{"control"}, conns: map[string]*fakeSock{}, sentTypes: map[byte]int{}}
}

type fakeSock struct {
	r         *fakeRelay
	url       string
	mu        sync.Mutex
	cond      *sync.Cond
	in        []fakeMsg
	end       *closeError
	node      string
	challenge []byte
	// gate, when set, holds every write from the member until it is closed: a socket that
	// takes nothing.
	gate   chan struct{}
	onPing func()
	// silent: the relay sends nothing on this connection, hello included.
	silent bool
}

func (r *fakeRelay) dial(_ context.Context, u string) (socket, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dials++
	if r.refuse != nil {
		return nil, r.refuse
	}
	s := &fakeSock{r: r, url: u, challenge: make([]byte, 32), silent: r.silent}
	s.cond = sync.NewCond(&s.mu)
	rand.Read(s.challenge)
	hello, _ := json.Marshal(map[string]any{"type": "hello", "version": 1, "challenge": b64u(s.challenge), "features": r.features})
	s.push(fakeMsg{text: true, data: hello})
	return s, nil
}

func (s *fakeSock) push(m fakeMsg) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.end == nil && !s.silent {
		s.in = append(s.in, m)
		s.cond.Broadcast()
	}
}

func (s *fakeSock) Read() (bool, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.in) == 0 && s.end == nil {
		s.cond.Wait()
	}
	if len(s.in) > 0 {
		m := s.in[0]
		s.in = s.in[1:]
		return m.text, m.data, nil
	}
	return false, nil, s.end
}

// kick is the relay closing the connection with code.
func (s *fakeSock) kick(code int) {
	s.r.mu.Lock()
	if s.r.conns[s.node] == s {
		delete(s.r.conns, s.node)
	}
	s.r.mu.Unlock()
	s.mu.Lock()
	if s.end == nil {
		s.end = &closeError{code: code}
		s.in = nil
		s.cond.Broadcast()
	}
	s.mu.Unlock()
}

func (s *fakeSock) WriteClose(int) error { s.kick(1000); return nil }

func (s *fakeSock) OnPing(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onPing = f
}

// ping is the relay's liveness ping reaching the member.
func (s *fakeSock) ping() {
	s.mu.Lock()
	f := s.onPing
	s.mu.Unlock()
	if f != nil {
		f()
	}
}
func (s *fakeSock) Close() error { s.kick(1006); return nil }

func (s *fakeSock) Write(text bool, data []byte) error {
	s.mu.Lock()
	gate, ended := s.gate, s.end != nil
	s.mu.Unlock()
	if ended {
		return errors.New("closed")
	}
	if gate != nil {
		<-gate
	}
	data = bytes.Clone(data)
	if text {
		s.control(data)
	} else {
		s.binary(data)
	}
	return nil
}

func (s *fakeSock) send(v any) {
	b, _ := json.Marshal(v)
	s.push(fakeMsg{text: true, data: b})
}

func (s *fakeSock) control(data []byte) {
	msg, ok := parseControl(data)
	if !ok {
		s.kick(4000)
		return
	}
	r := s.r
	if s.node == "" {
		if msg.typ() != "register" {
			s.kick(4000)
			return
		}
		s.register(msg)
		return
	}
	r.mu.Lock()
	r.controls = append(r.controls, msg.typ())
	r.mu.Unlock()
	switch msg.typ() {
	case "roster":
		raw, _ := json.Marshal(msg["roster"])
		ro, err := ValidateRoster(raw)
		r.mu.Lock()
		if err != nil || ro.Version <= r.roster.Version || s.node != ro.Network {
			r.mu.Unlock()
			return
		}
		r.roster = ro
		var gone []*fakeSock
		for id, c := range r.conns {
			if ro.member(id) == nil {
				gone = append(gone, c)
			}
		}
		r.mu.Unlock()
		for _, c := range gone {
			c.kick(CloseNotMember)
		}
	case "pairEnd":
	case "usage":
		s.send(map[string]any{"type": "usage", "id": msg.str("id"), "network": map[string]any{
			"bytesHour": 7, "connections": len(r.conns), "limits": map[string]any{"rateBps": 0, "quotaBytesHour": 0, "trickleBps": 0},
			"quotaUsed": 0, "slowed": false}})
	default:
		s.send(map[string]any{"type": "error", "code": "bad_request"})
	}
}

func (s *fakeSock) register(msg controlMessage) {
	r := s.r
	pub, err := fromB64uLen(msg.str("ed25519"), 32, "ed25519")
	if err != nil || NodeIDFromEd25519(pub) != msg.str("node") {
		s.kick(CloseRegistrationFailed)
		return
	}
	ts, _ := safeInteger(msg["ts"])
	u, _ := url.Parse(s.url)
	origin, _ := originOf(u.String())
	sig, _ := fromB64uLen(msg.str("sig"), 64, "sig")
	if !verifyEd25519(pub, registerSigningBytes(msg.str("network"), msg.str("node"), s.challenge, ts, origin), sig) {
		r.t.Errorf("fake relay: a registration signature does not verify (origin %s)", origin)
		s.kick(CloseRegistrationFailed)
		return
	}
	raw, _ := json.Marshal(msg["roster"])
	presented, err := ValidateRoster(raw)
	if err != nil || presented.Network != msg.str("network") {
		s.kick(CloseNotMember)
		return
	}
	r.mu.Lock()
	effective := presented
	newer := false
	if r.roster != nil && r.roster.Network == presented.Network && r.roster.Version > presented.Version {
		effective, newer = r.roster, true
	} else {
		r.roster = presented
	}
	node := msg.str("node")
	if effective.member(node) == nil {
		r.mu.Unlock()
		s.kick(CloseNotMember)
		return
	}
	old := r.conns[node]
	s.node = node
	r.conns[node] = s
	r.mu.Unlock()
	if old != nil {
		old.kick(CloseReplaced)
	}
	reply := map[string]any{"type": "registered", "node": node, "rosterVersion": effective.Version}
	if newer {
		reply["roster"] = effective
	}
	s.send(reply)
}

func (s *fakeSock) binary(data []byte) {
	f, err := decodeFrame(data)
	if err != nil || f.typ == frameUnreachable || f.typ > frameControl {
		s.kick(CloseBadRequest)
		return
	}
	if f.typ == framePair {
		return
	}
	r := s.r
	to := nodeIDFromBytes(f.peer[:])
	r.mu.Lock()
	r.sentTypes[f.typ]++
	dest := r.conns[to]
	intercept := r.intercept
	r.mu.Unlock()
	if dest == nil {
		out, _ := encodeFrame(frameUnreachable, f.peer, nil)
		s.push(fakeMsg{data: out})
		return
	}
	from, _ := nodeIDToBytes(s.node)
	typ := f.typ
	if typ == frameControl {
		typ = frameData
	}
	out, _ := encodeFrame(typ, from, f.body)
	frames := [][]byte{out}
	if intercept != nil {
		frames = intercept(s.node, to, out)
	}
	for _, fr := range frames {
		dest.push(fakeMsg{data: fr})
	}
}

func (r *fakeRelay) conn(node string) *fakeSock {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.conns[node]
}

func (r *fakeRelay) setIntercept(f func(from, to string, frame []byte) [][]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.intercept = f
}

// inject delivers a raw frame to node as if the relay sent it.
func (r *fakeRelay) inject(node string, frame []byte) {
	if c := r.conn(node); c != nil {
		c.push(fakeMsg{data: frame})
	}
}

// ── A network of members on the fake relay ──

type testNet struct {
	t       *testing.T
	relay   *fakeRelay
	clock   *fakeClock
	ids     []*Identity // ids[0] is the primary
	roster  *Roster
	members []*Member
}

const testRelayURL = "wss://relay.test/v1"

// newTestNet makes a network of n identities (the primary first) on one roster at version 2.
func newTestNet(t *testing.T, n int) *testNet {
	t.Helper()
	tn := &testNet{t: t, relay: newFakeRelay(t), clock: newFakeClock(time.UnixMilli(1790000000000))}
	for range n {
		id, err := NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		tn.ids = append(tn.ids, id)
	}
	tn.roster = tn.sign(2, tn.ids...)
	t.Cleanup(func() {
		for _, m := range tn.members {
			m.Close()
		}
	})
	return tn
}

// sign makes a roster of version v listing ids (ids[0] must be the primary).
func (tn *testNet) sign(v int64, ids ...*Identity) *Roster {
	tn.t.Helper()
	members := []RosterMember{}
	for i, id := range ids {
		kind := KindWorker
		if i == 0 {
			kind = KindPrimary
		}
		members = append(members, MemberFromIdentity(id, kind))
	}
	r, err := SignRoster(UnsignedRoster{
		Network: tn.ids[0].ID(), Version: v, IssuedAt: 1790000000000, Relay: testRelayURL,
		Primary: RosterPrimary{Ed25519: b64u(tn.ids[0].edPub)}, Members: members,
	}, tn.ids[0])
	if err != nil {
		tn.t.Fatal(err)
	}
	return r
}

func (tn *testNet) opts(i int, roster *Roster) MemberOptions {
	if roster == nil {
		roster = tn.roster
	}
	// The fake relay sends no liveness pings, and tests move the clock by minutes: the relay
	// silence rule is off except where a test turns it on.
	return MemberOptions{Identity: tn.ids[i], Roster: roster, clock: tn.clock, dial: tn.relay.dial,
		Timing: Timing{BackoffInitial: 100 * time.Millisecond, BackoffMax: time.Second}, liveness: -1}
}

// start connects member i and waits until it is registered.
func (tn *testNet) start(i int, mutate ...func(*MemberOptions)) *Member {
	tn.t.Helper()
	o := tn.opts(i, nil)
	for _, f := range mutate {
		f(&o)
	}
	var m *Member
	var err error
	if i == 0 {
		var p *Primary
		p, err = NewPrimary(o)
		if p != nil {
			m = p.Member
		}
	} else {
		m, err = NewMember(o)
	}
	if err != nil {
		tn.t.Fatal(err)
	}
	tn.members = append(tn.members, m)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.WaitConnected(ctx); err != nil {
		tn.t.Fatalf("member %d: %v", i, err)
	}
	return m
}

// eventually polls cond in real time; the members' goroutines run between polls.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func send(t *testing.T, m *Member, peer string, b []byte) error {
	t.Helper()
	select {
	case err := <-m.SendAsync(peer, b):
		return err
	case <-time.After(10 * time.Second):
		t.Fatalf("send to %s did not finish", peer)
		return nil
	}
}

func recv(t *testing.T, m *Member) InboundMessage {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	msg, err := m.Receive(ctx)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	return msg
}

// events records a member's events.
type eventLog struct {
	mu sync.Mutex
	ev []Event
}

func record(m *Member) *eventLog {
	l := &eventLog{}
	m.On(l.add)
	return l
}

func (l *eventLog) add(e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ev = append(l.ev, e)
}

func (l *eventLog) all() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Event(nil), l.ev...)
}

func (l *eventLog) states() []State {
	var out []State
	for _, e := range l.all() {
		if s, ok := e.(StateEvent); ok {
			out = append(out, s.State)
		}
	}
	return out
}

func (l *eventLog) codes() []int {
	var out []int
	for _, e := range l.all() {
		if d, ok := e.(DisconnectEvent); ok {
			out = append(out, d.Code)
		}
	}
	return out
}

func (l *eventLog) String() string { return fmt.Sprintf("%#v", l.all()) }

// locked runs f with the member's lock held, as the member's own code runs.
func locked(m *Member, f func()) {
	m.lock()
	defer m.unlock()
	f()
}
