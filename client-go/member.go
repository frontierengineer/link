package link

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"
	"unicode/utf8"
)

// A member of a network: one relay connection, sessions with the other members, the roster
// it holds, and the application's message stream.

// State is a member's connection state.
type State string

const (
	StateConnecting   State = "connecting"
	StateConnected    State = "connected"
	StateDisconnected State = "disconnected"
	StateRevoked      State = "revoked"  // terminal: 4008, or a roster that no longer lists this node
	StateReplaced     State = "replaced" // terminal: 4005, another copy of the identity connected
	StateClosed       State = "closed"   // terminal: Close was called
)

// Timing holds the protocol's timers. A zero field takes its default; tests shorten them.
type Timing struct {
	HandshakeTimeout time.Duration // per handshake message, and for a send to wait for the relay (10 s)
	RekeyInterval    time.Duration // the initiator rekeys after this long (10 min)...
	RekeyMessages    uint64        // ...or after this many messages in either direction (2^32)
	RetireGrace      time.Duration // a previous session's keys are kept this long after a rekey (30 s)
	Idle             time.Duration // a session with no frame either way this long is forgotten (10 min)
	BackoffInitial   time.Duration // first reconnect delay (500 ms), doubling...
	BackoffMax       time.Duration // ...to at most this (10 s)
	RequestTimeout   time.Duration // how long usage, roster sync and resign wait for an answer (10 s)
}

// DefaultTiming is the protocol's timing.
var DefaultTiming = Timing{
	HandshakeTimeout: 10 * time.Second,
	RekeyInterval:    10 * time.Minute,
	RekeyMessages:    1 << 32,
	RetireGrace:      30 * time.Second,
	Idle:             10 * time.Minute,
	BackoffInitial:   500 * time.Millisecond,
	BackoffMax:       10 * time.Second,
	RequestTimeout:   10 * time.Second,
}

func (t Timing) withDefaults() Timing {
	d := DefaultTiming
	set := func(v *time.Duration, def time.Duration) {
		if *v <= 0 {
			*v = def
		}
	}
	set(&t.HandshakeTimeout, d.HandshakeTimeout)
	set(&t.RekeyInterval, d.RekeyInterval)
	set(&t.RetireGrace, d.RetireGrace)
	set(&t.Idle, d.Idle)
	set(&t.BackoffInitial, d.BackoffInitial)
	set(&t.BackoffMax, d.BackoffMax)
	set(&t.RequestTimeout, d.RequestTimeout)
	if t.RekeyMessages == 0 {
		t.RekeyMessages = d.RekeyMessages
	}
	return t
}

// MemberOptions configures a member.
type MemberOptions struct {
	Identity *Identity // required
	Roster   *Roster   // required: the newest roster held
	// RelayURL defaults to the roster's relay. A roster whose network is not placed yet has none
	// (""): a member of it needs this, or it is not started (invalid).
	RelayURL string
	// PinnedNetworkKey is the network key pinned at pairing; it defaults to the roster's.
	PinnedNetworkKey string
	// NetworkSeed is the network seed, for the node meant to be the primary (section 3.1). It
	// must derive the roster's network key. A node started with it whose roster names another
	// member primary claims the primary once registered. The seed is the caller's to keep: this
	// package never stores, sends or deletes it.
	NetworkSeed []byte
	// CreditWindow is the receive window granted per session: 1 MiB (every session's
	// initial credit, the default) to 2^32 - 1, the excess granted as extra credit.
	CreditWindow int64
	Timing       Timing
	// ResolveRelay is called on close code 4009 and may return a new relay URL; "" or an
	// error keeps the current one.
	ResolveRelay func(ctx context.Context, network string) (string, error)
	// OnEvent, when set, is a listener installed before the member starts connecting, so it
	// sees every event from the first; On adds others later.
	OnEvent func(Event)

	clock    clock         // tests
	dial     socketDialer  // tests
	rng      io.Reader     // tests: fixes ephemeral keys and indices
	liveness time.Duration // tests: the relay silence that ends a connection; < 0 never
}

// InboundMessage is a whole message from a peer.
type InboundMessage struct {
	From  string
	Bytes []byte
}

type inboxItem struct {
	msg     InboundMessage
	release func()
}

// Member is a member of a network. Its methods are safe for concurrent use.
type Member struct {
	mu    sync.Mutex
	tasks []func() // run, in order, before the lock is released

	identity     *Identity
	roster       *Roster
	pinned       string
	timing       Timing
	clock        clock
	dialer       socketDialer
	creditWindow int64
	resolveRelay func(ctx context.Context, network string) (string, error)
	liveness     time.Duration

	relay *relayConn
	sess  *sessionManager
	prim  *primaryState // while this node is the primary: it holds the seed and the roster names it

	netKey   *NetworkKey // the network key, when this node was given the network seed
	claiming bool        // it was, and its roster named another primary: it claims once registered

	disp         dispatcher
	events       listeners[Event]
	arrivals     listeners[InboundMessage]
	handler      func(InboundMessage)
	handlerID    int
	inbox        []inboxItem
	inboxWake    chan struct{}
	stateWake    chan struct{}
	rosterWake   chan struct{}
	offline      []*outMsg // sends waiting for the relay connection
	rosterOut    map[string]*rosterOut
	relayErrors  bucket
	shaping      Shaping       // the relay's last shaping notice
	askedPrimary time.Time     // the last ask of the primary for its roster (monotonic)
	hintWait     time.Duration // the wait before the next
	hintAnswered bool          // a newer roster came since the last ask
	hintsSent    int
	hintTimer    *mtimer // a suppressed ask, due at the end of the wait
	lastStamp    uint64  // the stamp of the last handshake-init this node sent

	traffic trafficState
}

// NewMember creates a member and starts connecting; see also ConnectMember.
func NewMember(opts MemberOptions) (*Member, error) {
	m, err := newMember(opts)
	if err != nil {
		return nil, err
	}
	m.start()
	return m, nil
}

// ConnectMember creates a member and returns once it is registered with the relay.
func ConnectMember(ctx context.Context, opts MemberOptions) (*Member, error) {
	m, err := NewMember(opts)
	if err != nil {
		return nil, err
	}
	if err := m.WaitConnected(ctx); err != nil {
		m.Close()
		return nil, err
	}
	return m, nil
}

func newMember(opts MemberOptions) (*Member, error) {
	if opts.Identity == nil {
		return nil, invalidError("an identity is required")
	}
	if opts.Roster == nil || opts.Roster.Problem() != nil {
		return nil, invalidError("the roster is not valid")
	}
	if opts.Roster.member(opts.Identity.ID()) == nil {
		return nil, invalidError("this identity is not on the roster")
	}
	pinned := opts.PinnedNetworkKey
	if pinned == "" {
		pinned = opts.Roster.NetworkKey
	}
	if pinned != opts.Roster.NetworkKey {
		return nil, invalidError("the roster is not signed by the pinned network key")
	}
	var netKey *NetworkKey
	if opts.NetworkSeed != nil {
		k, err := NetworkKeyFromSeed(opts.NetworkSeed)
		if err != nil {
			return nil, err
		}
		if b64u(k.edPub) != opts.Roster.NetworkKey {
			return nil, invalidError("the network seed does not derive the roster's network key")
		}
		netKey = k
	}
	window := opts.CreditWindow
	if window == 0 {
		window = DefaultCreditWindow
	}
	if window < InitialCredit || window > 0xffffffff {
		return nil, invalidError("CreditWindow must be from 1 MiB to 2^32 - 1")
	}
	url := opts.RelayURL
	if url == "" {
		url = opts.Roster.Relay
	}
	if url == "" {
		// An unplaced network (section 3.2) has no relay to dial: a member of one is not started
		// unless it is given a relay URL itself.
		return nil, invalidError("the network has no relay yet: place it (PlaceNetwork), or give RelayURL")
	}
	if _, err := normalizeRelayURL(url); err != nil {
		return nil, invalidError(err.Error())
	}
	m := &Member{
		identity:     opts.Identity,
		roster:       opts.Roster.Clone(),
		pinned:       pinned,
		timing:       opts.Timing.withDefaults(),
		clock:        opts.clock,
		dialer:       opts.dial,
		creditWindow: window,
		resolveRelay: opts.ResolveRelay,
		liveness:     opts.liveness,
		netKey:       netKey,
		claiming:     netKey != nil && opts.Roster.PrimaryID() != opts.Identity.ID(),
		inboxWake:    make(chan struct{}),
		rosterOut:    map[string]*rosterOut{},
		stateWake:    make(chan struct{}),
		rosterWake:   make(chan struct{}),
	}
	if m.clock == nil {
		m.clock = realClock{}
	}
	m.disp.dropBeyond = maxDroppableBacklog
	if m.dialer == nil {
		m.dialer = dialWebSocket
	}
	m.relay = &relayConn{m: m, url: url, state: StateDisconnected, backoff: m.timing.BackoffInitial}
	m.sess = newSessionManager(m)
	if opts.rng != nil {
		m.sess.rng = opts.rng
	}
	m.traffic.reset(m.clock.Now())
	if opts.OnEvent != nil {
		m.events.add(opts.OnEvent)
	}
	return m, nil
}

func (m *Member) start() {
	m.lock()
	defer m.unlock()
	m.sess.startSweep()
	m.syncRole()
	m.relay.start()
}

// ── The lock, tasks, timers and events ──

func (m *Member) lock() { m.mu.Lock() }

// unlock runs the tasks queued while the lock was held, then releases it. Tasks play the
// part of the TypeScript client's microtasks: work that must not run in the middle of the
// step that queued it.
func (m *Member) unlock() {
	for len(m.tasks) > 0 {
		t := m.tasks[0]
		m.tasks[0] = nil
		m.tasks = m.tasks[1:]
		t()
	}
	m.mu.Unlock()
}

func (m *Member) later(f func()) { m.tasks = append(m.tasks, f) }

// mtimer is a timer whose callback runs under the member's lock, never after cancel.
type mtimer struct {
	stop func() bool
	dead bool
}

func (m *Member) after(d time.Duration, f func()) *mtimer {
	t := &mtimer{}
	t.stop = m.clock.AfterFunc(d, func() {
		m.lock()
		defer m.unlock()
		if !t.dead {
			t.dead = true
			f()
		}
	})
	return t
}

func (t *mtimer) cancel() {
	if t != nil && !t.dead {
		t.dead = true
		t.stop()
	}
}

// sleep returns a channel closed after d on the member's clock.
func (m *Member) sleep(d time.Duration) <-chan struct{} {
	ch := make(chan struct{})
	m.clock.AfterFunc(d, func() { close(ch) })
	return ch
}

func (m *Member) emit(e Event) {
	for _, l := range m.events.snapshot() {
		m.disp.push(func() { l(e) })
	}
}

// emitDroppable raises an event the relay can cause at will (a relay error, a failed
// pairing): beyond a backlog of maxDroppableBacklog it is dropped rather than queued.
func (m *Member) emitDroppable(e Event) {
	for _, l := range m.events.snapshot() {
		m.disp.pushDroppable(func() { l(e) })
	}
}

// On adds a listener for every event the member raises and returns a function that removes
// it. Listeners run one at a time, in order, on a goroutine of the member's.
func (m *Member) On(listener func(Event)) (remove func()) {
	m.lock()
	defer m.unlock()
	id := m.events.add(listener)
	return func() {
		m.lock()
		defer m.unlock()
		m.events.remove(id)
	}
}

// Settle returns once every event raised before the call, and every message handed to an
// OnMessage handler or OnArrival listener before it, has been delivered. It must not be
// called from a listener.
func (m *Member) Settle() {
	done := make(chan struct{})
	m.disp.push(func() { close(done) })
	<-done
}

func wake(ch *chan struct{}) {
	close(*ch)
	*ch = make(chan struct{})
}

// ── Accessors ──

// ID is this member's node id.
func (m *Member) ID() string { return m.identity.ID() }

// Identity is this member's identity.
func (m *Member) Identity() *Identity { return m.identity }

// Network is the network id.
func (m *Member) Network() string {
	m.lock()
	defer m.unlock()
	return m.roster.Network
}

// Roster returns a copy of the newest roster held.
func (m *Member) Roster() *Roster {
	m.lock()
	defer m.unlock()
	return m.roster.Clone()
}

// State is the connection state.
func (m *Member) State() State {
	m.lock()
	defer m.unlock()
	return m.relay.state
}

// Shaping is how the relay shapes this network (section 9), from its last shaping notice:
// the rate in force and whether the network is slowed. A ShapingEvent says when it changes,
// so there is no need to poll Usage for it.
type Shaping struct {
	// RateBps is the rate in force, bytes a second: the network's rate, or its trickle rate
	// once its quota is spent; 0 for none. Sends are paced to it (section 11).
	RateBps int64 `json:"rateBps"`
	// Slowed: the quota is spent and the trickle rate is in force. Send less (drop video,
	// keep audio).
	Slowed bool `json:"slowed"`
}

// Shaping is the relay's last shaping notice; unshaped before any.
func (m *Member) Shaping() Shaping {
	m.lock()
	defer m.unlock()
	return m.shaping
}

// RelayURL is the relay this member dials.
func (m *Member) RelayURL() string {
	m.lock()
	defer m.unlock()
	return m.relay.url
}

// Sessions describes the live sessions with a peer, or with every peer for "", for tests and
// diagnostics. A handshake in progress is not listed.
func (m *Member) Sessions(peer string) []SessionInfo {
	m.lock()
	defer m.unlock()
	return m.sess.sessionInfo(peer)
}

func terminalError(s State) error {
	switch s {
	case StateRevoked:
		return revokedError()
	case StateReplaced:
		return replacedError()
	case StateClosed:
		return closedError("")
	}
	return nil
}

// WaitConnected returns once registered with the relay, or with the terminal state's error
// (revoked, replaced, closed), or ctx's.
func (m *Member) WaitConnected(ctx context.Context) error {
	for {
		m.lock()
		s, w := m.relay.state, m.stateWake
		m.unlock()
		if s == StateConnected {
			return nil
		}
		if err := terminalError(s); err != nil {
			return err
		}
		select {
		case <-w:
		case <-ctx.Done():
			return timeoutOr(ctx.Err(), "connecting to the relay")
		}
	}
}

// timeoutOr turns a context deadline into the package's timeout error.
func timeoutOr(err error, what string) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return timeoutError(what)
	}
	return err
}

// waitOnline is the TypeScript client's online(): a terminal state fails at once, and a
// member that is not connected waits up to the handshake timeout for the relay.
func (m *Member) waitOnline(ctx context.Context) error {
	limit := m.sleep(m.timing.HandshakeTimeout)
	for {
		m.lock()
		s, w := m.relay.state, m.stateWake
		m.unlock()
		if s == StateConnected {
			return nil
		}
		if err := terminalError(s); err != nil {
			return err
		}
		select {
		case <-w:
		case <-limit:
			return timeoutError("connecting to the relay")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// dial opens a socket to the relay at its normalised URL, so the Host header the relay
// checks the signature against is the origin the member signed.
func (m *Member) dial(ctx context.Context, raw string) (socket, error) {
	u, err := normalizeRelayURL(raw)
	if err != nil {
		return nil, err
	}
	return m.dialer(ctx, u.String())
}

// ── Sending ──

// SendAsync starts sending one message to a member and returns a channel that receives the
// result: nil once every fragment is handed to the relay connection, else an *Error
// (unreachable, refused, revoked, replaced, timeout, closed, invalid). Messages to one peer
// go in call order. Delivery is at most once. The caller must not modify b until the
// result arrives.
func (m *Member) SendAsync(peer string, b []byte) <-chan error {
	o := &outMsg{peer: peer, bytes: b, done: make(chan error, 1)}
	m.lock()
	defer m.unlock()
	m.online(o)
	return o.done
}

// Send sends one message (up to 64 MiB) to a member and returns once every fragment is
// handed to the relay connection; see SendAsync. ctx withdraws a message only before its
// first fragment goes out: after that it is sent whole, or fails with its session, since a
// message is never cut short on the wire.
func (m *Member) Send(ctx context.Context, peer string, b []byte) error {
	o := &outMsg{peer: peer, bytes: b, done: make(chan error, 1)}
	m.lock()
	m.online(o)
	m.unlock()
	select {
	case err := <-o.done:
		return err
	case <-ctx.Done():
	}
	m.lock()
	if !o.started && !o.finished {
		m.withdraw(o, timeoutOr(ctx.Err(), "send"))
	}
	m.unlock()
	return <-o.done
}

func (m *Member) online(o *outMsg) {
	if err := terminalError(m.relay.state); err != nil {
		o.finished = true
		o.done <- err
		return
	}
	if m.relay.state == StateConnected {
		m.admit(o)
		return
	}
	m.offline = append(m.offline, o)
	o.timer = m.after(m.timing.HandshakeTimeout, func() {
		m.dropOffline(o)
		o.finished = true
		o.done <- timeoutError("connecting to the relay")
	})
}

func (m *Member) dropOffline(o *outMsg) {
	for i, x := range m.offline {
		if x == o {
			m.offline = append(m.offline[:i:i], m.offline[i+1:]...)
			return
		}
	}
}

func (m *Member) withdraw(o *outMsg, err error) {
	for _, x := range m.offline {
		if x == o {
			m.dropOffline(o)
			o.timer.cancel()
			o.finished = true
			o.done <- err
			return
		}
	}
	m.sess.finishOut(o, err)
}

// admit checks a message once online, as the TypeScript client's sessions.send does, and
// queues it for its peer.
func (m *Member) admit(o *outMsg) {
	fail := func(err error) {
		o.finished = true
		o.done <- err
	}
	switch {
	case m.sess.closed:
		fail(closedError(""))
	case len(o.bytes) > MaxMessage:
		fail(invalidError("message exceeds 64 MiB"))
	case o.peer == m.identity.ID():
		fail(invalidError("cannot send to self"))
	case m.roster.member(o.peer) == nil:
		fail(invalidError(o.peer + " is not on the roster"))
	default:
		m.sess.enqueue(o)
	}
}

// sendFrame hands a routed frame to the relay; false when not connected. Control goes as
// 0x08 only to a relay that lists the control feature, otherwise as 0x03 (section 6).
func (m *Member) sendFrame(typ byte, peer string, body []byte) bool {
	if typ == frameControl && !m.relay.features["control"] {
		typ = frameData
	}
	id, err := nodeIDToBytes(peer)
	if err != nil {
		return false
	}
	f, err := encodeFrame(typ, id, body)
	if err != nil || !m.relay.sendBinary(f) {
		return false
	}
	m.traffic.frame(m, true, peer, len(f))
	return true
}

// ── Receiving ──

// deliver hands a complete message to the application; release credits it back.
func (m *Member) deliver(from string, b []byte, release func()) {
	msg := InboundMessage{From: from, Bytes: b}
	m.traffic.message(m, false, from, len(b))
	for _, l := range m.arrivals.snapshot() {
		m.disp.push(func() { l(msg) })
	}
	if h := m.handler; h != nil {
		m.disp.push(m.handled(h, msg, release))
		return
	}
	m.inbox = append(m.inbox, inboxItem{msg: msg, release: release})
	wake(&m.inboxWake)
}

// Receive takes the next message, waiting for one. Taking a message is what credits it back
// to its sender, so a slow reader slows its senders. It fails once the member reaches a
// terminal state and nothing is left to take.
func (m *Member) Receive(ctx context.Context) (InboundMessage, error) {
	for {
		m.lock()
		if len(m.inbox) > 0 {
			item := m.inbox[0]
			m.inbox[0] = inboxItem{}
			m.inbox = m.inbox[1:]
			item.release()
			m.unlock()
			return item.msg, nil
		}
		if err := terminalError(m.relay.state); err != nil {
			m.unlock()
			return InboundMessage{}, err
		}
		w := m.inboxWake
		m.unlock()
		select {
		case <-w:
		case <-ctx.Done():
			return InboundMessage{}, ctx.Err()
		}
	}
}

// Pending is the number of messages waiting to be taken.
func (m *Member) Pending() int {
	m.lock()
	defer m.unlock()
	return len(m.inbox)
}

// OnMessage takes every message as it arrives (and those already waiting) and hands it to
// handler, one at a time, in order; each is credited back to its sender once handler
// returns. It returns a function that removes the handler.
func (m *Member) OnMessage(handler func(InboundMessage)) (remove func()) {
	m.lock()
	defer m.unlock()
	m.handler = handler
	m.handlerID++
	id := m.handlerID
	for _, item := range m.inbox {
		m.disp.push(m.handled(handler, item.msg, item.release))
	}
	m.inbox = nil
	return func() {
		m.lock()
		defer m.unlock()
		if m.handlerID == id {
			m.handler = nil
		}
	}
}

// handled runs a message handler, then credits the message back: credit returns only as fast
// as the handler takes messages, so a slow handler slows its senders instead of letting
// messages pile up in front of it.
func (m *Member) handled(h func(InboundMessage), msg InboundMessage, release func()) func() {
	return func() {
		defer func() {
			m.lock()
			release()
			m.unlock()
		}()
		h(msg)
	}
}

// OnArrival calls listener for every message as it arrives, before the application takes
// it; it does not take the message. Listeners must not modify the bytes.
func (m *Member) OnArrival(listener func(InboundMessage)) (remove func()) {
	m.lock()
	defer m.unlock()
	id := m.arrivals.add(listener)
	return func() {
		m.lock()
		defer m.unlock()
		m.arrivals.remove(id)
	}
}

// ── Rosters ──

// SyncRoster asks the primary for its newest roster and reports whether a newer one was
// accepted. The request is repeated until answered, since delivery is at most once.
func (m *Member) SyncRoster(ctx context.Context) (bool, error) {
	if m.ID() == m.Roster().PrimaryID() {
		return false, nil
	}
	if err := m.waitOnline(ctx); err != nil {
		return false, err
	}
	m.lock()
	before, got := m.roster.Version, m.rosterWake
	m.unlock()
	deadline := m.sleep(m.timing.RequestTimeout)
	retry := max(50*time.Millisecond, m.timing.RequestTimeout/4)
	for {
		m.lock()
		if primary := m.roster.PrimaryID(); primary != m.identity.ID() {
			m.sess.sendControl(primary, sessionMessage{typ: sessRosterRequest}, func(error) {})
		}
		m.unlock()
		select {
		case <-got:
			m.lock()
			newer := m.roster.Version > before
			m.unlock()
			return newer, nil
		case <-deadline:
			return false, timeoutError("roster request")
		case <-ctx.Done():
			return false, ctx.Err()
		case <-m.sleep(retry):
		}
	}
}

// Resign leaves the network: it sends a signed resignation to the primary and returns once
// the relay has closed this member (state revoked).
func (m *Member) Resign(ctx context.Context) error {
	m.lock()
	held, primary := m.netKey != nil, m.roster.PrimaryID() == m.identity.ID()
	m.unlock()
	if primary {
		return invalidError("the primary cannot resign")
	}
	if held {
		return invalidError("a node holding the network seed cannot resign")
	}
	if err := m.waitOnline(ctx); err != nil {
		return err
	}
	m.lock()
	r := signResignation(m.identity, m.roster.Network, m.clock.Now().UnixMilli())
	m.unlock()
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	deadline := m.sleep(m.timing.RequestTimeout)
	retry := max(50*time.Millisecond, m.timing.RequestTimeout/4)
	sending := true
	for {
		m.lock()
		s, w := m.relay.state, m.stateWake
		if s == StateRevoked {
			m.unlock()
			return nil
		}
		if sending && s == StateConnected {
			m.sess.sendControl(m.roster.PrimaryID(), sessionMessage{typ: sessResign, bytes: body}, func(error) {})
		} else {
			// Repeated only while connected, as the TypeScript client does; then it waits.
			sending = false
		}
		m.unlock()
		var tick <-chan struct{}
		if sending {
			tick = m.sleep(retry)
		}
		select {
		case <-w:
		case <-tick:
		case <-deadline:
			return timeoutError("resigning")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (m *Member) onSessionControl(from string, msg sessionMessage) {
	switch msg.typ {
	case sessRosterRequest:
		m.sendRoster(from)
	case sessRoster:
		if tree, err := parseJSON(msg.bytes); err == nil {
			if r, err := rosterFromTree(tree); err == nil {
				m.offerRoster(r)
			}
		}
		wake(&m.rosterWake)
	case sessResign:
		if m.prim != nil {
			m.prim.onResign(from, msg.bytes)
		}
	}
}

// offerRoster applies section 3's acceptance rule and reports whether the roster was taken.
func (m *Member) offerRoster(r *Roster) bool {
	if AcceptanceProblem(r, m.pinned, m.roster.Version) != nil {
		return false
	}
	m.adoptRoster(r)
	return true
}

func (m *Member) adoptRoster(r *Roster) {
	m.sess.rosterAdded(m.roster, r)
	m.roster = r.Clone()
	m.hintWait, m.hintAnswered = hintWaitMin, true
	m.hintTimer.cancel() // a newer roster came: a deferred ask has nothing left to ask for
	m.hintTimer = nil
	for id, st := range m.rosterOut {
		if m.roster.member(id) == nil {
			st.timer.cancel()
			delete(m.rosterOut, id)
		}
	}
	m.sess.rosterChanged()
	m.emit(RosterEvent{Roster: r.Clone()})
	m.syncRole()
	if m.roster.member(m.identity.ID()) == nil {
		m.relay.revoke()
	}
}

// onPeerVersion spreads rosters member to member (section 7.1). A peer holding a newer roster
// is asked for it: any member answers with the newest it holds, and a roster is taken only
// if the pinned network key signed it, so the peer need not be trusted. A peer that is behind,
// and still on this member's roster, is handed this one.
func (m *Member) onPeerVersion(from string, version uint64) {
	mine := uint64(m.roster.Version)
	switch {
	case version > mine:
		// The primary is the fallback, for a peer this member cannot open a session to.
		m.sess.sendControl(from, sessionMessage{typ: sessRosterRequest}, func(err error) {
			if err != nil {
				m.askPrimary()
			}
		})
	case version < mine && from != m.identity.ID() && m.roster.member(from) != nil:
		m.sendRoster(from)
	}
}

// maxRelayErrorField: a relay error's fields reach the application cut to 1 KiB.
const maxRelayErrorField = 1024

// cut shortens s to at most maxRelayErrorField bytes, at a UTF-8 boundary.
func cut(s string) string {
	if len(s) <= maxRelayErrorField {
		return s
	}
	n := maxRelayErrorField
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// nextStamp is the stamp of a new handshake-init (section 7.1): Unix milliseconds on the
// wall clock, so that it survives a restart, and always greater than the last this node sent,
// so that two inits in one millisecond, or a wall clock stepped back, still increase.
func (m *Member) nextStamp() uint64 {
	m.lastStamp = nextStampAfter(m.clock.Now().UnixMilli(), m.lastStamp)
	return m.lastStamp
}

// nextStampAfter is max(wallNowMs, lastStamp + 1).
func nextStampAfter(wallNowMs int64, lastStamp uint64) uint64 {
	if wallNowMs > 0 && uint64(wallNowMs) > lastStamp+1 {
		return uint64(wallNowMs)
	}
	return lastStamp + 1
}

// Relay errors reach the application 16 a second, in bursts of 64.
const relayErrorRate, relayErrorBurst = 16, 64

// rosterGap is the least time between two rosters sent to one peer.
const rosterGap = 250 * time.Millisecond

// rosterOut is what was last sent of the roster to one peer.
type rosterOut struct {
	last     time.Time
	timer    *mtimer // a coalesced send is due
	inflight bool    // a send waits for a session
	again    bool    // and another was asked for meanwhile
	ch       *channel
	end      int64 // where the last one sent ends in ch's queue
	version  int64
}

// sendRoster sends this member's roster to a peer: as a reply to roster-request, to a peer
// whose handshake showed an older one, and for the primary's publication. Each is a whole
// roster (up to 65000 bytes) that the peer, or a relay replaying its handshakes, could ask
// for at will, so per peer: at most one each rosterGap, those asked for in between coalesced
// into one, and none while one of this version or newer still waits to be written.
func (m *Member) sendRoster(peer string) {
	if peer == m.identity.ID() || m.roster.member(peer) == nil {
		return
	}
	st := m.rosterOut[peer]
	if st == nil {
		st = &rosterOut{}
		m.rosterOut[peer] = st
	}
	switch {
	case st.timer != nil:
		return
	case st.inflight:
		st.again = true
		return
	case st.ch != nil && st.ch == m.relay.ch && st.version >= m.roster.Version && st.ch.unsent(st.end):
		return
	}
	now := m.mono()
	if wait := st.last.Add(rosterGap).Sub(now); !st.last.IsZero() && wait > 0 {
		st.timer = m.after(wait, func() {
			st.timer = nil
			m.sendRoster(peer)
		})
		return
	}
	j, err := m.roster.JCS()
	if err != nil {
		return
	}
	st.last, st.inflight = now, true
	version := m.roster.Version
	m.sess.sendControl(peer, sessionMessage{typ: sessRoster, bytes: j}, func(err error) {
		st.inflight = false
		if err == nil && m.relay.ch != nil {
			st.ch, st.end, st.version = m.relay.ch, m.relay.ch.queuedEnd(), version
		}
		if m.prim != nil {
			m.prim.pushed(peer, version, err)
		}
		if st.again {
			st.again = false
			m.sendRoster(peer)
		}
	})
}

func (m *Member) askPrimary() {
	primary := m.roster.PrimaryID()
	if m.identity.ID() == primary {
		return
	}
	// A handshake from anyone claiming a newer roster leads here, and the relay can provoke
	// that at every member at once, each ask drawing a whole roster from the primary. So the
	// asks back off: one a second at first, and after an ask that brought no newer roster
	// twice the wait before the next, up to 5 minutes; a newer roster starts it over.
	now := m.mono()
	wait := m.hintWait
	if wait == 0 {
		wait = hintWaitMin
	}
	if !m.askedPrimary.IsZero() && !m.hintAnswered {
		wait = min(2*wait, hintWaitMax)
	}
	if !m.askedPrimary.IsZero() && now.Sub(m.askedPrimary) < wait {
		// Deferred, not dropped: one coalesced ask at the end of the wait, or a member that
		// learnt of a newer roster only here would stay on its old one.
		if m.hintTimer == nil {
			m.hintTimer = m.after(m.askedPrimary.Add(wait).Sub(now), func() {
				m.hintTimer = nil
				m.askPrimary()
			})
		}
		return
	}
	m.hintTimer.cancel()
	m.hintTimer = nil
	m.askedPrimary, m.hintWait, m.hintAnswered = now, wait, false
	m.hintsSent++
	m.sess.sendControl(primary, sessionMessage{typ: sessRosterRequest}, func(error) {})
}

// The roster hint's wait between asks of the primary: from a second, doubling while asks bring
// nothing newer, up to 5 minutes.
const (
	hintWaitMin = time.Second
	hintWaitMax = 5 * time.Minute
)

// ── Relay events ──

func (m *Member) onRelayState(s State) {
	if s != StateConnected {
		var err *Error
		switch s {
		case StateRevoked:
			err = revokedError()
		case StateReplaced:
			err = replacedError()
		case StateClosed:
			err = closedError("")
		default:
			err = closedError("relay connection lost")
		}
		m.sess.dropAll(err)
	}
	if m.relay.terminal() {
		m.sess.close()
		waiting := m.offline
		m.offline = nil
		for _, o := range waiting {
			o.timer.cancel()
			o.finished = true
			o.done <- terminalError(s)
		}
		wake(&m.inboxWake)
	}
	if m.prim != nil {
		m.prim.onConnectionState(s)
	}
	m.emit(StateEvent{State: s})
	wake(&m.stateWake)
	if s == StateConnected && m.claiming {
		// Section 3.1: claimed once, at the first registration, never on later rosters.
		m.claiming = false
		m.later(m.claim)
	}
	if s == StateConnected && len(m.offline) > 0 {
		m.later(func() {
			waiting := m.offline
			m.offline = nil
			for _, o := range waiting {
				o.timer.cancel()
				if !o.finished {
					m.admit(o)
				}
			}
		})
	}
}

func (m *Member) onRegistered(msg controlMessage) {
	// A relay without the feature never says: the network is taken as unshaped there.
	if !m.relay.features["shaping"] {
		m.setShaping(Shaping{})
	}
	if raw, ok := msg["roster"]; ok {
		// Section 4.1: the relay returns its newer roster when this member presented an older
		// one.
		if r, err := rosterFromTree(raw); err == nil {
			m.offerRoster(r)
		}
		return
	}
	// A relay that keeps only a compact record of a newer roster says so without sending it;
	// the primary, or the first up-to-date peer met (onPeerVersion), hands it over.
	if v, ok := safeInteger(msg["rosterVersion"]); ok && v > m.roster.Version {
		m.later(m.askPrimary)
	}
}

func (m *Member) onControl(msg controlMessage) {
	if msg.typ() == "shaping" {
		rate, ok := safeInteger(msg["rateBps"])
		slowed, isBool := msg["slowed"].(bool)
		if ok && isBool {
			m.setShaping(Shaping{RateBps: rate, Slowed: slowed})
		}
		return
	}
	if m.prim != nil && m.prim.onControl(msg) {
		return
	}
	if msg.typ() == "error" {
		e := RelayErrorEvent{Message: msg.str("message"), ID: msg.str("id")}
		e.Code = msg.str("code")
		if e.Code == "" {
			if c, ok := msg["code"]; ok {
				b, _ := json.Marshal(c)
				e.Code = string(b)
			}
		}
		// Each field is cut to 1 KiB: the relay chooses them.
		e.Code, e.Message, e.ID = cut(e.Code), cut(e.Message), cut(e.ID)
		// The relay may send any number of these: 16 a second reach the application, in
		// bursts of 64 (section 11).
		if m.relayErrors.take(m.mono(), relayErrorRate, relayErrorBurst) {
			m.emitDroppable(e)
		}
	}
}

// setShaping paces sends to the rate in force and raises a ShapingEvent when it changed. The
// relay can change it at will, so the event is droppable.
func (m *Member) setShaping(s Shaping) {
	m.sess.setRate(s.RateBps)
	if s == m.shaping {
		return
	}
	m.shaping = s
	m.emitDroppable(ShapingEvent{Shaping: s})
}

func (m *Member) onBinary(data []byte) {
	f, err := decodeFrame(data)
	if err != nil {
		return
	}
	if f.typ == framePair {
		if m.prim != nil {
			m.prim.onPairFrame(f.peer, f.body)
		}
		return
	}
	from := nodeIDFromBytes(f.peer[:])
	m.traffic.frame(m, false, from, len(data))
	m.sess.handleFrame(f, from)
}

// Close closes the member for good: the relay connection and every session.
func (m *Member) Close() {
	m.lock()
	defer m.unlock()
	if m.relay.state == StateClosed {
		return
	}
	m.relay.close()
	m.sess.close()
	// A deferred roster hint would hold the member for up to 5 minutes, to no purpose.
	m.hintTimer.cancel()
	m.hintTimer = nil
}
