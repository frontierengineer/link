package link

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

// The primary: the member that signs the roster. It opens pairing codes and runs the B side
// of pairing (section 5), revokes (section 8), accepts resignations (section 7.3), pushes
// every new roster to the relay and the members, and asks the relay for its usage figures
// (section 4.3: request-only, within the relay's budget).

const (
	// CodeLifetime is how long a pairing code admits a node by default.
	CodeLifetime = 15 * time.Minute
	// CodeAttempts failed confirmations burn a code.
	CodeAttempts = 5
	// PairingChannelTimeout is the relay's lifetime for a pairing channel.
	PairingChannelTimeout = 60 * time.Second
	resignSkew            = 5 * time.Minute
	// UsageBurst asks at once, then one per UsageInterval, per network: the relay's budget.
	UsageBurst    = 3
	UsageInterval = 10 * time.Second
)

// PairingCode is an open code.
type PairingCode struct {
	Code      string // display form, XXXX-XXXX
	CodeID    string // b64u of the 8-byte code id
	Kind      MemberKind
	Link      string // frontier://pair?... carrying network, code, code id and relay
	ExpiresAt time.Time
}

// PairingCodeOptions adjusts OpenPairingCode.
type PairingCodeOptions struct {
	Lifetime time.Duration // default CodeLifetime
	// Code chooses the code instead of a random one, in any spelling NormalizeCode accepts. A
	// chosen code is easier to say and easier to guess; like every code it burns after five
	// wrong confirmations.
	Code string
}

// UsageLimits are the relay's limits for the network.
type UsageLimits struct {
	RateBps        int64 `json:"rateBps"`
	QuotaBytesHour int64 `json:"quotaBytesHour"`
	TrickleBps     int64 `json:"trickleBps"`
}

// NetworkUsage is the relay's figures for the network.
type NetworkUsage struct {
	BytesHour   int64       `json:"bytesHour"`   // charged over the last hour, in five-minute steps
	Connections int64       `json:"connections"` // connected members
	Limits      UsageLimits `json:"limits"`
	QuotaUsed   float64     `json:"quotaUsed"` // bytesHour / quotaBytesHour; 0 without a quota
	Slowed      bool        `json:"slowed"`    // the trickle rate is in effect: send less
}

// UsageReport is the relay's answer to a usage ask (section 4.3). Per-member figures come from
// each member's Traffic.
type UsageReport struct {
	Network NetworkUsage `json:"network"`
}

type openCode struct {
	code      string
	codeID    string
	kind      MemberKind
	expiresAt time.Time // monotonic (Member.mono)
	failed    int
	inFlight  int
	claimed   bool
	burned    bool
	setups    bucket // pairing channels set up for it (setupRate, setupBurst)
}

// A code's pairing channels are set up (each costs key-exchange work, and pairEnd refunds its
// slot, so the five attempts alone would not bound them) at most 4 a second, bursts of 8.
const setupRate, setupBurst = 4, 8

type pairStage int

const (
	stageP1 pairStage = iota
	stageP3
	stageP5
	stageDone
)

type pairChannel struct {
	channel [16]byte
	key     string
	entry   *openCode
	ex      *primaryExchange
	stage   pairStage
	claimed bool
	timer   *mtimer
}

type usageResult struct {
	report UsageReport
	err    error
}

type primaryState struct {
	m        *Member
	codes    map[string]*openCode
	channels map[string]*pairChannel
	usage    map[string]chan usageResult
	refusals bucket                 // pairEnd refusals of pairings it cannot serve
	issued   map[string]*issuedCode // codes open, and the last closedCodes closed
	retries  map[string]*pushRetry  // roster pushes to try again, per member
	closed   []string               // closed code ids, oldest first
}

// issuedCode is what a refusal remembers of a code the primary issued.
type issuedCode struct {
	answered map[string]time.Time // the last pairEnd refusing it, per pairing channel
	told     map[string]time.Time // the last event per reason
}

// channelsPerCode bounds the pairing channels a code remembers its refusals on.
const channelsPerCode = 64

// answer says whether a refusal on channel gets a pairEnd: the first on each channel, then
// at most one a second there.
func (ic *issuedCode) answer(channel string, now time.Time) bool {
	if at, ok := ic.answered[channel]; ok && now.Sub(at) < time.Second {
		return false
	}
	if ic.answered == nil {
		ic.answered = map[string]time.Time{}
	}
	if len(ic.answered) >= channelsPerCode {
		// Those over a second old say nothing any more; failing that, forget any.
		for ch, at := range ic.answered {
			if now.Sub(at) >= time.Second {
				delete(ic.answered, ch)
			}
		}
		for ch := range ic.answered {
			if len(ic.answered) < channelsPerCode {
				break
			}
			delete(ic.answered, ch)
		}
	}
	ic.answered[channel] = now
	return true
}

// closedCodes: refusals name the last 1024 codes closed (section 5.2).
const closedCodes = 1024

// Primary is the member that signs the roster.
type Primary struct {
	*Member
}

// NewPrimary creates the primary and starts connecting; see also ConnectPrimary.
func NewPrimary(opts MemberOptions) (*Primary, error) {
	m, err := newMember(opts)
	if err != nil {
		return nil, err
	}
	if opts.Identity.ID() != opts.Roster.Network {
		return nil, invalidError("this identity is not the network primary")
	}
	m.prim = &primaryState{m: m, codes: map[string]*openCode{}, channels: map[string]*pairChannel{}, usage: map[string]chan usageResult{},
		issued: map[string]*issuedCode{}, retries: map[string]*pushRetry{}}
	m.start()
	return &Primary{Member: m}, nil
}

// ConnectPrimary creates the primary and returns once it is registered with the relay.
func ConnectPrimary(ctx context.Context, opts MemberOptions) (*Primary, error) {
	p, err := NewPrimary(opts)
	if err != nil {
		return nil, err
	}
	if err := p.WaitConnected(ctx); err != nil {
		p.Close()
		return nil, err
	}
	return p, nil
}

// placeholderMember is an entry of kind with every field at its fixed length, which
// measures the next roster before the newcomer's keys are known.
func placeholderMember(kind MemberKind) RosterMember {
	return RosterMember{ID: strings.Repeat("a", 26), Ed25519: strings.Repeat("A", 43), X25519: strings.Repeat("A", 43), Kind: kind}
}

// OpenPairingCode opens a code that admits one node of kind for 15 minutes. When no further
// member fits under the roster limit it fails with roster-full.
func (p *Primary) OpenPairingCode(kind MemberKind, opts PairingCodeOptions) (PairingCode, error) {
	m := p.Member
	m.lock()
	defer m.unlock()
	ps := m.prim
	if !slices.Contains(PairingKinds, kind) {
		return PairingCode{}, invalidError("kind must be one of worker, surface, mcp")
	}
	var chosen string
	if opts.Code != "" {
		c, err := NormalizeCode(opts.Code)
		if err != nil {
			return PairingCode{}, invalidError(err.Error())
		}
		chosen = c
	}
	// Every entry has the same shape, so a placeholder of this kind measures the next roster.
	size, err := ps.sizeWith(append(slices.Clone(m.roster.Members), placeholderMember(kind)))
	if err != nil {
		return PairingCode{}, err
	}
	if size > MaxRosterBytes {
		return PairingCode{}, rosterFullError(size)
	}
	ps.pruneCodes()
	code := chosen
	if code == "" {
		code = GenerateCode()
	}
	idBytes := make([]byte, codeIDLength)
	if _, err := rand.Read(idBytes); err != nil {
		return PairingCode{}, err
	}
	codeID := b64u(idBytes)
	lifetime := opts.Lifetime
	if lifetime <= 0 {
		lifetime = CodeLifetime
	}
	expires := m.clock.Now().Add(lifetime) // shown; the code expires on the monotonic clock
	link, err := BuildPairingLink(PairingLink{Network: m.roster.Network, Code: code, CodeID: codeID, Relay: m.roster.Relay})
	if err != nil {
		return PairingCode{}, err
	}
	ps.codes[codeID] = &openCode{code: code, codeID: codeID, kind: kind, expiresAt: m.mono().Add(lifetime)}
	ps.issued[codeID] = &issuedCode{told: map[string]time.Time{}}
	display, _ := FormatCode(code)
	return PairingCode{Code: display, CodeID: codeID, Kind: kind, Link: link, ExpiresAt: expires}, nil
}

// CancelPairingCode withdraws an open code.
func (p *Primary) CancelPairingCode(codeID string) {
	m := p.Member
	m.lock()
	defer m.unlock()
	if e := m.prim.codes[codeID]; e != nil {
		e.burned = true
	}
	m.prim.closeCode(codeID)
}

// Revoke removes a member and publishes the roster. It returns the new roster.
func (p *Primary) Revoke(nodeID string) (*Roster, error) {
	m := p.Member
	m.lock()
	defer m.unlock()
	if nodeID == m.identity.ID() {
		return nil, invalidError("the primary cannot revoke itself")
	}
	if m.roster.member(nodeID) == nil {
		return nil, invalidError(nodeID + " is not on the roster")
	}
	next, err := m.prim.nextRoster(withoutMember(m.roster.Members, nodeID))
	if err != nil {
		return nil, err
	}
	m.prim.publish(next, "")
	return next.Clone(), nil
}

func withoutMember(members []RosterMember, id string) []RosterMember {
	out := make([]RosterMember, 0, len(members))
	for _, x := range members {
		if x.ID != id {
			out = append(out, x)
		}
	}
	return out
}

// Usage asks the relay for this network's usage. The relay allows UsageBurst asks at once
// and then one per UsageInterval per network; beyond that it refuses, and Usage fails with
// rate-limited. Ask rarely, and keep the answer.
func (p *Primary) Usage(ctx context.Context) (UsageReport, error) {
	m := p.Member
	idBytes := make([]byte, 9)
	if _, err := rand.Read(idBytes); err != nil {
		return UsageReport{}, err
	}
	id := b64u(idBytes)
	timeout := m.sleep(m.timing.RequestTimeout)
	if err := m.waitOnline(ctx); err != nil {
		return UsageReport{}, err
	}
	done := make(chan usageResult, 1)
	m.lock()
	msg, _ := json.Marshal(map[string]string{"type": "usage", "id": id})
	if !m.relay.sendControl(msg) {
		m.unlock()
		return UsageReport{}, closedError("not connected to the relay")
	}
	m.prim.usage[id] = done
	m.unlock()
	select {
	case r := <-done:
		return r.report, r.err
	case <-timeout:
		m.lock()
		delete(m.prim.usage, id)
		m.unlock()
		return UsageReport{}, timeoutError("usage request")
	case <-ctx.Done():
		m.lock()
		delete(m.prim.usage, id)
		m.unlock()
		return UsageReport{}, ctx.Err()
	}
}

// usageFromTree reads the relay's usage figures, by their exact names (section 1: names match
// case included). A field missing reads as zero; one of the wrong type fails.
func usageFromTree(v any) (UsageReport, bool) {
	var r UsageReport
	n, ok := v.(map[string]any)
	if !ok {
		return r, false
	}
	num := func(m map[string]any, k string) (float64, bool) {
		x, present := m[k]
		if !present {
			return 0, true
		}
		j, isNum := x.(json.Number)
		if !isNum {
			return 0, false
		}
		f, err := j.Float64()
		return f, err == nil
	}
	ok = true
	get := func(m map[string]any, k string) int64 {
		f, good := num(m, k)
		ok = ok && good
		return int64(f)
	}
	r.Network.BytesHour = get(n, "bytesHour")
	r.Network.Connections = get(n, "connections")
	var good bool
	r.Network.QuotaUsed, good = num(n, "quotaUsed")
	ok = ok && good
	if x, present := n["slowed"]; present {
		r.Network.Slowed, good = x.(bool)
		ok = ok && good
	}
	if x, present := n["limits"]; present {
		l, isObj := x.(map[string]any)
		if !isObj {
			return r, false
		}
		r.Network.Limits = UsageLimits{RateBps: get(l, "rateBps"), QuotaBytesHour: get(l, "quotaBytesHour"), TrickleBps: get(l, "trickleBps")}
	}
	return r, ok
}

// ── Roster publication ──

// nextUnsigned is the next roster version with members.
func (ps *primaryState) nextUnsigned(members []RosterMember) UnsignedRoster {
	prev := ps.m.roster
	members = slices.Clone(members)
	slices.SortFunc(members, func(a, b RosterMember) int { return cmp.Compare(a.ID, b.ID) })
	return UnsignedRoster{
		Network:  prev.Network,
		Version:  prev.Version + 1,
		IssuedAt: max(ps.m.clock.Now().UnixMilli(), prev.IssuedAt),
		Relay:    prev.Relay,
		Primary:  prev.Primary,
		Members:  members,
	}
}

// sizeWith is the JCS size the next roster with members would have once signed.
func (ps *primaryState) sizeWith(members []RosterMember) (int, error) {
	r := &Roster{UnsignedRoster: ps.nextUnsigned(members), Signature: strings.Repeat("A", 86)}
	return r.Size()
}

// nextRoster signs the next roster version with members; over 65000 bytes it fails
// roster-full.
func (ps *primaryState) nextRoster(members []RosterMember) (*Roster, error) {
	size, err := ps.sizeWith(members)
	if err != nil {
		return nil, err
	}
	if size > MaxRosterBytes {
		return nil, rosterFullError(size)
	}
	return SignRoster(ps.nextUnsigned(members), ps.m.identity)
}

// A push of a new roster to a member that fails (the member unreachable, the handshake timed
// out, the connection lost) is tried again, 1 s after, doubling to 10 min, until it is handed
// over, the member leaves the roster, or a newer roster supersedes it.
const (
	pushRetryMin = time.Second
	pushRetryMax = 10 * time.Minute
)

type pushRetry struct {
	version int64
	wait    time.Duration
	timer   *mtimer
}

// pushed hears how a roster push to peer went.
func (ps *primaryState) pushed(peer string, version int64, err error) {
	m := ps.m
	r := ps.retries[peer]
	if err == nil || version < m.roster.Version || m.roster.member(peer) == nil {
		// Handed over, superseded, or the peer left: nothing more to try for this version, nor
		// for an older one, nor for a peer off the roster.
		if r != nil && (r.version <= version || r.version < m.roster.Version || m.roster.member(peer) == nil) {
			r.timer.cancel()
			delete(ps.retries, peer)
		}
		return
	}
	if r == nil || r.version != version {
		r = &pushRetry{version: version, wait: pushRetryMin}
		ps.retries[peer] = r
	} else {
		r.wait = min(2*r.wait, pushRetryMax)
	}
	if r.timer != nil && !r.timer.dead {
		return
	}
	r.timer = m.after(r.wait, func() {
		if ps.retries[peer] != r || m.roster.Version != r.version || m.roster.member(peer) == nil {
			if ps.retries[peer] == r {
				delete(ps.retries, peer)
			}
			return
		}
		m.sendRoster(peer)
	})
}

// publish adopts a roster this primary signed and pushes it to the relay and every member.
// except, when set, is a newcomer that has the roster already (sealed in P6) and is not
// connected yet: a push to it would fail and be retried into the middle of its first traffic
// (section 5.3).
func (ps *primaryState) publish(r *Roster, except string) {
	m := ps.m
	m.adoptRoster(r)
	rj, err := r.MarshalJSON()
	if err == nil {
		m.relay.sendControl(append(append([]byte(`{"type":"roster","roster":`), rj...), '}'))
	}
	for _, mem := range r.Members {
		if mem.ID != except {
			m.sendRoster(mem.ID)
		}
	}
}

func (ps *primaryState) onResign(from string, body []byte) {
	m := ps.m
	r, ok := parseResignation(body)
	if !ok || r.Node != from {
		return
	}
	now := m.clock.Now().UnixMilli()
	if d := now - r.TS; d > resignSkew.Milliseconds() || d < -resignSkew.Milliseconds() {
		return
	}
	member := m.roster.member(from)
	if member == nil || member.Kind == KindPrimary {
		return
	}
	pub, err := fromB64uLen(member.Ed25519, 32, "ed25519")
	if err != nil || !verifyResignation(r, m.roster.Network, pub) {
		return
	}
	next, err := ps.nextRoster(withoutMember(m.roster.Members, from))
	if err != nil {
		return
	}
	ps.publish(next, "")
}

// ── Relay control ──

// onControl handles what is the primary's; it reports false for anything else.
func (ps *primaryState) onControl(msg controlMessage) bool {
	switch msg.typ() {
	case "usage":
		done := ps.usage[msg.str("id")]
		if done == nil {
			return true
		}
		delete(ps.usage, msg.str("id"))
		report, ok := usageFromTree(msg["network"])
		if !ok {
			done <- usageResult{err: invalidError("the relay's usage answer is malformed")}
			return true
		}
		done <- usageResult{report: report}
		return true
	case "pairing":
		ps.onPairing(msg)
		return true
	case "pairEnd":
		if ch := msg.str("channel"); ch != "" {
			ps.endChannel(ch, FailNewcomerLeft, "the newcomer left", false)
		}
		return true
	case "error":
		done := ps.usage[msg.str("id")]
		if done == nil || msg.str("id") == "" {
			return false
		}
		delete(ps.usage, msg.str("id"))
		switch code := msg.str("code"); code {
		case "rate_limited":
			done <- usageResult{err: rateLimitedError("usage request")}
		case "forbidden":
			done <- usageResult{err: &Error{Code: CodeRefused, Message: "relay answered " + code}}
		default:
			done <- usageResult{err: &Error{Code: CodeInvalid, Message: "relay answered " + code}}
		}
		return true
	}
	return false
}

func (ps *primaryState) onConnectionState(s State) {
	if s == StateConnected {
		return
	}
	for key := range ps.channels {
		ps.endChannel(key, FailRelayLost, "the relay connection dropped", false)
	}
	for id, done := range ps.usage {
		done <- usageResult{err: closedError("relay connection lost")}
		delete(ps.usage, id)
	}
}

// ── Pairing, B side ──

func (ps *primaryState) pruneCodes() {
	now := ps.m.mono()
	for id, c := range ps.codes {
		if c.burned || !c.expiresAt.After(now) {
			ps.closeCode(id)
		}
	}
}

func (ps *primaryState) onPairing(msg controlMessage) {
	m := ps.m
	key, codeID := msg.str("channel"), msg.str("code")
	if key == "" || codeID == "" {
		return
	}
	chBytes, err := fromB64uLen(key, 16, "channel")
	if err != nil {
		return
	}
	// A refusal holds no state, and pairings for it can be streamed (section 5.2): by the
	// relay, and by a newcomer, who chooses the code id it asks for. For a code this primary
	// issued, the first refusal on each pairing channel is always answered, and repeats on that
	// channel at most once a second, apart from the budget for made-up ids, so that neither
	// those nor anyone else holding the code id can use up what an honest newcomer with a
	// mistyped or expired code is owed; its application hears of it at most once a second per
	// code and reason. A code id it never issued draws a pairEnd from one budget, and never
	// an event.
	refuse := func(code, reason string) {
		now := m.mono()
		ic := ps.issued[codeID]
		if ic == nil {
			if ps.refusals.take(now, refusalRate, refusalBurst) {
				m.relay.sendControl(pairEndMessage(key))
			}
			return
		}
		if ic.answer(key, now) {
			m.relay.sendControl(pairEndMessage(key))
		}
		if at, ok := ic.told[code]; ok && now.Sub(at) < time.Second {
			return
		}
		ic.told[code] = now
		m.emitDroppable(PairingFailedEvent{CodeID: codeID, Code: code, Reason: reason})
	}
	if ps.channels[key] != nil {
		return
	}
	entry := ps.codes[codeID]
	if entry == nil || entry.burned || !entry.expiresAt.After(m.mono()) {
		refuse(FailUnknownCode, "unknown or expired code")
		return
	}
	if entry.claimed {
		refuse(FailUsed, "code already used")
		return
	}
	// Reserve a slot atomically: attempts in flight plus failures never exceed five.
	if entry.failed+entry.inFlight >= CodeAttempts {
		refuse(FailNoAttempts, "no attempts left")
		return
	}
	if !entry.setups.take(m.mono(), setupRate, setupBurst) {
		refuse(FailNoAttempts, "too many attempts at once; try again")
		return
	}
	idBytes, err := fromB64uLen(entry.codeID, codeIDLength, "code id")
	if err != nil {
		return
	}
	ex, err := newPrimaryExchange(entry.code, idBytes, nil)
	if err != nil {
		refuse(FailMalformed, err.Error())
		return
	}
	entry.inFlight++
	ch := &pairChannel{key: key, entry: entry, ex: ex, stage: stageP1}
	copy(ch.channel[:], chBytes)
	ch.timer = m.after(PairingChannelTimeout, func() { ps.endChannel(key, FailTimeout, "pairing timed out", true) })
	ps.channels[key] = ch
}

// Refusals of pairings for code ids the primary never issued (made up by a relay, or by a
// newcomer) (section 5.2): 32 a second, bursts of 64.
const refusalRate, refusalBurst = 32, 64

// closeCode closes an open code; refusals go on naming it among the last closedCodes.
func (ps *primaryState) closeCode(codeID string) {
	if _, open := ps.codes[codeID]; !open {
		return
	}
	delete(ps.codes, codeID)
	ps.closed = append(ps.closed, codeID)
	for len(ps.closed) > closedCodes {
		old := ps.closed[0]
		ps.closed = ps.closed[1:]
		if _, open := ps.codes[old]; !open {
			delete(ps.issued, old)
		}
	}
}

func pairEndMessage(channel string) []byte {
	b, _ := json.Marshal(map[string]string{"type": "pairEnd", "channel": channel})
	return b
}

func (ps *primaryState) onPairFrame(channel [16]byte, body []byte) {
	ch := ps.channels[b64u(channel[:])]
	if ch == nil {
		return
	}
	var err error
	switch ch.stage {
	case stageP1:
		var pB []byte
		if pB, err = ch.ex.onP1(body); err == nil {
			ps.sendPair(ch, pB)
			ch.stage = stageP3
			return
		}
	case stageP3:
		var ok bool
		if ok, err = ch.ex.onP3(body); err == nil {
			if !ok {
				ps.failAttempt(ch, FailWrongCode, "wrong code")
				return
			}
			if ch.entry.claimed || ch.entry.burned {
				ps.endChannel(ch.key, FailUsed, "code already used", true)
				return
			}
			ch.entry.claimed = true
			ch.claimed = true
			var p4 []byte
			if p4, err = ch.ex.p4(); err == nil {
				ps.sendPair(ch, p4)
				ch.stage = stageP5
				return
			}
		}
	case stageP5:
		if err = ps.completePairing(ch, body); err == nil {
			return
		}
	default:
		return
	}
	// A malformed message counts as a failed attempt.
	ps.failAttempt(ch, FailMalformed, "malformed pairing message: "+err.Error())
}

func (ps *primaryState) completePairing(ch *pairChannel, body []byte) error {
	m := ps.m
	keys, err := ch.ex.onP5(body)
	if err != nil {
		return err
	}
	// Stricter than the TypeScript client: a key that is not a canonical encoding of a point
	// of large order could never sign for its node (or could be signed for by anyone).
	if !canonicalEd25519(keys.ed25519) || smallOrderEd25519(keys.ed25519) {
		return fmt.Errorf("the newcomer's ed25519 key is not usable")
	}
	id := NodeIDFromEd25519(keys.ed25519)
	if m.roster.member(id) != nil {
		ps.endChannel(ch.key, FailAlreadyMember, id+" is already a member", true)
		return nil
	}
	member := RosterMember{ID: id, Ed25519: b64u(keys.ed25519), X25519: b64u(keys.x25519), Kind: ch.entry.kind}
	next, err := ps.nextRoster(append(slices.Clone(m.roster.Members), member))
	if err != nil {
		if CodeOf(err) == CodeRosterFull {
			ps.endChannel(ch.key, FailRosterFull, err.Error(), true)
			return nil
		}
		return err
	}
	p6, err := ch.ex.p6(next)
	if err != nil {
		return err
	}
	ch.stage = stageDone
	ch.timer.cancel()
	delete(ps.channels, ch.key)
	ch.entry.inFlight--
	ch.entry.burned = true
	ps.closeCode(ch.entry.codeID)
	ps.sendPair(ch, p6)
	ps.publish(next, id)
	m.relay.sendControl(pairEndMessage(ch.key))
	m.emit(PairedEvent{Member: member, Roster: next.Clone()})
	return nil
}

func (ps *primaryState) sendPair(ch *pairChannel, body []byte) {
	if f, err := encodeFrame(framePair, ch.channel, body); err == nil {
		ps.m.relay.sendBinary(f)
	}
}

// failAttempt is a failed confirmation: the slot stays used; five burn the code.
func (ps *primaryState) failAttempt(ch *pairChannel, code, reason string) {
	ch.timer.cancel()
	delete(ps.channels, ch.key)
	ch.entry.inFlight--
	ch.entry.failed++
	if ch.claimed {
		ch.entry.claimed = false
	}
	if ch.entry.failed >= CodeAttempts {
		ch.entry.burned = true
		ps.closeCode(ch.entry.codeID)
	}
	ps.m.relay.sendControl(pairEndMessage(ch.key))
	ps.m.emitDroppable(PairingFailedEvent{CodeID: ch.entry.codeID, Code: code, Reason: reason})
}

// endChannel is a timeout or a dropped connection: the slot is refunded.
func (ps *primaryState) endChannel(key, code, reason string, tellRelay bool) {
	ch := ps.channels[key]
	if ch == nil {
		return
	}
	ch.timer.cancel()
	delete(ps.channels, key)
	ch.entry.inFlight--
	if ch.claimed {
		ch.entry.claimed = false
	}
	if tellRelay {
		ps.m.relay.sendControl(pairEndMessage(key))
	}
	// A channel ended with its slot refunded can be ended again at once, so its event goes at
	// most once a second per code and reason.
	if ic := ps.issued[ch.entry.codeID]; ic != nil {
		now := ps.m.mono()
		if at, ok := ic.told[code]; ok && now.Sub(at) < time.Second {
			return
		}
		ic.told[code] = now
	}
	ps.m.emitDroppable(PairingFailedEvent{CodeID: ch.entry.codeID, Code: code, Reason: reason})
}

// smallOrderEd25519 reports whether an encoding names one of the eight points of small
// order, whatever its sign bit (libsodium's list, which includes the non-canonical y = p and
// y = p + 1).
func smallOrderEd25519(b []byte) bool {
	for _, bad := range smallOrderPoints {
		diff := byte(0)
		for i := range 31 {
			diff |= b[i] ^ bad[i]
		}
		diff |= (b[31] & 0x7f) ^ bad[31]
		if diff == 0 {
			return true
		}
	}
	return false
}

var smallOrderPoints = [][]byte{
	mustHex("0000000000000000000000000000000000000000000000000000000000000000"), // y = 0, order 4
	mustHex("0100000000000000000000000000000000000000000000000000000000000000"), // y = 1, order 1
	mustHex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"), // order 8
	mustHex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"), // order 8
	mustHex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // y = p - 1, order 2
	mustHex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // y = p (0), order 4
	mustHex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // y = p + 1 (1), order 1
}
