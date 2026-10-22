package link

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/flynn/noise"
)

// Sessions (section 7): Noise IK handshakes keyed by roster x25519 keys, transport with
// receiver indices, rekeying, idle expiry, and the session message layer (fragmentation and
// credit flow control). A port of the TypeScript client's sessions.ts; every method runs with
// the member's lock held.
//
// Two lanes share the relay socket. Control (handshakes, refused, reset and session messages
// other than message) is encrypted and handed over at once. Message fragments wait in a gate
// until the socket is short, the session's un-credited bytes are within its window, credit
// allows, and, while the relay shapes the network (section 11, pacing), the connection's pace
// allows; only then is a fragment encrypted, in the same step that hands it to the socket.
// Wire order is therefore nonce order, and control can pass queued data without breaking
// Noise's implicit counter. Paced at the rate the relay reads, little lies in the socket in
// front of control, so control arrives quickly however much data waits.
//
// Credit and reassembly belong to one Noise session, and a message is never split across two
// sessions: a rekey switches at a message boundary, and a retired session lives past its
// grace while a message still uses it.
//
// Every byte from a peer is hostile, so beyond the TypeScript client this side also enforces
// the credit it granted (a peer that sends message bytes beyond it ends the session), bounds
// the sessions it keeps per peer, and bounds what a peer may leave buffered (partial
// messages and messages the application has not taken) across all its sessions.

const (
	// MaxMessage is the largest application message: 64 MiB.
	MaxMessage = 64 * 1024 * 1024
	// maxPlaintext: a Noise message is at most 65535 bytes, 16 of them the tag (section 7.2).
	maxNoiseMessage = 65535
	maxPlaintext    = maxNoiseMessage - 16
	maxFragment     = maxPlaintext - 2
	// InitialCredit is the credit every session starts with, in each direction (section 7.3).
	InitialCredit = 1024 * 1024
	// DefaultCreditWindow is the receive window granted per session by default.
	DefaultCreditWindow = InitialCredit
	// CreditBatchBytes: owed credit is returned at once from this much...
	CreditBatchBytes = 65536
	// CreditDelay: ...and otherwise this long after it began to be owed.
	CreditDelay = 250 * time.Millisecond
	// PaceFloorBytes: a session may have at least this many message bytes un-credited, or one
	// and a half times what was credited back over the last second if more.
	PaceFloorBytes = 65536
	// paceMinFragment is the smallest fragment the pace cuts a message into.
	paceMinFragment = 16384
	// PaceShareNum/PaceShareDen: while the relay shapes the network at R bytes a second (its
	// shaping notice), fragments go at most at 7/8 of R, each counted at its frame's size; the
	// eighth left is for credit, handshakes, the peers' own frames and WebSocket headers
	// (section 11).
	PaceShareNum, PaceShareDen = 7, 8
	// fragmentFrameOverhead is what a frame carrying a fragment adds to its message bytes: the
	// routed header, the receiver index, the session message's two bytes and the tag.
	fragmentFrameOverhead = 40
	// pacedMinFragment: a paced fragment carries at most a quarter of a second of the pace, and
	// at least this.
	pacedMinFragment = 1024

	// maxSessionsPerPeer bounds the sessions kept with one peer: the current one and those
	// retired by rekeys still finishing a message (section 7.3). Beyond it the oldest that is
	// not current is ended.
	maxSessionsPerPeer = 8
)

// Bounds on what one peer may leave buffered here (variables so tests can lower them).
var (
	// maxHeldMessagesPerPeer bounds complete messages from one peer that the application has
	// not taken; a peer that sends more has its session ended.
	maxHeldMessagesPerPeer = 65536
	// peerBufferLimit bounds the bytes one peer leaves buffered, partial messages and messages
	// not taken, over all its sessions (section 7.3): 2 × 64 MiB + 4 × window, since one whole
	// message can wait on a session while the next arrives on the session a rekey made.
	peerBufferLimit = func(window int64) int64 { return 2*MaxMessage + 4*window }
)

type session struct {
	peer                    string
	localIndex, remoteIndex uint32
	initiator               bool
	send, recv              *noise.CipherState
	createdAt, lastActivity time.Time
	sent, received          uint64
	ended                   bool
	endErr                  *Error
	retired                 bool
	activeSends             int   // outbound messages currently bound to this session
	sendCredit              int64 // bytes this side may still send
	inflight                int64 // message bytes sent and not yet credited back
	rateAt                  time.Time
	rateCur, ratePrev       int64 // credit applied to inflight, in one-second buckets
	creditTimer             *mtimer
	// Receive side.
	partial         []byte // one contiguous buffer, grown by doubling
	partialLen      int64
	partialCredited int64
	held            int   // complete messages handed to the application and not yet taken
	owed            int64 // credit to return
	allowance       int64 // message bytes the peer may still send: granted minus received
}

type pendingInit struct {
	peer       string
	localIndex uint32
	hs         *noise.HandshakeState
	timer      *mtimer
	waiters    []func(*session, *Error)
}

type indexEntry struct {
	s *session
	p *pendingInit
}

type peerState struct {
	current  *session
	sessions []*session
	pending  *pendingInit
	queue    []*outMsg // outbound messages, in order; the head is the one being sent
	// Bytes this peer has left buffered here (partial messages of its live sessions and
	// messages the application has not taken), and the count of the latter.
	buffered  int64
	heldCount int
}

// outMsg is one application message on its way out.
type outMsg struct {
	peer     string
	bytes    []byte
	off      int
	s        *session
	running  bool // its session is being found
	started  bool // a fragment went out
	finished bool
	done     chan error
	timer    *mtimer // waiting for the relay connection
}

// SessionInfo describes one live session, for tests and diagnostics.
type SessionInfo struct {
	Peer                    string
	LocalIndex, RemoteIndex uint32
	Initiator, Current      bool
	Sent, Received          uint64
	SendCredit, Inflight    int64
}

type coreStats struct {
	creditsSent      int
	messagesReceived int
	initsRead        int
}

// pacedFragment is the largest fragment at rate rateBps (0: unshaped).
func pacedFragment(rateBps int64) int64 {
	if rateBps <= 0 {
		return maxFragment
	}
	return max(pacedMinFragment, min(maxFragment, 7*rateBps/32))
}

type sessionManager struct {
	m              *Member
	peers          map[string]*peerState
	byIndex        map[uint32]indexEntry
	sweepTimer     *mtimer
	closed         bool
	gate           []*outMsg
	pumping        bool
	repump         bool
	awaitingSocket bool
	// The rate in force from the relay's shaping notice (0: none), when the connection's next
	// fragment may go at its pace, and the timer that pumps then.
	rateBps   int64
	paceDue   time.Time
	paceTimer *mtimer
	stats     coreStats
	rng       io.Reader // ephemeral keys and indices; nil is crypto/rand
	limits    *peerLimits
	// stamps holds, per member, the greatest stamp of an init accepted from it (section
	// 7.1); bounded by the roster, and kept across relay connections.
	stamps map[string]uint64
	// For a member with no stamp stored: when this responder started, and when ids were added
	// to its roster since, on the monotonic clock (a wall clock put right after either cannot
	// freeze the floor); bounded by the roster.
	startedMono time.Duration
	addedMono   map[string]time.Duration
	retained    retainedStamps // the last stamps of ids that left the roster
}

// lastStamp is what an init from a member must exceed (section 7.1): the greater of its
// stored stamp (the greatest accepted, or the one retained from before it left the roster) and
// the time floor, the later of this responder's start and the member's addition to its roster,
// in wall time now, less W. The floor alone would let a relay replay every init it recorded of
// a peer after a restart or a re-add; the stored stamp alone would let through an init from
// before a removal that was never delivered, however much later the member is re-added.
func (sm *sessionManager) lastStamp(id string) uint64 {
	joined := max(sm.startedMono, sm.addedMono[id])
	wallNow, monoNow := sm.m.clock.Now().UnixMilli(), sm.m.clock.Mono()
	floor := uint64(max(wallNow-(monoNow-joined).Milliseconds()-stampWindowMs, 0))
	return max(sm.stamps[id], floor)
}

// rosterAdded notes, for ids the new roster lists and the old did not, when they were added.
func (sm *sessionManager) rosterAdded(old, next *Roster) {
	now := sm.m.clock.Mono()
	for _, mem := range next.Members {
		if old.member(mem.ID) == nil {
			sm.addedMono[mem.ID] = now
			// Re-admitted: its last stamp from before it left, if retained, refuses exactly the
			// inits recorded before; the floor is only for an id with none.
			if s, ok := sm.retained.take(mem.ID); ok {
				sm.stamps[mem.ID] = s
			} else {
				delete(sm.stamps, mem.ID)
			}
		}
	}
}

// retainedStamps keeps the last stamp of ids that left the roster, the most recent
// retainedCap, so that one re-admitted refuses the inits recorded before it left.
type retainedStamps struct {
	order []string
	stamp map[string]uint64
}

const retainedCap = 1024

func (r *retainedStamps) put(id string, s uint64) {
	if r.stamp == nil {
		r.stamp = map[string]uint64{}
	}
	if _, ok := r.stamp[id]; ok {
		r.drop(id)
	}
	r.order = append(r.order, id)
	r.stamp[id] = s
	for len(r.order) > retainedCap {
		delete(r.stamp, r.order[0])
		r.order = r.order[1:]
	}
}

func (r *retainedStamps) take(id string) (uint64, bool) {
	s, ok := r.stamp[id]
	if ok {
		r.drop(id)
	}
	return s, ok
}

func (r *retainedStamps) drop(id string) {
	delete(r.stamp, id)
	for i, x := range r.order {
		if x == id {
			r.order = append(r.order[:i:i], r.order[i+1:]...)
			break
		}
	}
}

// initPayloadLen: an init's payload is the roster version and the stamp, u64be each.
const initPayloadLen = 16

// stampWindowMs, W: an init stamped more than this ahead of the responder's wall clock is
// refused, and a member with no stamp stored has a floor this far before it joined
// (section 7.1).
const stampWindowMs = 10 * 60 * 1000

func newSessionManager(m *Member) *sessionManager {
	sm := &sessionManager{m: m, peers: map[string]*peerState{}, byIndex: map[uint32]indexEntry{}, limits: newPeerLimits(), stamps: map[string]uint64{},
		startedMono: m.clock.Mono(), addedMono: map[string]time.Duration{}}
	return sm
}

func (sm *sessionManager) startSweep() {
	t := sm.m.timing
	period := max(20*time.Millisecond, min(t.Idle, t.RekeyInterval, t.RetireGrace)/4)
	var tick func()
	tick = func() {
		if sm.closed {
			return
		}
		sm.sweep()
		sm.sweepTimer = sm.m.after(period, tick)
	}
	sm.sweepTimer = sm.m.after(period, tick)
}

// now is monotonic: every interval, timeout and budget here is measured on it.
func (sm *sessionManager) now() time.Time { return sm.m.mono() }

func (sm *sessionManager) maxBufferedPerPeer() int64 { return peerBufferLimit(sm.m.creditWindow) }

// ── Public operations ──

// enqueue adds an admitted message to its peer's queue; messages to one peer go one at a
// time, in order.
func (sm *sessionManager) enqueue(o *outMsg) {
	ps := sm.peer(o.peer)
	ps.queue = append(ps.queue, o)
	if len(ps.queue) == 1 {
		sm.m.later(func() { sm.startHead(ps) })
	}
}

func (sm *sessionManager) startHead(ps *peerState) {
	for len(ps.queue) > 0 && ps.queue[0].finished {
		ps.queue = ps.queue[1:]
	}
	if len(ps.queue) == 0 {
		return
	}
	o := ps.queue[0]
	if o.running {
		return
	}
	o.running = true
	sm.ensureSession(o.peer, func(s *session, err *Error) {
		if o.finished {
			return
		}
		if err != nil {
			sm.finishOut(o, err)
			return
		}
		o.s = s
		s.activeSends++
		sm.gate = append(sm.gate, o)
		sm.pump()
	})
}

// finishOut completes a message, once: the result goes to its sender and the next message
// to the peer starts.
func (sm *sessionManager) finishOut(o *outMsg, err error) {
	if o.finished {
		return
	}
	o.finished = true
	o.timer.cancel()
	if o.s != nil {
		o.s.activeSends--
		sm.maybeRekey(o.s)
	}
	if err == nil {
		sm.m.countSent(o.peer, len(o.bytes))
	}
	o.done <- err
	if ps := sm.peers[o.peer]; ps != nil {
		for i, q := range ps.queue {
			if q == o {
				ps.queue = append(ps.queue[:i:i], ps.queue[i+1:]...)
				if i == 0 {
					sm.m.later(func() { sm.startHead(ps) })
				}
				break
			}
		}
	}
}

// sendControl sends a session message other than message (roster-request, roster, resign).
func (sm *sessionManager) sendControl(peer string, msg sessionMessage, cb func(error)) {
	if sm.closed {
		sm.m.later(func() { cb(closedError("")) })
		return
	}
	sm.ensureSession(peer, func(s *session, err *Error) {
		if err != nil {
			cb(err)
			return
		}
		_, e := sm.transmit(s, msg)
		cb(e)
	})
}

// rosterChanged ends every session with peers no longer on the roster.
func (sm *sessionManager) rosterChanged() {
	roster := sm.m.roster
	sm.limits.forget(func(id string) bool { return roster.member(id) != nil })
	for id, st := range sm.stamps {
		if roster.member(id) == nil {
			sm.retained.put(id, st)
			delete(sm.stamps, id)
		}
	}
	for id := range sm.addedMono {
		if roster.member(id) == nil {
			delete(sm.addedMono, id)
		}
	}
	for id, ps := range sm.peers {
		if roster.member(id) != nil {
			continue
		}
		err := invalidError(id + " is no longer on the roster")
		sm.failPending(ps, err)
		for _, s := range append([]*session(nil), ps.sessions...) {
			sm.endSession(s, err)
		}
	}
}

// dropAll ends all sessions, as when the relay connection drops.
func (sm *sessionManager) dropAll(err *Error) {
	for _, ps := range sm.peers {
		sm.failPending(ps, err)
		for _, s := range append([]*session(nil), ps.sessions...) {
			sm.endSession(s, err)
		}
	}
}

func (sm *sessionManager) close() {
	if sm.closed {
		return
	}
	sm.closed = true
	sm.sweepTimer.cancel()
	sm.paceTimer.cancel()
	sm.dropAll(closedError(""))
}

// setRate sets the rate the relay shapes the network at (section 9's shaping; 0: none).
// Fragments are paced to it from now on; what was handed over already is the relay's grace to
// read.
func (sm *sessionManager) setRate(rateBps int64) {
	if rateBps == sm.rateBps {
		return
	}
	sm.rateBps = rateBps
	if rateBps == 0 {
		sm.paceTimer.cancel()
		sm.paceTimer = nil
	}
	sm.pump()
}

// sessionInfo lists the sessions with peer, or with every peer for "".
func (sm *sessionManager) sessionInfo(peer string) []SessionInfo {
	var out []SessionInfo
	for id, ps := range sm.peers {
		if peer != "" && id != peer {
			continue
		}
		for _, s := range ps.sessions {
			out = append(out, SessionInfo{
				Peer: id, LocalIndex: s.localIndex, RemoteIndex: s.remoteIndex, Initiator: s.initiator, Current: ps.current == s,
				Sent: s.sent, Received: s.received, SendCredit: s.sendCredit, Inflight: s.inflight,
			})
		}
	}
	return out
}

// ── Frames from the relay ──

// handleFrame takes a routed frame from the relay. A malformed frame is dropped; it never
// takes the member down.
func (sm *sessionManager) handleFrame(f frame, from string) {
	if sm.closed {
		return
	}
	switch f.typ {
	case frameHandshakeInit:
		sm.onInit(from, f.body)
	case frameHandshakeResp:
		sm.onResp(from, f.body)
	case frameData, frameControl:
		sm.onData(from, f.body)
	case frameUnreachable:
		sm.onUnreachable(from)
	case frameRefused:
		reason := 0
		if len(f.body) > 0 {
			reason = int(f.body[0])
		}
		sm.onRefused(from, reason)
	case frameReset:
		if len(f.body) >= 4 {
			sm.onReset(from, binary.BigEndian.Uint32(f.body))
		}
	}
}

func (sm *sessionManager) onInit(from string, body []byte) {
	roster := sm.m.roster
	senderIndex, msg1, err := parseHandshakeInit(body)
	if err != nil || senderIndex == 0 {
		return
	}
	// Reading message 1 costs two X25519 operations before the sender is known, and IK's
	// message 1 can be replayed: each sender gets a budget.
	onRoster := roster.member(from) != nil
	if !sm.limits.allowInit(from, onRoster, sm.now()) {
		// An init from an id off the roster hints that a roster this member has not seen
		// lists it (a newcomer, say): the primary is asked, at most once a second.
		if !onRoster {
			sm.m.askPrimary()
		}
		return
	}
	sm.stats.initsRead++
	hs, err := newHandshake(sm.m.identity, false, roster.Network, nil, sm.rng)
	if err != nil {
		return
	}
	payload, _, _, err := hs.ReadMessage(nil, msg1)
	if err != nil {
		// An honest member's init always reads: one labelled with a member's id that does not
		// is bad (forged by the relay, or sent so by that member) and spends that id's own
		// failure budget.
		if onRoster {
			sm.limits.failedInit(from, sm.now())
		}
		return
	}
	// The payload is the roster version and the init's stamp (section 7.1), 16 bytes.
	version, stamp, hasVersion := uint64(0), uint64(0), len(payload) == initPayloadLen
	if hasVersion {
		version, stamp = binary.BigEndian.Uint64(payload), binary.BigEndian.Uint64(payload[8:])
	}
	member := roster.member(from)
	rs := hs.PeerStatic()
	if member == nil || rs == nil || !sameKey(member.X25519, rs) {
		sm.m.sendFrame(frameRefused, from, []byte{refusedNotOnRoster}) // within the init's budget
		if onRoster {
			// Labelled with a member's id, but not that member's key: a bad init (forged by the
			// relay, or sent so by that member), which spends that id's own failure budget. Its
			// version is ignored, or a forgery could draw a roster push.
			sm.limits.failedInit(from, sm.now())
			return
		}
		if hasVersion {
			// An id off the roster with a newer roster hints at one this member has not seen.
			sm.m.onPeerVersion(from, version)
		}
		return
	}
	if !hasVersion {
		// Well keyed but malformed: a failed init, like one that does not read.
		sm.limits.failedInit(from, sm.now())
		return
	}
	// IK's message 1 has no replay protection of its own: the stamp gives it. One no greater
	// than the greatest accepted from this member (or than its floor) is a replay, and one more
	// than W ahead of this side's wall clock could be replayed until the clock caught up: both
	// are dropped unanswered and charged as a failed init, changing no session or stamp, and
	// their version is ignored.
	if stamp > uint64(max(sm.m.clock.Now().UnixMilli(), 0))+stampWindowMs || stamp <= sm.lastStamp(from) {
		sm.limits.failedInit(from, sm.now())
		return
	}
	sm.stamps[from] = stamp
	localIndex := sm.newIndex()
	msg2, toInitiator, toResponder, err := hs.WriteMessage(nil, u64be(uint64(roster.Version)))
	if err != nil || toInitiator == nil {
		return
	}
	if !sm.m.sendFrame(frameHandshakeResp, from, handshakeRespBody(localIndex, senderIndex, msg2)) {
		return
	}
	// flynn/noise splits into initiator->responder, then responder->initiator.
	s := sm.newSession(from, localIndex, senderIndex, false, toResponder, toInitiator)
	sm.adopt(s)
	sm.m.onPeerVersion(from, version)
}

func (sm *sessionManager) onResp(from string, body []byte) {
	senderIndex, receiverIndex, msg2, err := parseHandshakeResp(body)
	if err != nil {
		return
	}
	p := sm.byIndex[receiverIndex].p
	if p == nil || p.peer != from || senderIndex == 0 {
		return
	}
	ps := sm.peer(from)
	payload, toResponder, toInitiator, err := p.hs.ReadMessage(nil, msg2)
	if err != nil || toResponder == nil || len(payload) != 8 {
		sm.failPending(ps, closedError(fmt.Sprintf("handshake with %s failed", from)))
		return
	}
	// The responder's key must still be on the current roster.
	member := sm.m.roster.member(from)
	if member == nil || !sameKey(member.X25519, p.hs.PeerStatic()) {
		sm.failPending(ps, invalidError(from+" is no longer on the roster"))
		return
	}
	p.timer.cancel()
	if ps.pending == p {
		ps.pending = nil
	}
	s := sm.newSession(from, p.localIndex, senderIndex, true, toResponder, toInitiator)
	sm.adopt(s)
	for _, w := range p.waiters {
		sm.m.later(func() { w(s, nil) })
	}
	sm.m.onPeerVersion(from, binary.BigEndian.Uint64(payload))
}

func (sm *sessionManager) onData(from string, body []byte) {
	receiverIndex, ct, err := parseData(body)
	if err != nil {
		return
	}
	s := sm.byIndex[receiverIndex].s
	if s == nil || s.peer != from || s.ended || (sm.expired(s) && !sm.crossing(s)) {
		// Section 7.2: a receiver index this side does not hold (or a responder session past
		// its lifetime, unless a message is still crossing it in either direction) is
		// answered with reset.
		if s != nil && s.peer == from {
			sm.endSession(s, closedError(fmt.Sprintf("session with %s expired", from)))
		}
		if sm.limits.allowReset(from, sm.m.roster.member(from) != nil, receiverIndex, sm.now()) {
			sm.m.sendFrame(frameReset, from, u32be(receiverIndex))
		}
		return
	}
	if len(ct) > maxNoiseMessage {
		sm.endSession(s, closedError(fmt.Sprintf("session with %s carried a frame over 65535 bytes", from)))
		return
	}
	plaintext, err := s.recv.Decrypt(nil, nil, ct)
	if err != nil {
		// Frames for one pair arrive in order: a frame that does not decrypt (lost, replayed,
		// reordered or forged) ends the session.
		sm.endSession(s, closedError(fmt.Sprintf("session with %s lost a frame", from)))
		return
	}
	s.received++
	s.lastActivity = sm.now()
	msg, err := decodeSessionMessage(plaintext)
	if err != nil {
		sm.endSession(s, closedError(fmt.Sprintf("session with %s carried a malformed message", from)))
		return
	}
	switch msg.typ {
	case sessMessage:
		sm.onFragment(s, msg.more, msg.bytes)
	case sessCredit:
		c := int64(msg.credit)
		s.sendCredit = min(s.sendCredit+c, 1<<53) // a peer cannot overflow it
		took := min(s.inflight, c)
		s.inflight -= took
		sm.rollRate(s, sm.now())
		s.rateCur += took
		sm.pump()
	default:
		sm.m.onSessionControl(from, msg)
	}
	sm.maybeRekey(s)
}

func (sm *sessionManager) onFragment(s *session, more bool, bytes []byte) {
	n := int64(len(bytes))
	ps := sm.peer(s.peer)
	switch {
	case more && n == 0:
		// A fragment that says more follow carries at least one byte (section 7.3).
		sm.endSession(s, closedError(fmt.Sprintf("%s sent an empty fragment saying more follow", s.peer)))
		return
	case n > s.allowance:
		sm.endSession(s, closedError(fmt.Sprintf("%s sent message bytes beyond the credit granted", s.peer)))
		return
	case s.partialLen+n > MaxMessage:
		sm.endSession(s, closedError(fmt.Sprintf("%s sent a message over 64 MiB", s.peer)))
		return
	case ps.buffered+n > sm.maxBufferedPerPeer():
		sm.endSession(s, closedError(fmt.Sprintf("%s left more buffered than this member keeps for a peer", s.peer)))
		return
	case !more && ps.heldCount >= maxHeldMessagesPerPeer:
		sm.endSession(s, closedError(fmt.Sprintf("%s sent more messages than this member holds untaken", s.peer)))
		return
	}
	s.allowance -= n
	if n > 0 {
		s.partial = growAppend(s.partial, bytes)
	}
	s.partialLen += n
	ps.buffered += n
	if more {
		// Fragments of a message in progress are taken at once while the application keeps
		// up, so a message larger than the window can finish.
		if s.held == 0 {
			s.owed += n
			s.partialCredited += n
			sm.flushCredit(s, false)
		}
		return
	}
	whole := s.partial[:s.partialLen:s.partialLen]
	if int64(cap(s.partial)) > s.partialLen+s.partialLen/4 {
		// Doubling left room unused: a message waiting for the application keeps its bytes only.
		whole = append([]byte(nil), whole...)
	}
	if whole == nil {
		whole = []byte{}
	}
	sm.stats.messagesReceived++
	uncredited := s.partialLen - s.partialCredited
	s.partial, s.partialLen, s.partialCredited = nil, 0, 0
	s.held++
	ps.heldCount++
	size := int64(len(whole))
	released := false
	sm.m.deliver(s.peer, whole, func() {
		if released {
			return
		}
		released = true
		s.held--
		ps.heldCount--
		ps.buffered -= size
		s.owed += uncredited
		if s.held == 0 && s.partialLen > s.partialCredited {
			s.owed += s.partialLen - s.partialCredited
			s.partialCredited = s.partialLen
		}
		sm.flushCredit(s, false)
	})
}

// flushCredit returns owed credit in batches: at once from CreditBatchBytes, else
// CreditDelay after it began to be owed.
func (sm *sessionManager) flushCredit(s *session, now bool) {
	if s.ended || s.owed <= 0 {
		return
	}
	if !now && s.owed < CreditBatchBytes {
		if s.creditTimer == nil {
			s.creditTimer = sm.m.after(CreditDelay, func() {
				s.creditTimer = nil
				sm.flushCredit(s, true)
			})
		}
		return
	}
	s.creditTimer.cancel()
	s.creditTimer = nil
	for s.owed > 0 {
		n := min(s.owed, 0xffffffff)
		s.owed -= n
		s.allowance += n
		sm.stats.creditsSent++
		if ok, _ := sm.transmit(s, sessionMessage{typ: sessCredit, credit: uint32(n)}); !ok {
			return
		}
	}
}

func (sm *sessionManager) onUnreachable(peer string) {
	ps := sm.peers[peer]
	if ps == nil {
		return
	}
	err := unreachableError(peer)
	sm.failPending(ps, err)
	for _, s := range append([]*session(nil), ps.sessions...) {
		sm.endSession(s, err)
	}
}

// onReset: the peer holds no session for index (our remote index). Ours is dropped; the next
// send handshakes.
func (sm *sessionManager) onReset(peer string, index uint32) {
	ps := sm.peers[peer]
	if ps == nil {
		return
	}
	for _, s := range append([]*session(nil), ps.sessions...) {
		if s.remoteIndex == index {
			sm.endSession(s, closedError(peer+" reset the session"))
		}
	}
}

func (sm *sessionManager) onRefused(peer string, reason int) {
	ps := sm.peers[peer]
	if ps == nil {
		return
	}
	err := refusedError(peer, reason)
	sm.failPending(ps, err)
	for _, s := range append([]*session(nil), ps.sessions...) {
		sm.endSession(s, err)
	}
}

// ── Session lifecycle ──

func (sm *sessionManager) peer(id string) *peerState {
	ps := sm.peers[id]
	if ps == nil {
		ps = &peerState{}
		sm.peers[id] = ps
	}
	return ps
}

func (sm *sessionManager) random() io.Reader {
	if sm.rng != nil {
		return sm.rng
	}
	return rand.Reader
}

func (sm *sessionManager) newIndex() uint32 {
	var b [4]byte
	for {
		if _, err := io.ReadFull(sm.random(), b[:]); err != nil {
			panic(err)
		}
		i := binary.BigEndian.Uint32(b[:])
		if _, used := sm.byIndex[i]; i != 0 && !used {
			return i
		}
	}
}

func (sm *sessionManager) newSession(peer string, local, remote uint32, initiator bool, send, recv *noise.CipherState) *session {
	now := sm.now()
	return &session{
		peer: peer, localIndex: local, remoteIndex: remote, initiator: initiator, send: send, recv: recv,
		createdAt: now, lastActivity: now, rateAt: now, sendCredit: InitialCredit, allowance: InitialCredit,
	}
}

// adopt makes a newly established session the one new messages use.
func (sm *sessionManager) adopt(s *session) {
	ps := sm.peer(s.peer)
	sm.byIndex[s.localIndex] = indexEntry{s: s}
	ps.sessions = append(ps.sessions, s)
	// A window beyond the initial 1 MiB is granted as extra credit at once.
	if extra := sm.m.creditWindow - InitialCredit; extra > 0 {
		s.owed += extra
		sm.flushCredit(s, false)
	}
	prev := ps.current
	ps.current = s
	if prev != nil && prev != s {
		prev.retired = true
		if now := sm.now(); now.After(prev.lastActivity) {
			prev.lastActivity = now
		}
	}
	for len(ps.sessions) > maxSessionsPerPeer {
		oldest := ps.sessions[0]
		if oldest == ps.current {
			oldest = ps.sessions[1]
		}
		sm.endSession(oldest, closedError(fmt.Sprintf("too many sessions with %s", s.peer)))
	}
}

// ensureSession finds the session for the next message to peer, handshaking when there is
// none; cb runs as a task.
func (sm *sessionManager) ensureSession(peer string, cb func(*session, *Error)) {
	var cur *session
	if ps := sm.peers[peer]; ps != nil {
		cur = ps.current
	}
	if cur != nil && sm.expired(cur) {
		// Expiry yields to a message in flight (section 7.2): one still crossing finishes on
		// the old session, which is retired; this send takes a new one.
		if sm.crossing(cur) {
			cur.retired = true
		} else {
			sm.endSession(cur, closedError(fmt.Sprintf("session with %s expired", peer)))
		}
		sm.initiate(peer, cb)
		return
	}
	if cur != nil && !cur.ended {
		sm.maybeRekey(cur)
		sm.m.later(func() { cb(cur, nil) })
		return
	}
	sm.initiate(peer, cb)
}

func (sm *sessionManager) initiate(peer string, cb func(*session, *Error)) {
	fail := func(err *Error) { sm.m.later(func() { cb(nil, err) }) }
	// A send queued before close runs after it: it must not start a handshake.
	if sm.closed {
		fail(closedError(""))
		return
	}
	roster := sm.m.roster
	member := roster.member(peer)
	if member == nil {
		// Checked before any state is made for the peer: the relay can name anyone.
		fail(invalidError(peer + " is not on the roster"))
		return
	}
	ps := sm.peer(peer)
	if ps.pending != nil {
		ps.pending.waiters = append(ps.pending.waiters, cb)
		return
	}
	rs, err := member.x25519Of()
	if err != nil {
		fail(invalidError(peer + " has no usable x25519 key"))
		return
	}
	hs, err := newHandshake(sm.m.identity, true, roster.Network, rs, sm.rng)
	if err != nil {
		fail(closedError(fmt.Sprintf("handshake with %s failed", peer)))
		return
	}
	localIndex := sm.newIndex()
	msg1, _, _, err := hs.WriteMessage(nil, append(u64be(uint64(roster.Version)), u64be(sm.m.nextStamp())...))
	if err != nil {
		fail(closedError(fmt.Sprintf("handshake with %s failed", peer)))
		return
	}
	p := &pendingInit{peer: peer, localIndex: localIndex, hs: hs, waiters: []func(*session, *Error){cb}}
	p.timer = sm.m.after(sm.m.timing.HandshakeTimeout, func() {
		if ps.pending == p {
			sm.failPending(ps, timeoutError("handshake with "+peer))
		}
	})
	ps.pending = p
	sm.byIndex[localIndex] = indexEntry{p: p}
	if !sm.m.sendFrame(frameHandshakeInit, peer, handshakeInitBody(localIndex, msg1)) {
		sm.failPending(ps, closedError("not connected to the relay"))
	}
}

func (sm *sessionManager) failPending(ps *peerState, err *Error) {
	p := ps.pending
	if p == nil {
		return
	}
	p.timer.cancel()
	ps.pending = nil
	if sm.byIndex[p.localIndex].p == p {
		delete(sm.byIndex, p.localIndex)
	}
	for _, w := range p.waiters {
		sm.m.later(func() { w(nil, err) })
	}
}

func (sm *sessionManager) endSession(s *session, err *Error) {
	if s.ended {
		return
	}
	s.ended = true
	s.endErr = err
	if sm.byIndex[s.localIndex].s == s {
		delete(sm.byIndex, s.localIndex)
	}
	if ps := sm.peers[s.peer]; ps != nil {
		for i, x := range ps.sessions {
			if x == s {
				ps.sessions = append(ps.sessions[:i:i], ps.sessions[i+1:]...)
				break
			}
		}
		if ps.current == s {
			ps.current = nil
		}
		ps.buffered -= s.partialLen
	}
	s.partial, s.partialLen, s.partialCredited = nil, 0, 0
	s.creditTimer.cancel()
	s.creditTimer = nil
	// Fragments waiting in the gate on this session fail with it.
	sm.pump()
}

// expired: a responder session older than the rekey interval plus the grace.
func (sm *sessionManager) expired(s *session) bool {
	t := sm.m.timing
	return !s.initiator && sm.now().Sub(s.createdAt) > t.RekeyInterval+t.RetireGrace
}

// crossing: a message is part-way across the session, being received or sent.
func (sm *sessionManager) crossing(s *session) bool {
	return s.partialLen > 0 || s.activeSends > 0
}

func (sm *sessionManager) maybeRekey(s *session) {
	if !s.initiator || s.retired || s.ended {
		return
	}
	t := sm.m.timing
	due := sm.now().Sub(s.createdAt) >= t.RekeyInterval || s.sent >= t.RekeyMessages || s.received >= t.RekeyMessages
	if due && sm.peer(s.peer).pending == nil {
		sm.initiate(s.peer, func(*session, *Error) {})
	}
}

func (sm *sessionManager) sweep() {
	now := sm.now()
	t := sm.m.timing
	for id, ps := range sm.peers {
		for _, s := range append([]*session(nil), ps.sessions...) {
			quiet := now.Sub(s.lastActivity)
			idleOK := s.activeSends == 0 && s.partialLen == 0 && s.held == 0
			switch {
			case quiet >= t.Idle:
				sm.endSession(s, closedError(fmt.Sprintf("session with %s went idle", s.peer)))
			case sm.expired(s) && idleOK:
				sm.endSession(s, closedError(fmt.Sprintf("session with %s expired", s.peer)))
			case s.retired && quiet >= t.RetireGrace && idleOK:
				sm.endSession(s, closedError(fmt.Sprintf("session with %s was replaced", s.peer)))
			case s.sent+s.received > 0:
				// A session that never carried a frame is left to expire, not rekeyed.
				sm.maybeRekey(s)
			}
		}
		// A peer that left the roster and holds nothing is forgotten.
		if len(ps.sessions) == 0 && ps.pending == nil && len(ps.queue) == 0 && ps.heldCount == 0 && sm.m.roster.member(id) == nil {
			delete(sm.peers, id)
		}
	}
}

// ── Sending ──

// transmit encrypts one session message and hands it to the relay in one step: the frame's
// nonce is its place on the wire. It reports whether the frame was handed over.
func (sm *sessionManager) transmit(s *session, msg sessionMessage) (bool, error) {
	if s.ended {
		return false, nil
	}
	plaintext := encodeSessionMessage(msg)
	// Checked before encrypting, so a refused message does not spend a nonce.
	if len(plaintext) > maxPlaintext {
		return false, invalidError(fmt.Sprintf("a %s session message exceeds %d bytes", msg.name(), maxPlaintext))
	}
	ct, err := s.send.Encrypt(nil, nil, plaintext)
	if err != nil {
		sm.endSession(s, closedError(fmt.Sprintf("session with %s is exhausted", s.peer)))
		return false, nil
	}
	s.sent++
	s.lastActivity = sm.now()
	typ := frameControl
	if msg.typ == sessMessage {
		typ = frameData
	}
	return sm.m.sendFrame(typ, s.peer, dataBody(s.remoteIndex, ct)), nil
}

// runFragment sends the next fragment of o: never more than the room left under the window
// (but not below the smallest fragment), so the socket holds about the window and no more: on
// a slow link fragments shrink, and control behind them waits a fraction of a second rather
// than a whole fragment.
func (sm *sessionManager) runFragment(o *outMsg) {
	s := o.s
	largest := pacedFragment(sm.rateBps)
	room := max(min(paceMinFragment, largest), sm.pace(s)-s.inflight)
	n := min(int64(len(o.bytes)-o.off), largest, max(s.sendCredit, 0), room)
	more := int64(o.off)+n < int64(len(o.bytes))
	ok, err := sm.transmit(s, sessionMessage{typ: sessMessage, more: more, bytes: o.bytes[o.off : o.off+int(n)]})
	if err == nil && !ok {
		if s.endErr != nil {
			err = s.endErr
		} else {
			err = closedError("not connected to the relay")
		}
	}
	if err != nil {
		sm.finishOut(o, err)
		return
	}
	if sm.rateBps > 0 {
		pace := sm.rateBps * PaceShareNum / PaceShareDen
		cost := time.Duration((n + fragmentFrameOverhead) * int64(time.Second) / max(pace, 1))
		now := sm.now()
		if sm.paceDue.Before(now) {
			sm.paceDue = now
		}
		sm.paceDue = sm.paceDue.Add(cost)
	}
	o.started = true
	s.sendCredit -= n
	s.inflight += n
	o.off += int(n)
	if o.off < len(o.bytes) {
		sm.m.later(func() {
			if !o.finished {
				sm.gate = append(sm.gate, o)
				sm.pump()
			}
		})
	} else {
		sm.m.later(func() { sm.finishOut(o, nil) })
	}
}

// pace is the message bytes s may have un-credited, its window: about a second and a half of
// what its receiver takes; while shaped, about a second of it, and never more than half a
// second of the rate, so that members sending at once each keep about a second of their share
// behind their control (section 11). A second's worth of credit is the larger of the last
// whole second and the one under way (not their sum: credit comes in lumps).
func (sm *sessionManager) pace(s *session) int64 {
	sm.rollRate(s, sm.now())
	credited := max(s.ratePrev, s.rateCur)
	if sm.rateBps > 0 {
		return max(pacedFragment(sm.rateBps), min(credited, sm.rateBps/2))
	}
	return max(PaceFloorBytes, 3*credited/2)
}

func (sm *sessionManager) rollRate(s *session, now time.Time) {
	d := now.Sub(s.rateAt)
	switch {
	case d >= 2*time.Second || d < 0:
		s.ratePrev, s.rateCur, s.rateAt = 0, 0, now
	case d >= time.Second:
		s.ratePrev, s.rateCur = s.rateCur, 0
		s.rateAt = s.rateAt.Add(time.Second)
	}
}

// pump hands waiting fragments to the socket, oldest first, skipping a session that is out
// of credit or over its window (its next credit wakes it) so one slow receiver never holds up
// another. It stops while the socket is backed up, and resumes once it drains; and, while
// shaped, until the connection's pace allows the next fragment.
func (sm *sessionManager) pump() {
	if sm.pumping {
		sm.repump = true
		return
	}
	sm.pumping = true
	defer func() { sm.pumping = false }()
	for {
		sm.repump = false
		sm.pumpOnce()
		if !sm.repump {
			return
		}
	}
}

func (sm *sessionManager) pumpOnce() {
	for i := 0; i < len(sm.gate); {
		o := sm.gate[i]
		if o.finished {
			sm.gate = append(sm.gate[:i:i], sm.gate[i+1:]...)
			continue
		}
		if o.s.ended || sm.closed {
			sm.gate = append(sm.gate[:i:i], sm.gate[i+1:]...)
			var err error = closedError("")
			if o.s.endErr != nil {
				err = o.s.endErr
			}
			sm.finishOut(o, err)
			continue
		}
		if (len(o.bytes) > 0 && o.s.sendCredit <= 0) || o.s.inflight >= sm.pace(o.s) {
			i++
			continue
		}
		if !sm.m.relay.writable() {
			if !sm.awaitingSocket {
				sm.awaitingSocket = true
				sm.m.relay.whenWritable(func() {
					sm.awaitingSocket = false
					sm.pump()
				})
			}
			return
		}
		if sm.rateBps > 0 {
			if wait := sm.paceDue.Sub(sm.now()); wait > 0 {
				if sm.paceTimer == nil || sm.paceTimer.dead {
					sm.paceTimer = sm.m.after(wait, func() {
						sm.paceTimer = nil
						sm.pump()
					})
				}
				return
			}
		}
		sm.gate = append(sm.gate[:i:i], sm.gate[i+1:]...)
		sm.runFragment(o)
	}
}

// growAppend appends b to a reassembly buffer that grows by doubling (never past
// MaxMessage), so fragments of any size, one byte included, cost their bytes and no more
// than as much again: no per-fragment allocation or header.
func growAppend(buf, b []byte) []byte {
	need := len(buf) + len(b)
	if need > cap(buf) {
		c := max(cap(buf)*2, need, 4096)
		c = min(c, max(need, MaxMessage))
		grown := make([]byte, len(buf), c)
		copy(grown, buf)
		buf = grown
	}
	return append(buf, b...)
}
