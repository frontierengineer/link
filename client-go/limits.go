package link

import (
	"container/list"
	"time"
)

// The rates of section 7.4: what a peer, or a relay forging frames, gets a member to do in
// return. Every budget belongs to one id, so a peer that floods spends only its own and never
// what another is owed. Roster members each have theirs, kept while they are on the roster;
// ids off the roster have theirs in an LRU of the 256 most recently seen, and beyond those,
// all their handshake-inits together are bounded by a ceiling on work that only a relay
// forging ids can reach. An init labelled with a member's id that fails to read or fails the
// key check (an honest member's never does: its id is derived from its key) spends that id's
// own failure budget, and while it is empty that id's inits are dropped before any DH. It is
// per id, never shared: a member sending bad inits as itself, or a relay forging them under
// one member's id, holds back that id alone. Budgets carry across relay connections and are
// not refilled on redial: they refill only with time, from their last use, so a relay that
// forces reconnects gets no fresh budget for it.

const (
	// A roster member's handshake-inits are read 16 a second, in bursts of 32.
	memberInitRate, memberInitBurst = 16, 32
	// An id off the roster: 4 a second, bursts of 8...
	strangerInitRate, strangerInitBurst = 4, 8
	// ...and all such ids together 128 a second, bursts of 256.
	strangersInitRate, strangersInitBurst = 128, 256
	// Inits labelled with one member's id that fail to read or fail the key check: 2 a second,
	// bursts of 4, per id; while none is left, that id's inits are not read.
	failRate, failBurst = 2, 4
	// resets to one id: 32 a second, bursts of 64, and one a second per receiver index...
	resetRate, resetBurst = 32, 64
	// ...and to ids off the roster together 128 a second, bursts of 256.
	strangersResetRate, strangersResetBurst = 128, 256
	resetIndexEvery                         = time.Second
	// The indices remembered per id, and the ids off the roster remembered.
	resetIndices = 64
	strangerIDs  = 256
)

// bucket is a token bucket: a burst's worth to begin with, refilled at the rate.
type bucket struct {
	tokens float64
	at     time.Time
}

// take spends a token from a bucket refilled at rate a second up to burst.
func (b *bucket) take(now time.Time, rate, burst float64) bool {
	if !b.available(now, rate, burst) {
		return false
	}
	b.tokens--
	return true
}

// available refills the bucket to now and reports whether a token is left, spending none.
func (b *bucket) available(now time.Time, rate, burst float64) bool {
	if b.at.IsZero() {
		b.tokens = burst
	} else if d := now.Sub(b.at).Seconds(); d > 0 {
		b.tokens = min(burst, b.tokens+d*rate)
	}
	b.at = now
	return b.tokens >= 1
}

// failedInit spends a member id's failure budget for an init under its id that failed to read
// or failed the key check.
func (l *peerLimits) failedInit(id string, now time.Time) {
	l.get(id, true).fails.take(now, failRate, failBurst)
}

type peerLimit struct {
	id      string
	inits   bucket
	fails   bucket // a member id's inits that failed to read or failed the key check
	resets  bucket
	resetAt map[uint32]time.Time
}

type peerLimits struct {
	members   map[string]*peerLimit
	strangers *list.List // ids off the roster, most recently seen at the front
	byID      map[string]*list.Element
	ceiling   bucket // the inits of every id off the roster together
	resets    bucket // the resets to every id off the roster together
}

func newPeerLimits() *peerLimits {
	return &peerLimits{members: map[string]*peerLimit{}, strangers: list.New(), byID: map[string]*list.Element{}}
}

// reset starts every budget afresh (for tests; connections carry them over).
func (l *peerLimits) reset() {
	clear(l.members)
	l.strangers.Init()
	clear(l.byID)
	l.ceiling, l.resets = bucket{}, bucket{}
}

// forget drops the budgets of members that left the roster; they are strangers now.
func (l *peerLimits) forget(onRoster func(string) bool) {
	for id := range l.members {
		if !onRoster(id) {
			delete(l.members, id)
		}
	}
}

func (l *peerLimits) get(id string, member bool) *peerLimit {
	if member {
		p := l.members[id]
		if p == nil {
			p = &peerLimit{id: id}
			l.members[id] = p
		}
		return p
	}
	if e := l.byID[id]; e != nil {
		l.strangers.MoveToFront(e)
		return e.Value.(*peerLimit)
	}
	if l.strangers.Len() >= strangerIDs {
		old := l.strangers.Back()
		l.strangers.Remove(old)
		delete(l.byID, old.Value.(*peerLimit).id)
	}
	p := &peerLimit{id: id}
	l.byID[id] = l.strangers.PushFront(p)
	return p
}

// allowInit says whether a handshake-init from id may be read (the X25519 work of message 1).
func (l *peerLimits) allowInit(id string, member bool, now time.Time) bool {
	p := l.get(id, member)
	if member {
		return p.fails.available(now, failRate, failBurst) && p.inits.take(now, memberInitRate, memberInitBurst)
	}
	return p.inits.take(now, strangerInitRate, strangerInitBurst) && l.ceiling.take(now, strangersInitRate, strangersInitBurst)
}

// allowReset says whether a reset for index may go to id: once a second per index, and within
// the id's budget.
func (l *peerLimits) allowReset(id string, member bool, index uint32, now time.Time) bool {
	p := l.get(id, member)
	if at, ok := p.resetAt[index]; ok && now.Sub(at) < resetIndexEvery {
		return false
	}
	if !p.resets.take(now, resetRate, resetBurst) || !member && !l.resets.take(now, strangersResetRate, strangersResetBurst) {
		return false
	}
	if p.resetAt == nil {
		p.resetAt = map[uint32]time.Time{}
	}
	if len(p.resetAt) >= resetIndices {
		for i, at := range p.resetAt {
			if now.Sub(at) >= resetIndexEvery {
				delete(p.resetAt, i)
			}
		}
		for i := range p.resetAt {
			if len(p.resetAt) < resetIndices {
				break
			}
			delete(p.resetAt, i)
		}
	}
	p.resetAt[index] = now
	return true
}
