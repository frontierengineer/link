package link

import (
	"fmt"
	"os"
	"sync"
)

// Event is something a member raises: StateEvent, RosterEvent, DisconnectEvent, MovedEvent,
// RelayErrorEvent, and for a primary PairedEvent and PairingFailedEvent. Listeners run one
// at a time, in the order the events happened, on a goroutine of the member's; a listener
// may call any method of the member.
type Event interface{ isEvent() }

// StateEvent: the member's state changed.
type StateEvent struct{ State State }

// RosterEvent: a newer roster was accepted. Persist it.
type RosterEvent struct{ Roster *Roster }

// DisconnectEvent: the relay connection closed, with any code.
type DisconnectEvent struct {
	Code   int
	Reason string
}

// MovedEvent: close code 4009; the network moved to another relay node.
type MovedEvent struct{ Network string }

// RelayErrorEvent: a non-fatal error control message from the relay.
type RelayErrorEvent struct {
	Code    string
	Message string // empty when the relay sent none
	ID      string // the request it answers, if any
}

// PairedEvent (primary): a newcomer completed pairing with the code CodeID and is on the
// published roster.
type PairedEvent struct {
	Member RosterMember
	CodeID string
	Roster *Roster
}

// PairingFailedEvent (primary): a pairing attempt ended without a new member. Code is one of
// the Fail constants; Reason says it in words.
type PairingFailedEvent struct {
	CodeID string
	Code   string
	Reason string
}

// Why a pairing attempt failed (PairingFailedEvent.Code).
const (
	FailWrongCode     = "wrong-code"     // the newcomer's confirmation did not verify: a failed attempt
	FailMalformed     = "malformed"      // a pairing message was malformed: a failed attempt
	FailUnknownCode   = "unknown-code"   // no open code has that id
	FailUsed          = "used"           // another newcomer already confirmed the code
	FailNoAttempts    = "no-attempts"    // the code's five attempts are all failed or in flight
	FailNewcomerLeft  = "newcomer-left"  // the relay ended the channel (pairEnd)
	FailTimeout       = "timeout"        // the primary's own 60-second limit on the channel ran out
	FailRelayLost     = "relay-lost"     // the primary's relay connection dropped mid-pairing
	FailAlreadyMember = "already-member" // the newcomer's key is already on the roster
	FailRosterFull    = "roster-full"    // the roster has no room for the newcomer
	FailDemoted       = "demoted"        // the primary stopped being the primary mid-pairing
)

func (StateEvent) isEvent()         {}
func (RosterEvent) isEvent()        {}
func (DisconnectEvent) isEvent()    {}
func (MovedEvent) isEvent()         {}
func (RelayErrorEvent) isEvent()    {}
func (PairedEvent) isEvent()        {}
func (PairingFailedEvent) isEvent() {}

// dispatcher runs callbacks in order, outside the member's lock, on one goroutine at a time.
// Its queue has no hard limit, so everything pushed to it must be bounded at its source:
// messages by the credit window and the per-peer limits (each is credited back only once
// its handler returns); state, disconnect and moved events by reconnect backoff; roster
// events by the signed version, which only grows. What the relay can raise at will (relay
// errors, failed pairings) goes through pushDroppable, which drops beyond a backlog.
type dispatcher struct {
	mu         sync.Mutex
	queue      []func()
	running    bool
	dropBeyond int // pushDroppable drops beyond this backlog; 0 never drops
	dropped    int
}

// maxDroppableBacklog bounds what a hostile relay can queue with relay errors behind a slow
// listener.
const maxDroppableBacklog = 1024

// pushDroppable queues f unless the backlog is already over dropBeyond.
func (d *dispatcher) pushDroppable(f func()) {
	d.mu.Lock()
	if d.dropBeyond > 0 && len(d.queue) >= d.dropBeyond {
		d.dropped++
		d.mu.Unlock()
		return
	}
	d.mu.Unlock()
	d.push(f)
}

func (d *dispatcher) push(f func()) {
	d.mu.Lock()
	d.queue = append(d.queue, f)
	if d.running {
		d.mu.Unlock()
		return
	}
	d.running = true
	d.mu.Unlock()
	go d.run()
}

func (d *dispatcher) run() {
	for {
		d.mu.Lock()
		if len(d.queue) == 0 {
			d.running = false
			d.mu.Unlock()
			return
		}
		f := d.queue[0]
		d.queue[0] = nil
		d.queue = d.queue[1:]
		d.mu.Unlock()
		call(f)
	}
}

// call runs an application callback; a panic in it must not stop protocol handling.
func call(f func()) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "link: a listener panicked: %v\n", r)
		}
	}()
	f()
}

// listeners is a set of callbacks keyed for removal.
type listeners[T any] struct {
	next int
	fns  map[int]func(T)
	ord  []int
}

func (l *listeners[T]) add(f func(T)) int {
	if l.fns == nil {
		l.fns = map[int]func(T){}
	}
	l.next++
	l.fns[l.next] = f
	l.ord = append(l.ord, l.next)
	return l.next
}

func (l *listeners[T]) remove(id int) {
	delete(l.fns, id)
	for i, k := range l.ord {
		if k == id {
			l.ord = append(l.ord[:i:i], l.ord[i+1:]...)
			break
		}
	}
}

func (l *listeners[T]) snapshot() []func(T) {
	out := make([]func(T), 0, len(l.ord))
	for _, k := range l.ord {
		out = append(out, l.fns[k])
	}
	return out
}
