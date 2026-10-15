package link

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// The member's connection to its relay (sections 4.1, 10, 11): hello, a signed register,
// registered; reconnect with backoff forever, except after 4008 or 4005. Every method runs
// with the member's lock held.

// Close codes (section 10).
const (
	CloseNormal             = 1000
	CloseGoingAway          = 1001
	CloseBadRequest         = 4000
	CloseRateLimited        = 4002
	CloseReplaced           = 4005
	CloseSlowPeer           = 4006
	CloseRegistrationFailed = 4007
	CloseNotMember          = 4008
	CloseMoved              = 4009
)

type relayConn struct {
	m        *Member
	url      string
	state    State
	ch       *channel
	gen      int // dial generation: results of an older dial are ignored
	cancel   context.CancelFunc
	timer    *mtimer
	backoff  time.Duration
	features map[string]bool

	challenge []byte // of the current connection, once hello arrived

	// UTF-8 bytes of control messages sent and received, over every connection.
	textSent, textReceived int64

	drainWaiters []func()
	stopping     bool // a terminal state is being entered

	regTimer  *mtimer // registration must complete in time
	liveTimer *mtimer // the relay must be heard from
}

func (r *relayConn) terminal() bool {
	return r.state == StateClosed || r.state == StateRevoked || r.state == StateReplaced
}

func (r *relayConn) start() {
	if r.state == StateDisconnected && !r.stopping {
		r.dial()
	}
}

func (r *relayConn) setState(s State) {
	if r.state == s {
		return
	}
	r.state = s
	r.m.onRelayState(s)
}

// writable: data may be handed to the socket now (little waits in it, or there is no socket
// and a send fails at once).
func (r *relayConn) writable() bool { return r.ch == nil || r.ch.writable() }

func (r *relayConn) bufferedAmount() int {
	if r.ch == nil {
		return 0
	}
	return r.ch.bufferedAmount()
}

// whenWritable calls f once data may be handed to the socket again (at once, as a task,
// if it may now).
func (r *relayConn) whenWritable(f func()) {
	if r.ch == nil || !r.ch.wantDrain() {
		r.m.later(f)
		return
	}
	r.drainWaiters = append(r.drainWaiters, f)
}

func (r *relayConn) drained(ch *channel) {
	if ch != r.ch && r.ch != nil {
		return
	}
	if r.ch != nil && !r.ch.writable() {
		r.ch.wantDrain()
		return
	}
	ws := r.drainWaiters
	r.drainWaiters = nil
	for _, f := range ws {
		f()
	}
}

// sendBinary hands a frame over only once registered.
func (r *relayConn) sendBinary(b []byte) bool {
	return r.state == StateConnected && r.ch != nil && r.queue(false, b)
}

// sendControl sends a control message once registered.
func (r *relayConn) sendControl(msg []byte) bool {
	if r.state != StateConnected || r.ch == nil || len(msg) > maxControlBytes {
		return false
	}
	if !r.queue(true, msg) {
		return false
	}
	r.textSent += int64(len(msg))
	return true
}

// queue hands a message to the channel. One that overflows its bound is given up, as a task
// (the caller may be part-way through a session's state), and redialled.
func (r *relayConn) queue(text bool, b []byte) bool {
	ch := r.ch
	if ch.send(text, b) {
		return true
	}
	if ch.overflowed() {
		r.m.later(func() {
			if r.ch == ch {
				r.abandon(ch, "the outbound queue overflowed")
			}
		})
	}
	return false
}

func (r *relayConn) close() {
	if r.state == StateClosed {
		return
	}
	r.stop(StateClosed)
}

// revoke enters the terminal revoked state (also when a roster drops this node).
func (r *relayConn) revoke() {
	if r.terminal() {
		return
	}
	r.stop(StateRevoked)
}

// stop closes the connection for good and enters the terminal state s. The close is reported
// (DisconnectEvent) before the state, as for a close the relay makes; the TypeScript client
// reports the state first.
func (r *relayConn) stop(s State) {
	r.timer.cancel()
	r.cancelDial()
	r.stopping = true
	r.closeChannel(CloseNormal)
	r.setState(s)
}

func (r *relayConn) cancelDial() {
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
}

// closeChannel closes the current connection with code and reports the close at once, as
// the TypeScript client's Channel does; the socket's own report is ignored afterwards.
func (r *relayConn) closeChannel(code int) {
	ch := r.ch
	if ch == nil {
		return
	}
	ch.close(code)
	r.onClose(ch, code, "")
}

func (r *relayConn) dial() {
	r.setState(StateConnecting)
	if r.state != StateConnecting {
		return // a listener closed the member
	}
	r.features = map[string]bool{}
	r.challenge = nil
	r.gen++
	gen := r.gen
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	url := r.url
	m := r.m
	go func() {
		sock, err := m.dial(ctx, url)
		m.lock()
		defer m.unlock()
		if gen != r.gen || r.state != StateConnecting || r.ch != nil {
			if sock != nil {
				sock.Close()
			}
			return
		}
		if err != nil {
			// A connection that never opened reports 1006, as a browser's does.
			r.afterDialFailure(err)
			return
		}
		var ch *channel
		ch = newChannel(sock, func() {
			m.lock()
			r.drained(ch)
			m.unlock()
		})
		r.ch = ch
		// Budgets, the roster coalescing state and the hint time carry over from the last
		// connection: a relay that forces reconnects gets nothing fresh for it.
		r.heard(ch)
		sock.OnPing(func() { r.heard(ch) })
		// A relay that opens the connection and then says nothing (no hello, or no
		// registered) is left like one that closed it: the member reconnects.
		r.regTimer = m.after(registrationTimeout(m.timing), func() {
			if r.ch == ch && r.state == StateConnecting {
				r.abandon(ch, "the relay did not complete registration")
			}
		})
		r.watchLiveness(ch)
		go r.read(ch)
	}()
}

// registrationTimeout is how long hello and registered may take, from the connection opening:
// the request timeout, and at least ten seconds.
func registrationTimeout(t Timing) time.Duration { return max(t.RequestTimeout, 10*time.Second) }

// relaySilence: the relay pings every 30 seconds (section 9), so a connection over which
// nothing at all arrives for two and a half of its intervals is taken for dead.
const relaySilence = 75 * time.Second

// heard notes that the relay was heard from over ch. It takes no lock: it runs for every
// frame, ping and pong.
func (r *relayConn) heard(ch *channel) { ch.lastRead.Store(int64(r.m.clock.Mono())) }

// watchLiveness checks, a few times per silence period, that the relay was heard from
// lately, and abandons the connection when it was not.
func (r *relayConn) watchLiveness(ch *channel) {
	silence := r.m.liveness
	if silence < 0 {
		return
	}
	if silence == 0 {
		silence = relaySilence
	}
	var check func()
	check = func() {
		if r.ch != ch {
			return
		}
		if quiet := r.m.clock.Mono() - time.Duration(ch.lastRead.Load()); quiet >= silence {
			r.abandon(ch, fmt.Sprintf("nothing heard from the relay for %s", quiet.Round(time.Second)))
			return
		}
		r.liveTimer = r.m.after(silence/5, check)
	}
	r.liveTimer = r.m.after(silence/5, check)
}

// abandon gives up on a connection this side finds dead: it sends a close and reports the
// close as 1006 (abnormal), after which the member reconnects as after any failed connection.
func (r *relayConn) abandon(ch *channel, reason string) {
	ch.close(CloseNormal)
	r.onClose(ch, 1006, reason)
}

func (r *relayConn) afterDialFailure(err error) {
	r.cancel = nil
	r.m.emit(DisconnectEvent{Code: 1006, Reason: err.Error()})
	r.afterClose(1006)
}

// read is the connection's reader goroutine: each message is handled under the lock, in
// order.
func (r *relayConn) read(ch *channel) {
	m := r.m
	for {
		text, data, err := ch.sock.Read()
		r.heard(ch)
		m.lock()
		if r.ch != ch {
			m.unlock()
			ch.abort()
			return
		}
		if err != nil {
			code, reason := 1006, err.Error()
			if ce, ok := err.(*closeError); ok {
				code, reason = ce.code, ce.reason
			}
			ch.abort()
			r.onClose(ch, code, reason)
			m.unlock()
			return
		}
		if text {
			r.onText(ch, data)
		} else if r.state == StateConnected {
			m.onBinary(data)
		}
		m.unlock()
	}
}

// controlMessage is a parsed text message: an object with a string type.
type controlMessage map[string]any

func (c controlMessage) typ() string { return c.str("type") }

func (c controlMessage) str(k string) string {
	s, _ := c[k].(string)
	return s
}

func parseControl(data []byte) (controlMessage, bool) {
	if len(data) > maxControlBytes {
		return nil, false
	}
	tree, err := parseJSON(data)
	if err != nil {
		return nil, false
	}
	obj, ok := tree.(map[string]any)
	if !ok {
		return nil, false
	}
	if _, ok := obj["type"].(string); !ok {
		return nil, false
	}
	return controlMessage(obj), true
}

func (r *relayConn) onText(ch *channel, data []byte) {
	r.textReceived += int64(len(data))
	msg, ok := parseControl(data)
	if !ok {
		return
	}
	switch {
	case msg.typ() == "hello" && r.challenge == nil:
		if v, ok := safeInteger(msg["version"]); !ok || v != 1 {
			r.closeChannel(CloseBadRequest)
			return
		}
		challenge, err := fromB64uLen(msg.str("challenge"), 32, "challenge")
		if err != nil {
			r.closeChannel(CloseBadRequest)
			return
		}
		r.challenge = challenge
		// Names this client does not know are ignored; a missing list is empty.
		if fs, ok := msg["features"].([]any); ok {
			for _, f := range fs {
				if s, ok := f.(string); ok {
					r.features[s] = true
				}
			}
		}
		reg, err := r.registerMessage(challenge)
		if err != nil || len(reg) > maxControlBytes {
			r.closeChannel(CloseBadRequest)
			return
		}
		if ch.send(true, reg) {
			r.textSent += int64(len(reg))
		}
	case msg.typ() == "registered" && r.challenge != nil && r.state == StateConnecting:
		r.backoff = r.m.timing.BackoffInitial
		r.regTimer.cancel()
		// A newer roster in registered is applied before anything is sent under it. A roster
		// that drops this node revokes it there, and then it stays revoked (only a hostile
		// relay sends registered with such a roster: a real one closes 4008).
		r.m.onRegistered(msg)
		if r.state == StateConnecting && r.ch == ch {
			r.setState(StateConnected)
		}
	case r.state == StateConnected || msg.typ() == "error":
		r.m.onControl(msg)
	}
}

func (r *relayConn) registerMessage(challenge []byte) ([]byte, error) {
	m := r.m
	roster := m.roster
	origin, err := originOf(r.url)
	if err != nil {
		return nil, err
	}
	ts := m.clock.Now().UnixMilli()
	sig := m.identity.Sign(registerSigningBytes(roster.Network, m.identity.ID(), challenge, ts, origin))
	rj, err := roster.MarshalJSON()
	if err != nil {
		return nil, err
	}
	head, err := json.Marshal(struct {
		Type    string `json:"type"`
		Network string `json:"network"`
		Node    string `json:"node"`
		Ed25519 string `json:"ed25519"`
		TS      int64  `json:"ts"`
		Sig     string `json:"sig"`
	}{"register", roster.Network, m.identity.ID(), b64u(m.identity.edPub), ts, b64u(sig)})
	if err != nil {
		return nil, err
	}
	out := append(head[:len(head)-1], `,"roster":`...)
	out = append(out, rj...)
	return append(out, '}'), nil
}

func (r *relayConn) onClose(ch *channel, code int, reason string) {
	if r.ch != ch {
		return
	}
	r.ch = nil
	r.cancel = nil
	r.regTimer.cancel()
	r.liveTimer.cancel()
	ws := r.drainWaiters
	r.drainWaiters = nil
	for _, f := range ws {
		r.m.later(f) // whoever waits to write learns at once that the socket is gone
	}
	r.m.emit(DisconnectEvent{Code: code, Reason: reason})
	r.afterClose(code)
}

func (r *relayConn) afterClose(code int) {
	if r.terminal() || r.stopping {
		return
	}
	if code == CloseNotMember {
		r.setState(StateRevoked)
		return
	}
	if code == CloseReplaced {
		// Section 11: a newer copy of this identity holds the connection; stop rather than
		// fight it.
		r.setState(StateReplaced)
		return
	}
	r.setState(StateDisconnected)
	if code == CloseMoved {
		network := r.m.roster.Network
		r.m.emit(MovedEvent{Network: network})
		if resolve := r.m.resolveRelay; resolve != nil {
			gen := r.gen
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), r.m.timing.RequestTimeout)
				url, err := resolve(ctx, network)
				cancel()
				r.m.lock()
				defer r.m.unlock()
				if gen != r.gen {
					return
				}
				if err == nil && url != "" {
					if _, err := normalizeRelayURL(url); err == nil {
						r.url = url
					}
				}
				r.schedule()
			}()
			return
		}
	}
	r.schedule()
}

func (r *relayConn) schedule() {
	if r.state != StateDisconnected {
		return
	}
	delay := r.backoff
	r.backoff = min(r.backoff*2, r.m.timing.BackoffMax)
	r.timer.cancel()
	r.timer = r.m.after(delay, func() {
		if r.state == StateDisconnected {
			r.dial()
		}
	})
}

func (r *relayConn) String() string {
	return fmt.Sprintf("relay %s (%s)", r.url, r.state)
}
