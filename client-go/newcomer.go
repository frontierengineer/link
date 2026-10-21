package link

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// The newcomer's side of pairing (sections 5.2 and 5.3): find the primary through the relay,
// prove the code with SPAKE2, hand over the node's keys and receive the roster that
// includes it.

// PairOptions configures Pair. Give Link, or Target.
type PairOptions struct {
	Link     string       // a frontier://pair?... link
	Target   *PairingLink // or its parts; the code in any spelling NormalizeCode accepts
	Identity *Identity
	// Timeout bounds the whole exchange (60 s, the relay's channel lifetime).
	Timeout time.Duration

	dial socketDialer // tests
}

// PairResult is what pairing yields. Persist both with the identity.
type PairResult struct {
	Roster *Roster // the roster that includes this node
	// PinnedNetworkKey is the network key, pinned from the roster.
	PinnedNetworkKey string
}

type pairEvent struct {
	text bool
	data []byte
	err  error
}

// Pair pairs the identity into the network the link names. It fails with a pairing error,
// unreachable (the primary is not connected) or timeout.
func Pair(ctx context.Context, opts PairOptions) (*PairResult, error) {
	var target PairingLink
	var err error
	switch {
	case opts.Link != "":
		target, err = ParsePairingLink(opts.Link)
	case opts.Target != nil:
		target = *opts.Target
		target.Code, err = NormalizeCode(target.Code)
	default:
		err = fmt.Errorf("a link or a target is required")
	}
	if err != nil {
		return nil, pairingError(err.Error())
	}
	if opts.Identity == nil {
		return nil, invalidError("an identity is required")
	}
	codeID, err := fromB64uLen(target.CodeID, codeIDLength, "code id")
	if err != nil {
		return nil, pairingError(err.Error())
	}
	ex, err := newNewcomerExchange(target.Code, codeID, nil)
	if err != nil {
		return nil, pairingError(err.Error())
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = PairingChannelTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dial := opts.dial
	if dial == nil {
		dial = dialWebSocket
	}
	u, err := normalizeRelayURL(target.Relay)
	if err != nil {
		return nil, pairingError(err.Error())
	}
	sock, err := dial(ctx, u.String())
	if err != nil {
		if ctx.Err() != nil {
			return nil, timeoutOr(ctx.Err(), "pairing")
		}
		return nil, pairingError(fmt.Sprintf("the relay ended pairing (close %d) before it finished", 1006))
	}
	defer func() {
		sock.WriteClose(CloseNormal)
		sock.Close()
	}()
	events := make(chan pairEvent)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			text, data, err := sock.Read()
			select {
			case events <- pairEvent{text: text, data: data, err: err}:
			case <-stop:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	p := &newcomerRun{ex: ex, sock: sock, target: target, id: opts.Identity, stage: "hello"}
	for {
		select {
		case <-ctx.Done():
			return nil, timeoutOr(ctx.Err(), "pairing")
		case ev := <-events:
			res, err := p.step(ev)
			if err != nil || res != nil {
				return res, err
			}
		}
	}
}

type newcomerRun struct {
	ex      *newcomerExchange
	sock    socket
	target  PairingLink
	id      *Identity
	stage   string // hello, pairing, p2, p4, p6
	channel []byte
}

func (p *newcomerRun) sendPair(body []byte) error {
	var peer [16]byte
	copy(peer[:], p.channel)
	f, err := encodeFrame(framePair, peer, body)
	if err != nil {
		return err
	}
	return p.sock.Write(false, f)
}

// step takes one event from the relay; it returns a result or an error when pairing ends.
func (p *newcomerRun) step(ev pairEvent) (*PairResult, error) {
	if ev.err != nil {
		code := 1006
		if ce, ok := ev.err.(*closeError); ok {
			code = ce.code
		}
		if p.stage == "p4" {
			return nil, pairingError("the primary rejected the code")
		}
		return nil, pairingError(fmt.Sprintf("the relay ended pairing (close %d) before it finished", code))
	}
	if ev.text {
		msg, ok := parseControl(ev.data)
		if !ok {
			return nil, nil
		}
		switch {
		case msg.typ() == "hello" && p.stage == "hello":
			if v, ok := safeInteger(msg["version"]); !ok || v != 1 {
				return nil, pairingError(fmt.Sprintf("relay speaks version %v", msg["version"]))
			}
			p.stage = "pairing"
			b, _ := json.Marshal(map[string]string{"type": "pair", "network": p.target.Network, "code": p.target.CodeID})
			if err := p.sock.Write(true, b); err != nil {
				return nil, pairingError("the relay ended pairing before it finished")
			}
		case msg.typ() == "pairing" && p.stage == "pairing":
			ch, err := fromB64uLen(msg.str("channel"), 16, "channel")
			if err != nil {
				return nil, pairingError(err.Error())
			}
			p.channel = ch
			p.stage = "p2"
			if err := p.sendPair(p.ex.p1()); err != nil {
				return nil, pairingError("the relay ended pairing before it finished")
			}
		case msg.typ() == "pairEnd" && p.stage != "hello":
			if p.stage == "p4" {
				return nil, pairingError("the primary rejected the code")
			}
			return nil, pairingError("the primary ended pairing before it finished")
		case msg.typ() == "error":
			if msg.str("code") == "unreachable" {
				return nil, unreachableError(p.target.Network)
			}
			return nil, pairingError(fmt.Sprintf("relay answered %v", msg["code"]))
		}
		return nil, nil
	}
	f, err := decodeFrame(ev.data)
	if err != nil || f.typ != framePair || p.channel == nil || !bytes.Equal(f.peer[:], p.channel) {
		return nil, nil
	}
	fail := func(err error) (*PairResult, error) {
		if e, ok := err.(*Error); ok && e.Code == CodePairing {
			return nil, e
		}
		return nil, pairingError(err.Error())
	}
	switch p.stage {
	case "p2":
		p.stage = "p4"
		cA, err := p.ex.onP2(f.body)
		if err != nil {
			return fail(err)
		}
		if err := p.sendPair(cA); err != nil {
			return fail(err)
		}
	case "p4":
		p.stage = "p6"
		p5, err := p.ex.onP4(f.body, newcomerKeys{ed25519: p.id.edPub, x25519: p.id.xPub[:]})
		if err != nil {
			return fail(err)
		}
		if err := p.sendPair(p5); err != nil {
			return fail(err)
		}
	case "p6":
		r, err := p.ex.onP6(f.body)
		if err != nil {
			return fail(err)
		}
		return checkPairedRoster(r, p.target.Network, p.id)
	}
	return nil, nil
}

func checkPairedRoster(r *Roster, network string, id *Identity) (*PairResult, error) {
	if err := r.Problem(); err != nil {
		return nil, pairingError("the primary sent an invalid roster: " + err.Error())
	}
	if r.Network != network {
		return nil, pairingError("the roster is for a different network")
	}
	me := r.member(id.ID())
	if me == nil || me.Ed25519 != b64u(id.edPub) || me.X25519 != b64u(id.xPub[:]) {
		return nil, pairingError("the roster does not list this node with its keys")
	}
	return &PairResult{Roster: r.Clone(), PinnedNetworkKey: r.NetworkKey}, nil
}
