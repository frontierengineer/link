// Command link-driver runs one node of a Link network, steered over stdin and stdout as
// test/drivers/PROTOCOL.md specifies. It is test equipment, not part of the package's API.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sync"
	"time"

	link "github.com/frontierengineer/link/client-go"
)

// The longest command line: a send of 64 MiB, base64, and some.
const maxLine = 96 << 20

type driver struct {
	outMu sync.Mutex
	out   *bufio.Writer

	mu       sync.Mutex
	identity *link.Identity
	node     *link.Member
	autoTake bool
}

func main() {
	d := &driver{out: bufio.NewWriter(os.Stdout)}
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	for {
		line, err := readLine(in)
		if len(bytes.TrimSpace(line)) > 0 && d.dispatch(line) {
			break
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				fmt.Fprintln(os.Stderr, "link-driver: stdin:", err)
			}
			break
		}
	}
	d.shutdown()
	os.Exit(0)
}

func readLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > maxLine {
			return nil, errors.New("line too long")
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if n := len(line); n > 0 && line[n-1] == '\n' {
			line = line[:n-1]
		}
		return line, err
	}
}

// write sends one JSON object as a line.
func (d *driver) write(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintln(os.Stderr, "link-driver: encode:", err)
		return
	}
	d.outMu.Lock()
	defer d.outMu.Unlock()
	d.out.Write(b)
	d.out.WriteByte('\n')
	d.out.Flush()
}

type command struct {
	ID  json.RawMessage `json:"id"`
	Cmd *string         `json:"cmd"`

	Seed             *string         `json:"seed"`
	Relay            string          `json:"relay"`
	Link             string          `json:"link"`
	Network          string          `json:"network"`
	Code             string          `json:"code"`
	CodeID           string          `json:"codeId"`
	TimeoutMs        *int64          `json:"timeoutMs"`
	Role             string          `json:"role"`
	Roster           json.RawMessage `json:"roster"`
	PinnedNetworkKey string          `json:"pinnedNetworkKey"`
	NetworkSeed      *string         `json:"networkSeed"`
	RelayURL         string          `json:"relayUrl"`
	CreditWindow     int64           `json:"creditWindow"`
	Timing           *timing         `json:"timing"`
	AutoTake         *bool           `json:"autoTake"`
	Peer             string          `json:"peer"`
	Bytes            *string         `json:"bytes"`
	Size             *int64          `json:"size"`
	Fill             *int64          `json:"fill"`
	Count            *int            `json:"count"`
	LifetimeMs       int64           `json:"lifetimeMs"`
	Node             string          `json:"node"`
}

type timing struct {
	HandshakeTimeoutMs int64  `json:"handshakeTimeoutMs"`
	RekeyIntervalMs    int64  `json:"rekeyIntervalMs"`
	RekeyMessages      uint64 `json:"rekeyMessages"`
	RetireGraceMs      int64  `json:"retireGraceMs"`
	IdleMs             int64  `json:"idleMs"`
	BackoffInitialMs   int64  `json:"backoffInitialMs"`
	BackoffMaxMs       int64  `json:"backoffMaxMs"`
	RequestTimeoutMs   int64  `json:"requestTimeoutMs"`
}

func (t *timing) toLink() link.Timing {
	if t == nil {
		return link.Timing{}
	}
	ms := func(v int64) time.Duration { return time.Duration(v) * time.Millisecond }
	return link.Timing{
		HandshakeTimeout: ms(t.HandshakeTimeoutMs), RekeyInterval: ms(t.RekeyIntervalMs), RekeyMessages: t.RekeyMessages,
		RetireGrace: ms(t.RetireGraceMs), Idle: ms(t.IdleMs), BackoffInitial: ms(t.BackoffInitialMs),
		BackoffMax: ms(t.BackoffMaxMs), RequestTimeout: ms(t.RequestTimeoutMs),
	}
}

type result map[string]any

// failure is an error reply with a code of the protocol's list.
type failure struct {
	code string
	msg  string
}

func (f *failure) Error() string { return f.msg }

func invalid(format string, a ...any) error {
	return &failure{"invalid", fmt.Sprintf(format, a...)}
}

// reply writes a command's reply once every event the node raised before it is written.
func (d *driver) reply(id json.RawMessage, node *link.Member, res result, err error) {
	if node != nil {
		node.Settle()
	}
	if err != nil {
		body := map[string]any{"code": "internal", "message": err.Error()}
		var le *link.Error
		var f *failure
		switch {
		case errors.As(err, &le):
			body["code"] = string(le.Code)
			if le.Code == link.CodeRefused {
				body["reason"] = le.Reason
			}
		case errors.As(err, &f):
			body["code"] = f.code
		}
		d.write(map[string]any{"id": id, "ok": false, "error": body})
		return
	}
	out := map[string]any{}
	for k, v := range res {
		out[k] = v
	}
	out["id"], out["ok"] = id, true
	d.write(out)
}

// dispatch handles one command line; it reports true for exit. Commands run concurrently,
// except that sends are queued here, in the order they arrive, before they run.
func (d *driver) dispatch(line []byte) bool {
	var c command
	if err := json.Unmarshal(line, &c); err != nil || c.Cmd == nil || !integer(c.ID) {
		fmt.Fprintf(os.Stderr, "link-driver: not a command, no reply: %.200s\n", line)
		return false
	}
	switch *c.Cmd {
	case "exit":
		d.reply(c.ID, nil, result{}, nil)
		return true
	case "send":
		m, done, err := d.startSend(c)
		if err != nil {
			d.reply(c.ID, m, nil, err)
			return false
		}
		go func() { d.reply(c.ID, m, result{}, <-done) }()
		return false
	}
	go func() {
		node, res, err := d.run(c)
		d.reply(c.ID, node, res, err)
	}()
	return false
}

func integer(raw json.RawMessage) bool {
	var f float64
	if len(raw) == 0 || raw[0] == '"' || json.Unmarshal(raw, &f) != nil {
		return false
	}
	return f == math.Trunc(f) && !math.IsInf(f, 0)
}

func (d *driver) shutdown() {
	d.mu.Lock()
	node := d.node
	d.mu.Unlock()
	if node != nil {
		node.Close()
		node.Settle()
	}
	d.outMu.Lock()
	d.out.Flush()
	d.outMu.Unlock()
}

func (d *driver) member() (*link.Member, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.node == nil {
		return nil, invalid("no node: connect or start first")
	}
	return d.node, nil
}

// primary is the node, when it is the primary now.
func (d *driver) primary() (*link.Member, error) {
	m, err := d.member()
	if err != nil {
		return nil, err
	}
	if !m.IsPrimary() {
		return m, invalid("this node is not the primary")
	}
	return m, nil
}

func (d *driver) ident() (*link.Identity, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.identity == nil {
		return nil, invalid("no identity: send identity first")
	}
	return d.identity, nil
}

func rosterValue(r *link.Roster) json.RawMessage {
	b, _ := r.MarshalJSON()
	return b
}

// withTimeout is ctx bounded by timeoutMs when given.
func withTimeout(ms *int64) (context.Context, context.CancelFunc) {
	if ms != nil && *ms >= 0 {
		return context.WithTimeout(context.Background(), time.Duration(*ms)*time.Millisecond)
	}
	return context.WithCancel(context.Background())
}

func timedOut(err error, what string) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return &failure{"timeout", what + " timed out"}
	}
	return err
}

func (d *driver) startSend(c command) (*link.Member, <-chan error, error) {
	m, err := d.member()
	if err != nil {
		return nil, nil, err
	}
	var payload []byte
	switch {
	case c.Bytes != nil:
		if payload, err = base64.StdEncoding.DecodeString(*c.Bytes); err != nil {
			return m, nil, invalid("bytes: %v", err)
		}
	case c.Size != nil && c.Fill != nil:
		if *c.Size < 0 || *c.Fill < 0 {
			return m, nil, invalid("size and fill are non-negative")
		}
		if *c.Size > link.MaxMessage {
			return m, nil, invalid("message exceeds 64 MiB")
		}
		payload = make([]byte, *c.Size)
		for i := range payload {
			payload[i] = byte((*c.Fill + int64(i)*31) % 256)
		}
	default:
		return m, nil, invalid("send needs bytes, or size and fill")
	}
	return m, m.SendAsync(c.Peer, payload), nil
}

func (d *driver) run(c command) (*link.Member, result, error) {
	switch *c.Cmd {
	case "identity":
		var id *link.Identity
		var err error
		if c.Seed != nil {
			seed, e := base64.StdEncoding.DecodeString(*c.Seed)
			if e != nil {
				return nil, nil, invalid("seed: %v", e)
			}
			id, err = link.IdentityFromSeed(seed)
		} else {
			id, err = link.NewIdentity()
		}
		if err != nil {
			return nil, nil, err
		}
		d.mu.Lock()
		d.identity = id
		d.mu.Unlock()
		return nil, result{
			"seed":    base64.StdEncoding.EncodeToString(id.Seed()),
			"node":    id.ID(),
			"ed25519": base64.RawURLEncoding.EncodeToString(id.Ed25519Public()),
		}, nil

	case "createNetwork":
		id, err := d.ident()
		if err != nil {
			return nil, nil, err
		}
		r, seed, err := link.CreateNetwork(id, c.Relay, time.Now(), nil)
		if err != nil {
			return nil, nil, invalid("%v", err)
		}
		return nil, result{"roster": rosterValue(r), "networkSeed": base64.StdEncoding.EncodeToString(seed)}, nil

	case "pair":
		id, err := d.ident()
		if err != nil {
			return nil, nil, err
		}
		opts := link.PairOptions{Identity: id, Link: c.Link}
		if c.Link == "" {
			opts.Target = &link.PairingLink{Network: c.Network, Code: c.Code, CodeID: c.CodeID, Relay: c.Relay}
		}
		if c.TimeoutMs != nil {
			opts.Timeout = time.Duration(*c.TimeoutMs) * time.Millisecond
		}
		res, err := link.Pair(context.Background(), opts)
		if err != nil {
			return nil, nil, err
		}
		return nil, result{"roster": rosterValue(res.Roster), "pinnedNetworkKey": res.PinnedNetworkKey}, nil

	case "connect", "start":
		m, err := d.open(c)
		if err != nil {
			return m, nil, err
		}
		if *c.Cmd == "connect" {
			ctx, cancel := withTimeout(c.TimeoutMs)
			defer cancel()
			if err := m.WaitConnected(ctx); err != nil {
				return m, nil, timedOut(err, "connecting to the relay")
			}
		}
		return m, result{}, nil

	case "waitConnected":
		m, err := d.member()
		if err != nil {
			return nil, nil, err
		}
		ctx, cancel := withTimeout(c.TimeoutMs)
		defer cancel()
		if err := m.WaitConnected(ctx); err != nil {
			return m, nil, timedOut(err, "connecting to the relay")
		}
		return m, result{}, nil

	case "state":
		m, err := d.member()
		if err != nil {
			return nil, nil, err
		}
		return m, result{"state": string(m.State()), "roster": rosterValue(m.Roster()), "primary": m.IsPrimary()}, nil

	case "sessions":
		m, err := d.member()
		if err != nil {
			return nil, nil, err
		}
		list := []map[string]any{}
		for _, s := range m.Sessions(c.Peer) {
			list = append(list, map[string]any{
				"peer": s.Peer, "localIndex": s.LocalIndex, "remoteIndex": s.RemoteIndex, "initiator": s.Initiator, "current": s.Current,
			})
		}
		return m, result{"sessions": list}, nil

	case "take":
		m, err := d.member()
		if err != nil {
			return nil, nil, err
		}
		d.mu.Lock()
		auto := d.autoTake
		d.mu.Unlock()
		if auto {
			return m, nil, invalid("take needs a node started with autoTake false")
		}
		count := 1
		if c.Count != nil {
			count = *c.Count
		}
		if count < 0 {
			return m, nil, invalid("count is negative")
		}
		msgs, err := take(m, count, c.TimeoutMs)
		if err != nil {
			return m, nil, err
		}
		return m, result{"messages": msgs}, nil

	case "syncRoster":
		m, err := d.member()
		if err != nil {
			return nil, nil, err
		}
		if _, err := m.SyncRoster(context.Background()); err != nil {
			return m, nil, err
		}
		return m, result{"roster": rosterValue(m.Roster())}, nil

	case "resign":
		m, err := d.member()
		if err != nil {
			return nil, nil, err
		}
		return m, result{}, m.Resign(context.Background())

	case "traffic":
		m, err := d.member()
		if err != nil {
			return nil, nil, err
		}
		t := m.Traffic()
		return m, result{"since": t.Since, "total": t.Total, "relay": t.Relay, "peers": t.Peers}, nil

	case "resetTraffic":
		m, err := d.member()
		if err != nil {
			return nil, nil, err
		}
		m.ResetTraffic()
		return m, result{}, nil

	case "openPairingCode":
		m, err := d.primary()
		if err != nil {
			return m, nil, err
		}
		pc, err := m.OpenPairingCode(link.PairingCodeOptions{
			Lifetime: time.Duration(c.LifetimeMs) * time.Millisecond, Code: c.Code,
		})
		if err != nil {
			return m, nil, err
		}
		return m, result{"code": pc.Code, "codeId": pc.CodeID, "link": pc.Link, "expiresAt": pc.ExpiresAt.UnixMilli()}, nil

	case "cancelPairingCode":
		m, err := d.primary()
		if err != nil {
			return m, nil, err
		}
		m.CancelPairingCode(c.CodeID)
		return m, result{}, nil

	case "revoke":
		m, err := d.primary()
		if err != nil {
			return m, nil, err
		}
		r, err := m.Revoke(c.Node)
		if err != nil {
			return m, nil, err
		}
		return m, result{"roster": rosterValue(r)}, nil

	case "usage":
		m, err := d.primary()
		if err != nil {
			return m, nil, err
		}
		u, err := m.Usage(context.Background())
		if err != nil {
			return m, nil, err
		}
		return m, result{"network": u.Network}, nil

	case "close":
		m, err := d.member()
		if err != nil {
			return nil, nil, err
		}
		m.Close()
		return m, result{}, nil
	}
	return nil, nil, &failure{"internal", fmt.Sprintf("unknown command %q", *c.Cmd)}
}

// take waits until count messages are waiting, then takes them, oldest first. With a
// timeout it takes nothing when the time runs out; a node that stops first fails with its
// state.
func take(m *link.Member, count int, timeoutMs *int64) ([]map[string]any, error) {
	ctx, cancel := withTimeout(timeoutMs)
	defer cancel()
	for m.Pending() < count {
		switch s := m.State(); s {
		case link.StateRevoked, link.StateReplaced, link.StateClosed:
			return nil, &link.Error{Code: link.ErrorCode(s), Message: "the node is " + string(s)}
		}
		select {
		case <-ctx.Done():
			return nil, &failure{"timeout", "take timed out"}
		case <-time.After(2 * time.Millisecond):
		}
	}
	msgs := []map[string]any{}
	for range count {
		msg, err := m.Receive(context.Background())
		if err != nil {
			return nil, err
		}
		msgs = append(msgs, messageBody(msg))
	}
	return msgs, nil
}

// open creates the node for connect and start. A driver runs one node at a time; a new one
// may replace a node that is closed.
func (d *driver) open(c command) (*link.Member, error) {
	id, err := d.ident()
	if err != nil {
		return nil, err
	}
	if len(c.Roster) == 0 {
		return nil, invalid("a roster is required")
	}
	roster, err := link.DecodeRoster(c.Roster)
	if err != nil {
		return nil, invalid("roster: %v", err)
	}
	auto := c.AutoTake == nil || *c.AutoTake
	var seed []byte
	if c.NetworkSeed != nil {
		if seed, err = base64.StdEncoding.DecodeString(*c.NetworkSeed); err != nil || len(seed) != 32 {
			return nil, invalid("networkSeed must be 32 bytes of base64")
		}
	}
	opts := link.MemberOptions{
		Identity: id, Roster: roster, RelayURL: c.RelayURL, PinnedNetworkKey: c.PinnedNetworkKey,
		NetworkSeed: seed, CreditWindow: c.CreditWindow, Timing: c.Timing.toLink(), OnEvent: d.event,
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.node != nil && d.node.State() != link.StateClosed {
		return nil, invalid("this driver already runs a node; close it first")
	}
	var m *link.Member
	switch c.Role {
	case "primary":
		var p *link.Primary
		if p, err = link.NewPrimary(opts); err == nil {
			m = p.Member
		}
	case "member":
		m, err = link.NewMember(opts)
	default:
		return nil, invalid("role must be member or primary")
	}
	if err != nil {
		return nil, err
	}
	d.node, d.autoTake = m, auto
	if auto {
		m.OnMessage(func(msg link.InboundMessage) { d.write(event("message", messageBody(msg))) })
	} else {
		m.OnArrival(func(msg link.InboundMessage) { d.write(event("message", messageBody(msg))) })
	}
	return m, nil
}

func messageBody(m link.InboundMessage) map[string]any {
	sum := sha256.Sum256(m.Bytes)
	body := map[string]any{"from": m.From, "size": len(m.Bytes), "sha256": hex.EncodeToString(sum[:])}
	if len(m.Bytes) <= 65536 {
		body["bytes"] = base64.StdEncoding.EncodeToString(m.Bytes)
	}
	return body
}

func event(name string, body map[string]any) map[string]any {
	out := map[string]any{"event": name}
	for k, v := range body {
		out[k] = v
	}
	return out
}

func (d *driver) event(e link.Event) {
	switch e := e.(type) {
	case link.StateEvent:
		d.write(event("state", map[string]any{"state": string(e.State)}))
	case link.RosterEvent:
		d.write(event("roster", map[string]any{"roster": rosterValue(e.Roster)}))
	case link.DisconnectEvent:
		d.write(event("disconnect", map[string]any{"code": e.Code, "reason": e.Reason}))
	case link.MovedEvent:
		d.write(event("moved", map[string]any{"network": e.Network}))
	case link.PairedEvent:
		d.write(event("paired", map[string]any{"node": e.Member.ID, "codeId": e.CodeID, "version": e.Roster.Version}))
	case link.PairingFailedEvent:
		d.write(event("pairingFailed", map[string]any{"codeId": e.CodeID, "reason": e.Code}))
	case link.RelayErrorEvent:
		d.write(event("relayError", map[string]any{"code": e.Code, "message": e.Message}))
	}
}
