package relay

// The tests start the real relay on a random port and drive it with real WebSocket clients
// (gorilla/websocket, a different implementation from the relay's).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/frontierengineer/link/relay/internal/link"
)

type harness struct {
	t      *testing.T
	s      *Server
	addr   string
	origin string
}

func start(t *testing.T, tune func(*Config)) *harness {
	t.Helper()
	cfg := Defaults()
	cfg.CloseGrace = 3 * time.Second
	if tune != nil {
		tune(&cfg)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg)
	go s.Serve(ln)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.Shutdown(ctx)
	})
	return &harness{t: t, s: s, addr: ln.Addr().String(), origin: ln.Addr().String()}
}

func keys(t testing.TB, i byte) *link.Keys {
	k, err := link.DeriveKeys(bytes.Repeat([]byte{i}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func b64(b []byte) string { return link.B64u.EncodeToString(b) }

// roster makes a roster signed by primary, listing it and the others as workers.
func roster(t testing.TB, version int, primary *link.Keys, others ...*link.Keys) []byte {
	t.Helper()
	member := func(k *link.Keys, kind string) map[string]any {
		return map[string]any{"id": k.ID.String(), "ed25519": b64(k.Ed25519Public), "x25519": b64(k.X25519Public), "kind": kind}
	}
	ms := []map[string]any{member(primary, link.KindPrimary)}
	for _, o := range others {
		ms = append(ms, member(o, link.KindWorker))
	}
	slices.SortFunc(ms, func(a, b map[string]any) int { return compareStr(a["id"].(string), b["id"].(string)) })
	members := make([]any, len(ms))
	for i, m := range ms {
		members[i] = m
	}
	r := map[string]any{
		"network": primary.ID.String(), "version": version, "issuedAt": time.Now().UnixMilli(),
		"relay": "wss://relay.test/v1", "primary": map[string]any{"ed25519": b64(primary.Ed25519Public)},
		"members": members,
	}
	if err := link.SignRoster(r, primary.Ed25519); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(r)
	return raw
}

func compareStr(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

type client struct {
	t         testing.TB
	ws        *websocket.Conn
	challenge []byte
}

type dialOpt func(*net.Dialer)

// smallBuffers shrinks the client's socket buffers, so a client that stops reading fills
// its share of the path quickly.
func smallBuffers(d *net.Dialer) {
	d.Control = func(_, _ string, rc syscall.RawConn) error {
		return rc.Control(func(fd uintptr) {
			syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 32<<10)
			syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 32<<10)
		})
	}
}

func (h *harness) dial(opts ...dialOpt) *client {
	h.t.Helper()
	nd := &net.Dialer{}
	for _, o := range opts {
		o(nd)
	}
	d := websocket.Dialer{NetDialContext: nd.DialContext, HandshakeTimeout: 5 * time.Second}
	ws, _, err := d.Dial("ws://"+h.addr+"/v1", nil)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { ws.Close() })
	c := &client{t: h.t, ws: ws}
	hello := c.json()
	if hello["type"] != "hello" || hello["version"] != float64(1) {
		h.t.Fatalf("hello: %v", hello)
	}
	c.challenge, _ = link.B64u.DecodeString(hello["challenge"].(string))
	if len(c.challenge) != 32 {
		h.t.Fatalf("challenge is %d bytes", len(c.challenge))
	}
	return c
}

// registerMsg builds a correct register message; tests break one thing at a time.
func (h *harness) registerMsg(c *client, k *link.Keys, network string, rosterJSON []byte) map[string]any {
	ts := time.Now().UnixMilli()
	sig := ed25519.Sign(k.Ed25519, link.RegisterMessage(network, k.ID.String(), c.challenge, uint64(ts), h.origin))
	return map[string]any{
		"type": "register", "network": network, "node": k.ID.String(), "ed25519": b64(k.Ed25519Public),
		"ts": ts, "sig": b64(sig), "roster": json.RawMessage(rosterJSON),
	}
}

// register connects k as a member of the network in rosterJSON and waits for registered.
func (h *harness) register(k *link.Keys, network *link.Keys, rosterJSON []byte, opts ...dialOpt) *client {
	h.t.Helper()
	c := h.dial(opts...)
	c.send(h.registerMsg(c, k, network.ID.String(), rosterJSON))
	m := c.json()
	if m["type"] != "registered" || m["node"] != k.ID.String() {
		h.t.Fatalf("expected registered, got %v", m)
	}
	return c
}

func (c *client) send(v any) {
	c.t.Helper()
	if err := c.ws.WriteJSON(v); err != nil {
		c.t.Fatal(err)
	}
}

func (c *client) sendBinary(b []byte) {
	c.t.Helper()
	if err := c.ws.WriteMessage(websocket.BinaryMessage, b); err != nil {
		c.t.Fatal(err)
	}
}

func (c *client) next(timeout time.Duration) (int, []byte, error) {
	c.ws.SetReadDeadline(time.Now().Add(timeout))
	return c.ws.ReadMessage()
}

func (c *client) json() map[string]any {
	c.t.Helper()
	typ, b, err := c.next(5 * time.Second)
	if err != nil {
		c.t.Fatalf("expected a message: %v", err)
	}
	if typ != websocket.TextMessage {
		c.t.Fatalf("expected text, got a %d-byte binary frame", len(b))
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		c.t.Fatal(err)
	}
	return m
}

func (c *client) frame() []byte {
	c.t.Helper()
	typ, b, err := c.next(5 * time.Second)
	if err != nil {
		c.t.Fatalf("expected a frame: %v", err)
	}
	if typ != websocket.BinaryMessage {
		c.t.Fatalf("expected binary, got %s", b)
	}
	return b
}

// closeCode reads until the connection ends and returns the close code: 1006 when it
// ended without a close frame (gorilla's report of that), -1 on any other error.
func (c *client) closeCode(timeout time.Duration) int {
	c.t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		c.ws.SetReadDeadline(deadline)
		_, _, err := c.ws.ReadMessage()
		if err == nil {
			continue
		}
		var ce *websocket.CloseError
		if errors.As(err, &ce) {
			return ce.Code
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			c.t.Fatalf("connection still open after %v", timeout)
		}
		return -1
	}
}

func (c *client) expectClose(code int) {
	c.t.Helper()
	if got := c.closeCode(5 * time.Second); got != code {
		c.t.Fatalf("closed %d, want %d", got, code)
	}
}

// quiet asserts nothing arrives for d.
func (c *client) quiet(d time.Duration) {
	c.t.Helper()
	typ, b, err := c.next(d)
	if err == nil {
		c.t.Fatalf("unexpected message (type %d): %q", typ, b[:min(len(b), 80)])
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		c.t.Fatalf("connection ended: %v", err)
	}
}

func frame(typ byte, peer link.ID, body []byte) []byte {
	f := append([]byte{1, typ}, peer[:]...)
	return append(f, body...)
}

func peerOf(f []byte) link.ID {
	var id link.ID
	copy(id[:], f[2:18])
	return id
}

// queuedFor reads, from the relay's own state, the bytes queued for a connected node.
func (s *Server) queuedFor(network, node link.ID) int64 {
	s.mu.Lock()
	n := s.networks[network]
	s.mu.Unlock()
	if n == nil {
		return 0
	}
	n.mu.Lock()
	c := n.members[node]
	n.mu.Unlock()
	if c == nil {
		return 0
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.queued
}
