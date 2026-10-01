package relay

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/frontierengineer/link/relay/internal/link"
)

// sizedRoster is a signed roster of primary and others whose JCS encoding is exactly size
// bytes, padded through its relay URL.
func sizedRoster(t *testing.T, version, size int, primary *link.Keys, others ...*link.Keys) []byte {
	t.Helper()
	build := func(relay string) ([]byte, int) {
		ms := []any{map[string]any{"id": primary.ID.String(), "ed25519": b64(primary.Ed25519Public), "x25519": b64(primary.X25519Public), "kind": link.KindPrimary}}
		for _, o := range others {
			ms = append(ms, map[string]any{"id": o.ID.String(), "ed25519": b64(o.Ed25519Public), "x25519": b64(o.X25519Public), "kind": link.KindWorker})
		}
		slices.SortFunc(ms, func(a, b any) int {
			return compareStr(a.(map[string]any)["id"].(string), b.(map[string]any)["id"].(string))
		})
		r := map[string]any{
			"network": primary.ID.String(), "version": version, "issuedAt": time.Now().UnixMilli(),
			"relay": relay, "primary": map[string]any{"ed25519": b64(primary.Ed25519Public)}, "members": ms,
		}
		if err := link.SignRoster(r, primary.Ed25519); err != nil {
			t.Fatal(err)
		}
		canon, err := link.Canonicalize(r)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(r)
		return raw, len(canon)
	}
	_, base := build("")
	raw, n := build(strings.Repeat("x", size-base))
	if n != size {
		t.Fatalf("built %d bytes, want %d", n, size)
	}
	return raw
}

// A roster over 65000 bytes is invalid at registration (4008) and when pushed (bad_request);
// one of exactly 65000 is accepted both ways.
func TestRosterSizeLimitAtTheRelay(t *testing.T) {
	h := start(t, nil)
	p, w := keys(t, 1), keys(t, 2)

	c := h.dial()
	c.send(h.registerMsg(c, p, p.ID.String(), sizedRoster(t, 1, link.MaxRosterBytes+1, p, w)))
	c.expectClose(4008)

	pc := h.register(p, p, sizedRoster(t, 1, link.MaxRosterBytes, p, w))
	pc.send(map[string]any{"type": "roster", "roster": json.RawMessage(sizedRoster(t, 2, link.MaxRosterBytes+1, p, w))})
	if m := pc.json(); m["type"] != "error" || m["code"] != "bad_request" || !strings.Contains(m["message"].(string), "limit") {
		t.Fatalf("oversize push answered %v", m)
	}
	// The relay still holds v1: a worker presenting it registers, and is not handed anything newer.
	wc := h.dial()
	wc.send(h.registerMsg(wc, w, p.ID.String(), sizedRoster(t, 1, link.MaxRosterBytes, p, w)))
	if m := wc.json(); m["type"] != "registered" || m["rosterVersion"] != float64(1) || m["roster"] != nil {
		t.Fatalf("got %v", m)
	}
	pc.send(map[string]any{"type": "roster", "roster": json.RawMessage(sizedRoster(t, 2, link.MaxRosterBytes, p, w))})
	pc.quiet(200 * time.Millisecond)
}

// LINK_ORIGIN follows the same rule as Host: 80 and 443 are dropped (section 4.1).
func TestConfiguredOriginDropsDefaultPorts(t *testing.T) {
	for origin, want := range map[string]string{
		"Relay.Example:443":  "relay.example",
		"relay.example:80":   "relay.example",
		"relay.example:8443": "relay.example:8443",
		"[::1]:443":          "[::1]",
	} {
		s := &Server{cfg: Config{Origin: origin}}
		if got := s.originOf(nil); got != want {
			t.Errorf("LINK_ORIGIN=%s: got %s want %s", origin, got, want)
		}
	}
}
