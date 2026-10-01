package relay

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/frontierengineer/link/relay/internal/link"
)

func TestHealth(t *testing.T) {
	h := start(t, nil)
	resp, err := http.Get("http://" + h.addr + "/health")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "ok" {
		t.Fatalf("health: %d %q", resp.StatusCode, body)
	}
}

func TestRegistered(t *testing.T) {
	h := start(t, nil)
	p, w := keys(t, 1), keys(t, 2)
	r := roster(t, 12, p, w)
	c := h.dial()
	c.send(h.registerMsg(c, w, p.ID.String(), r))
	m := c.json()
	if m["type"] != "registered" || m["node"] != w.ID.String() || m["rosterVersion"] != float64(12) {
		t.Fatalf("registered: %v", m)
	}
}

// Every check of section 4.1, in order, with its close code.
func TestRegistrationChecks(t *testing.T) {
	p, w, stranger, dropped := keys(t, 1), keys(t, 2), keys(t, 3), keys(t, 5)
	other := keys(t, 4) // another network's primary
	r := roster(t, 5, p, w)
	net := p.ID.String()

	resign := func(h *harness, c *client, m map[string]any, k *link.Keys, network, origin string, challenge []byte, ts int64) {
		m["ts"] = ts
		m["sig"] = b64(ed25519.Sign(k.Ed25519, link.RegisterMessage(network, m["node"].(string), challenge, uint64(ts), origin)))
	}
	now := func() int64 { return time.Now().UnixMilli() }

	cases := []struct {
		name  string
		code  int
		build func(h *harness, c *client) any // a message to send, or a []byte to send as binary
	}{
		// 1. Shape.
		{"not json", 4000, func(h *harness, c *client) any { return "nope" }},
		{"missing sig", 4000, func(h *harness, c *client) any {
			m := h.registerMsg(c, w, net, r)
			delete(m, "sig")
			return m
		}},
		{"ts as string", 4000, func(h *harness, c *client) any {
			m := h.registerMsg(c, w, net, r)
			m["ts"] = "1790000000000"
			return m
		}},
		{"short key", 4000, func(h *harness, c *client) any {
			m := h.registerMsg(c, w, net, r)
			m["ed25519"] = b64(w.Ed25519Public[:31])
			return m
		}},
		{"roster not an object", 4000, func(h *harness, c *client) any {
			m := h.registerMsg(c, w, net, r)
			m["roster"] = "{}"
			return m
		}},
		{"network not an id", 4000, func(h *harness, c *client) any {
			m := h.registerMsg(c, w, "net", r)
			return m
		}},
		{"usage before register", 4000, func(h *harness, c *client) any { return map[string]any{"type": "usage", "id": "1"} }},
		{"frame before register", 4000, func(h *harness, c *client) any { return frame(typeData, p.ID, []byte{0, 0, 0, 1}) }},
		// 2. The node id is derived from the key.
		{"node not derived", 4007, func(h *harness, c *client) any {
			m := h.registerMsg(c, w, net, r)
			m["node"] = stranger.ID.String()
			resign(h, c, m, w, net, h.origin, c.challenge, now())
			return m
		}},
		// 3. The signature.
		{"wrong origin", 4007, func(h *harness, c *client) any {
			m := h.registerMsg(c, w, net, r)
			resign(h, c, m, w, net, "relay.elsewhere", c.challenge, now())
			return m
		}},
		{"wrong challenge", 4007, func(h *harness, c *client) any {
			m := h.registerMsg(c, w, net, r)
			resign(h, c, m, w, net, h.origin, make([]byte, 32), now())
			return m
		}},
		{"signed by another key", 4007, func(h *harness, c *client) any {
			m := h.registerMsg(c, w, net, r)
			resign(h, c, m, stranger, net, h.origin, c.challenge, now())
			return m
		}},
		{"non-canonical signature (S + L)", 4007, func(h *harness, c *client) any {
			m := h.registerMsg(c, w, net, r)
			sig, _ := b64dec(m["sig"].(string))
			m["sig"] = b64(link.NonCanonical(sig))
			return m
		}},
		{"bad signature beats a bad roster", 4007, func(h *harness, c *client) any {
			m := h.registerMsg(c, w, net, r)
			m["roster"] = json.RawMessage(`{"network":"x"}`)
			m["sig"] = b64(make([]byte, 64))
			return m
		}},
		// 4. The time.
		{"stale", 4007, func(h *harness, c *client) any {
			m := h.registerMsg(c, w, net, r)
			resign(h, c, m, w, net, h.origin, c.challenge, now()-300_500)
			return m
		}},
		{"future", 4007, func(h *harness, c *client) any {
			m := h.registerMsg(c, w, net, r)
			resign(h, c, m, w, net, h.origin, c.challenge, now()+300_500)
			return m
		}},
		// 5. The roster.
		{"roster invalid", 4008, func(h *harness, c *client) any {
			var tampered map[string]any
			json.Unmarshal(r, &tampered)
			tampered["version"] = 6
			raw, _ := json.Marshal(tampered)
			return h.registerMsg(c, w, net, raw)
		}},
		{"roster of another network", 4008, func(h *harness, c *client) any {
			return h.registerMsg(c, w, net, roster(t, 1, other, w))
		}},
		// 7. Membership.
		{"not a member", 4008, func(h *harness, c *client) any {
			return h.registerMsg(c, stranger, net, r)
		}},
		{"listed by an older roster but not by the relay's", 4008, func(h *harness, c *client) any {
			return h.registerMsg(c, dropped, net, roster(t, 4, p, w, dropped))
		}},
	}
	h := start(t, nil)
	h.register(p, p, r) // the relay now holds version 5, without dropped
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := h.dial()
			c.t = t
			switch m := tc.build(h, c).(type) {
			case string:
				c.ws.WriteMessage(websocket.TextMessage, []byte(m))
			case []byte:
				c.sendBinary(m)
			default:
				c.send(m)
			}
			c.expectClose(tc.code)
		})
	}
}

func TestReplacedByNewerConnection(t *testing.T) {
	h := start(t, nil)
	p, w := keys(t, 1), keys(t, 2)
	r := roster(t, 1, p, w)
	pc := h.register(p, p, r)
	first := h.register(w, p, r)
	second := h.register(w, p, r)
	first.expectClose(4005)
	// The replacement is the one routed to.
	pc.sendBinary(frame(typeData, w.ID, []byte("hi")))
	if f := second.frame(); string(f[18:]) != "hi" || peerOf(f) != p.ID {
		t.Fatalf("got %q", f)
	}
}

func TestHelloTimeout(t *testing.T) {
	h := start(t, func(c *Config) { c.HelloTimeout = 200 * time.Millisecond })
	h.dial().expectClose(4000)
}

func TestConfiguredOrigin(t *testing.T) {
	h := start(t, func(c *Config) { c.Origin = "Relay.Example" })
	p := keys(t, 1)
	r := roster(t, 1, p)
	h.origin = "relay.example"
	h.register(p, p, r)
	h.origin = h.addr // the Host is not used when LINK_ORIGIN is set
	c := h.dial()
	c.send(h.registerMsg(c, p, p.ID.String(), r))
	c.expectClose(4007)
}

func TestOriginFromHost(t *testing.T) {
	s := &Server{}
	for host, want := range map[string]string{
		"Relay.Example":        "relay.example",
		"relay.example:443":    "relay.example",
		"relay.example:80":     "relay.example",
		"relay.example:8443":   "relay.example:8443",
		"[::1]:443":            "[::1]",
		"[::1]:8080":           "[::1]:8080",
		"EU.frontier.link:443": "eu.frontier.link",
	} {
		r := httptest.NewRequest("GET", "/v1", nil)
		r.Host = host
		if got := s.originOf(r); got != want {
			t.Errorf("%s: got %s want %s", host, got, want)
		}
	}
}

func TestIPRegisterLimit(t *testing.T) {
	h := start(t, func(c *Config) { c.IPRegisterPerMin = 2 })
	p := keys(t, 1)
	r := roster(t, 1, p)
	h.register(p, p, r)
	h.register(p, p, r)
	c := h.dial()
	c.send(h.registerMsg(c, p, p.ID.String(), r))
	if m := c.json(); m["type"] != "error" || m["code"] != "rate_limited" {
		t.Fatalf("got %v", m)
	}
	c.expectClose(4002)
}

func TestIPNetworksLimit(t *testing.T) {
	h := start(t, func(c *Config) { c.IPNetworksPerHour = 1 })
	a, b := keys(t, 1), keys(t, 2)
	h.register(a, a, roster(t, 1, a))
	h.register(a, a, roster(t, 1, a)) // a known network is not new
	c := h.dial()
	c.send(h.registerMsg(c, b, b.ID.String(), roster(t, 1, b)))
	if m := c.json(); m["code"] != "rate_limited" {
		t.Fatalf("got %v", m)
	}
	c.expectClose(4002)
}

func TestConfigFromEnv(t *testing.T) {
	env := map[string]string{
		"LINK_ADDR": "127.0.0.1:9", "LINK_RATE_BPS": "1048576", "LINK_QUOTA_BYTES_HOUR": "5",
		"LINK_TRICKLE_BPS": "16384", "LINK_QUEUE_BYTES": "4194304", "LINK_SLOW_PEER_SEC": "30",
		"LINK_IP_REGISTER_PER_MIN": "60", "LINK_IP_PAIR_PER_MIN": "61", "LINK_IP_NETWORKS_PER_HOUR": "10",
		"LINK_NETWORK_TTL": "168h", "LINK_ORIGIN": "eu.example", "LINK_TRUST_PROXY": "true",
		"LINK_PING_INTERVAL": "250ms", "LINK_PAIR_TIMEOUT": "2", "LINK_HELLO_TIMEOUT": "1s",
	}
	c, err := FromEnv(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr != "127.0.0.1:9" || c.RateBps != 1048576 || c.QuotaBytesHour != 5 || c.TrickleBps != 16384 ||
		c.QueueBytes != 4194304 || c.SlowPeer != 30*time.Second || c.IPRegisterPerMin != 60 ||
		c.IPPairPerMin != 61 || c.IPNetworksPerHour != 10 || c.NetworkTTL != 168*time.Hour ||
		c.Origin != "eu.example" || !c.TrustProxy || c.PingInterval != 250*time.Millisecond ||
		c.PairTimeout != 2*time.Second || c.HelloTimeout != time.Second {
		t.Fatalf("config: %+v", c)
	}
	d, err := FromEnv(func(string) string { return "" })
	if err != nil || d.RateBps != 0 || d.QueueBytes != 0 || d.SlowPeer != 0 || d.Addr != ":8080" || d.NetworkTTL != 168*time.Hour ||
		d.PingInterval != 30*time.Second || d.PairTimeout != 60*time.Second || d.HelloTimeout != 30*time.Second {
		t.Fatalf("defaults: %+v %v", d, err)
	}
	if _, err := FromEnv(func(k string) string {
		if k == "LINK_RATE_BPS" {
			return "fast"
		}
		return ""
	}); err == nil || !strings.Contains(err.Error(), "LINK_RATE_BPS") {
		t.Fatalf("bad value accepted: %v", err)
	}
}

// Rules 6 and 7: membership is judged against the newer of the presented roster and the
// relay's, and a node behind the relay is handed the relay's roster.
func TestEffectiveRoster(t *testing.T) {
	h := start(t, nil)
	p, w, x := keys(t, 1), keys(t, 2), keys(t, 3)
	r2 := roster(t, 2, p, w, x)
	h.register(p, p, r2)

	// A member offline during a change (it holds version 1) is admitted and brought up to
	// date: registered carries the relay's version 2, exactly as the primary signed it.
	c := h.dial()
	c.send(h.registerMsg(c, w, p.ID.String(), roster(t, 1, p, w)))
	m := c.json()
	if m["type"] != "registered" || m["rosterVersion"] != float64(2) {
		t.Fatalf("got %v", m)
	}
	got, _ := json.Marshal(m["roster"])
	var want any
	json.Unmarshal(r2, &want)
	wantJSON, _ := json.Marshal(want)
	if string(got) != string(wantJSON) {
		t.Fatalf("roster in registered:\n%s\nwant\n%s", got, wantJSON)
	}
	if _, err := link.ParseRoster(got); err != nil {
		t.Fatalf("the roster handed over does not verify: %v", err)
	}

	// Presenting the relay's own version: no roster in registered.
	c = h.dial()
	c.send(h.registerMsg(c, x, p.ID.String(), r2))
	if m := c.json(); m["type"] != "registered" || m["roster"] != nil {
		t.Fatalf("got %v", m)
	}

	// A newer presented roster, delivered by a worker, replaces the relay's: x is no longer
	// listed and its connection is closed 4008.
	r3 := roster(t, 3, p, w)
	wc := h.dial()
	wc.send(h.registerMsg(wc, w, p.ID.String(), r3))
	if m := wc.json(); m["type"] != "registered" || m["rosterVersion"] != float64(3) || m["roster"] != nil {
		t.Fatalf("got %v", m)
	}
	c.expectClose(4008)
	// The cache now holds version 3: a node presenting version 2 receives it, and x, listed
	// by version 2 but not by 3, is closed 4008.
	pc := h.dial()
	pc.send(h.registerMsg(pc, p, p.ID.String(), r2))
	if m := pc.json(); m["rosterVersion"] != float64(3) || m["roster"] == nil {
		t.Fatalf("got %v", m)
	}
	xc := h.dial()
	xc.send(h.registerMsg(xc, x, p.ID.String(), r2))
	xc.expectClose(4008)

	// A newer presented roster that does not list the presenter still replaces the relay's
	// (the primary signed it), and the presenter is closed 4008.
	r4 := roster(t, 4, p)
	wc2 := h.dial()
	wc2.send(h.registerMsg(wc2, w, p.ID.String(), r4))
	wc2.expectClose(4008)
	wc.expectClose(4008) // w's registered connection is not on version 4 either
	pc.send(map[string]any{"type": "usage", "id": "v"})
	if u := pc.json(); len(u["members"].([]any)) != 1 {
		t.Fatalf("relay did not adopt version 4: %v", u)
	}
}
