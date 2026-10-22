package relay

import (
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/frontierengineer/link/relay/internal/link"
)

// startWithLimits starts a relay whose LINK_LIMITS_FILE holds doc, and its admin API.
func startWithLimits(t *testing.T, doc string, tune func(*Config)) (*harness, *httptest.Server, string) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "limits.json")
	if err := os.WriteFile(file, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	h := start(t, func(c *Config) {
		c.LimitsFile = file
		if tune != nil {
			tune(c)
		}
	})
	if err := h.s.ReloadLimits(); err != nil {
		t.Fatal(err)
	}
	admin := httptest.NewServer(h.s.AdminHandler())
	t.Cleanup(admin.Close)
	return h, admin, file
}

// dialHost dials the relay with host as the Host header: the origin the member signs.
func (h *harness) dialHost(host string) *client {
	h.t.Helper()
	d := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	ws, _, err := d.Dial("ws://"+h.addr+"/v1", http.Header{"Host": {host}})
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { ws.Close() })
	c := &client{t: h.t, ws: ws}
	hello := c.json()
	c.challenge, _ = link.B64u.DecodeString(hello["challenge"].(string))
	return c
}

// registerHost registers k, dialling host.
func (h *harness) registerHost(host string, k, network *link.Keys, rosterJSON []byte) *client {
	h.t.Helper()
	c := h.dialHost(host)
	ts := time.Now().UnixMilli()
	sig := ed25519.Sign(k.Ed25519, link.RegisterMessage(netID(network), k.ID.String(), c.challenge, uint64(ts), normalOrigin(host)))
	c.send(map[string]any{
		"type": "register", "network": netID(network), "node": k.ID.String(), "ed25519": b64(k.Ed25519Public),
		"ts": ts, "sig": b64(sig), "roster": json.RawMessage(rosterJSON),
	})
	if m := c.json(); m["type"] != "registered" {
		h.t.Fatalf("expected registered, got %v", m)
	}
	c.shapingNotice()
	return c
}

func usageLimitsOf(t *testing.T, c *client, id string) map[string]any {
	t.Helper()
	c.send(map[string]any{"type": "usage", "id": id})
	m := c.json()
	if m["type"] != "usage" {
		t.Fatalf("usage: %v", m)
	}
	return m["network"].(map[string]any)["limits"].(map[string]any)
}

func limitsWant(rate, quota, trickle float64) map[string]any {
	return map[string]any{"rateBps": rate, "quotaBytesHour": quota, "trickleBps": trickle}
}

func post(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Post(url, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func get(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestLimitsFileRefusals(t *testing.T) {
	for _, doc := range []string{
		`{"rateBps":-1}`,
		`{"origins":{"a.test":{"trickleBps":-5}}}`,
		`{"rateBPS":1}`,                 // unknown field
		`{"origins":{"A.test":{}}}`,     // not lowercase
		`{"origins":{"a.test:443":{}}}`, // the port a member never signs
		`{"origins":{"":{}}}`,
		`{"origins":{"a.test/x":{}}}`,
		`{"origins":{"ä.test":{}}}`,
		`{"rateBps":1}{}`, // trailing data
		`{"rateBps":1.5}`,
		`[]`,
		`{"origins":{"a.test":{},"a.test":{}}}`, // repeated name
	} {
		var f limitsFile
		if decodeLimitsFile([]byte(doc), &f) == nil {
			t.Errorf("accepted %s", doc)
		}
	}
	var f limitsFile
	if err := decodeLimitsFile([]byte(`{"rateBps":0,"origins":{"37.eu1.example.com":{"rateBps":5},"[::1]:8080":{}}}`), &f); err != nil {
		t.Fatal(err)
	}
}

func TestOriginLimitsAndReload(t *testing.T) {
	h, admin, file := startWithLimits(t, `{"rateBps":1000000,"trickleBps":1000,
		"origins":{"a.test":{"rateBps":500000,"quotaBytesHour":9000000},"b.test":{}}}`,
		func(c *Config) { c.QuotaBytesHour = 7000000 })

	pa, pb, pc := keys(t, 1), keys(t, 2), keys(t, 3)
	ca := h.registerHost("a.test", pa, pa, roster(t, 1, pa))
	cb := h.registerHost("B.test:80", pb, pb, roster(t, 1, pb)) // normalised to b.test
	cc := h.registerHost("c.test", pc, pc, roster(t, 1, pc))    // not named: the defaults

	check := func(c *client, id string, want map[string]any) {
		t.Helper()
		h.s.refillUsage()
		if got := usageLimitsOf(t, c, id); !equalJSON(got, want) {
			t.Fatalf("%s: limits %v, want %v", id, got, want)
		}
	}
	// Each member was told its network's rate at registration...
	notice := func(rate float64) map[string]any {
		return map[string]any{"type": "shaping", "rateBps": rate, "slowed": false}
	}
	for c, rate := range map[*client]float64{ca: 500000, cb: 1000000, cc: 1000000} {
		if !equalJSON(c.shaping, notice(rate)) {
			t.Fatalf("told %v at registration, want %v", c.shaping, notice(rate))
		}
	}
	// The file's defaults over the environment's quota; a.test's own overrides over those.
	check(ca, "a1", limitsWant(500000, 9000000, 1000))
	check(cb, "b1", limitsWant(1000000, 7000000, 1000))
	check(cc, "c1", limitsWant(1000000, 7000000, 1000))

	// A reload applies to live networks. b.test now overrides; a.test is no longer named.
	os.WriteFile(file, []byte(`{"rateBps":2000000,"origins":{"b.test":{"trickleBps":64}}}`), 0o600)
	if code, body := post(t, admin.URL+"/reload"); code != 200 {
		t.Fatalf("reload: %d %s", code, body)
	}
	// ...and is told again when a reload changes it.
	for _, c := range []*client{ca, cb, cc} {
		if m := c.json(); !equalJSON(m, notice(2000000)) {
			t.Fatalf("told %v after the reload", m)
		}
	}
	check(ca, "a2", limitsWant(2000000, 7000000, 0))
	check(cb, "b2", limitsWant(2000000, 7000000, 64))
	check(cc, "c2", limitsWant(2000000, 7000000, 0))

	// A file that does not parse changes nothing.
	os.WriteFile(file, []byte(`{"rateBps":-1}`), 0o600)
	if code, _ := post(t, admin.URL+"/reload"); code != 400 {
		t.Fatalf("bad reload answered %d", code)
	}
	check(cb, "b3", limitsWant(2000000, 7000000, 64))
}

func equalJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func TestDrainClosesOnlyItsOrigin(t *testing.T) {
	h, admin, _ := startWithLimits(t, `{"origins":{"a.test":{},"b.test":{}}}`, nil)
	pa, wa, pb := keys(t, 1), keys(t, 2), keys(t, 3)
	ra := roster(t, 1, pa, wa)
	a1 := h.registerHost("a.test", pa, pa, ra)
	a2 := h.registerHost("a.test", wa, pa, ra)
	pending := h.dialHost("a.test")
	b1 := h.registerHost("b.test", pb, pb, roster(t, 1, pb))

	if code, body := post(t, admin.URL+"/drain?origin=a.test"); code != 200 || !strings.Contains(body, `"closed":3`) {
		t.Fatalf("drain: %d %s", code, body)
	}
	a1.expectClose(closeGoingAway)
	a2.expectClose(closeGoingAway)
	pending.expectClose(closeGoingAway)
	b1.quiet(300 * time.Millisecond)

	// The drained member reconnects through the same origin and is served again.
	h.registerHost("a.test", pa, pa, ra)

	if code, _ := post(t, admin.URL+"/drain?origin=c.test"); code != 404 {
		t.Fatalf("drain of an origin not named answered %d", code)
	}
}

func TestMetrics(t *testing.T) {
	h, admin, _ := startWithLimits(t, `{"origins":{"a.test":{},"b.test":{}}}`, nil)
	pa, wa := keys(t, 1), keys(t, 2)
	ra := roster(t, 1, pa, wa)
	ca := h.registerHost("a.test", pa, pa, ra)
	h.registerHost("a.test", wa, pa, ra)
	h.dialHost("b.test") // pending
	ca.sendBinary(frame(typeData, wa.ID, make([]byte, 100)))

	var m string
	deadline := time.Now().Add(5 * time.Second)
	for {
		m = get(t, admin.URL+"/metrics")
		if strings.Contains(m, "link_connections{state=\"pending\"} 1\n") || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, want := range []string{
		"link_connections{state=\"pending\"} 1\n",
		"link_connections{state=\"registered\"} 2\n",
		"link_networks{state=\"connected\"} 1\n",
		"link_networks{state=\"idle\"} 0\n",
		"link_origin_connections{origin=\"a.test\"} 2\n",
		"link_origin_connections{origin=\"b.test\"} 0\n",
		"link_origin_networks{origin=\"a.test\"} 1\n",
		"link_origin_slowed_networks{origin=\"a.test\"} 0\n",
		"link_closes_total{code=\"1001\"} 0\n",
		"# TYPE link_closes_total counter\n",
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %q:\n%s", want, m)
		}
	}
	if strings.Contains(m, "link_origin_bytes_hour{origin=\"a.test\"} 0\n") {
		t.Errorf("a.test charged nothing:\n%s", m)
	}
	for _, id := range []string{pa.ID.String(), wa.ID.String()} {
		if strings.Contains(m, id) {
			t.Fatalf("metrics carry a node id")
		}
	}

	post(t, admin.URL+"/drain?origin=a.test")
	time.Sleep(100 * time.Millisecond)
	if m := get(t, admin.URL+"/metrics"); !strings.Contains(m, "link_closes_total{code=\"1001\"} 2\n") {
		t.Errorf("drain closes not counted:\n%s", m)
	}
}
