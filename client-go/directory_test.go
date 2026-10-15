package link

// Choosing a relay from a directory: the shard hash, the directory's shape, and picking the
// closest accepting region.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestShardOf(t *testing.T) {
	for _, c := range []struct {
		network string
		shards  int
		want    string
	}{
		{"aaaaaaaaaaaaaaaaaaaaaaaaaa", 256, "49"},
		{"7k3q2m8x4v9b1n6c5z0wtrpyhd", 256, "61"},
		{"7k3q2m8x4v9b1n6c5z0wtrpyhd", 16, "1"},
		{"7k3q2m8x4v9b1n6c5z0wtrpyhd", 4096, "d61"},
		{"x", 1, "0"},
	} {
		got, err := ShardOf(c.network, c.shards)
		if err != nil || got != c.want {
			t.Errorf("ShardOf(%q, %d) = %q, %v; want %q", c.network, c.shards, got, err, c.want)
		}
	}
	for _, shards := range []int{0, 0x10001} {
		if _, err := ShardOf("x", shards); !errors.Is(err, ErrInvalid) {
			t.Errorf("ShardOf(x, %d): %v, want invalid", shards, err)
		}
	}
}

func testDirectory() *RelayDirectory {
	return &RelayDirectory{Version: 1, Regions: []DirectoryRegion{
		{ID: "use1", Probe: "https://use1.test/health", Relay: "wss://{shard}.use1.test/v1", Shards: 256, Accepting: true},
		{ID: "eu1", Probe: "https://eu1.test/health", Relay: "wss://{shard}.eu1.test/v1", Shards: 256, Accepting: true},
		{ID: "ap1", Probe: "https://ap1.test/health", Relay: "wss://{shard}.ap1.test/v1", Shards: 16, Accepting: false},
		{ID: "down", Probe: "https://down.test/health", Relay: "wss://down.test/v1", Accepting: true},
	}}
}

// fakeNet answers each probe host after its next delay, in real time; down.test never answers.
type fakeNet struct {
	mu     sync.Mutex
	delays map[string][]time.Duration
	calls  []string
}

func newFakeNet(delays map[string][]int) *fakeNet {
	n := &fakeNet{delays: map[string][]time.Duration{}}
	for host, ms := range delays {
		for _, d := range ms {
			n.delays[host] = append(n.delays[host], time.Duration(d)*time.Millisecond)
		}
	}
	return n
}

func (n *fakeNet) client() *http.Client { return &http.Client{Transport: n} }

func (n *fakeNet) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Host
	n.mu.Lock()
	n.calls = append(n.calls, req.URL.String())
	queue, known := n.delays[host]
	var d time.Duration
	if len(queue) > 0 {
		d, n.delays[host] = queue[0], queue[1:]
	}
	n.mu.Unlock()
	if !known {
		<-req.Context().Done()
		return nil, req.Context().Err()
	}
	select {
	case <-time.After(d):
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok")), Request: req}, nil
}

func (n *fakeNet) called(substr string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, u := range n.calls {
		if strings.Contains(u, substr) {
			return true
		}
	}
	return false
}

func TestPickRelayFastestAccepting(t *testing.T) {
	net := newFakeNet(map[string][]int{"use1.test": {150, 120, 130}, "eu1.test": {60, 20, 25}})
	got, err := PickRelay(context.Background(), PickRelayOptions{Network: "7k3q2m8x4v9b1n6c5z0wtrpyhd", Directory: testDirectory(), Client: net.client(), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != "wss://61.eu1.test/v1" || got.Region != "eu1" || got.Shard != "61" {
		t.Fatalf("picked %+v", got)
	}
	if got.RTT < 19*time.Millisecond || got.RTT >= 60*time.Millisecond {
		t.Errorf("the fastest probe counts: %v", got.RTT)
	}
	if net.called("ap1") {
		t.Error("a region not accepting is not timed")
	}
}

func TestPickRelayDirectoryURL(t *testing.T) {
	// A real server: the directory, and two probes that take their region's time.
	var dirJSON []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/relays":
			w.Write(dirJSON)
		case "/use1/health":
			time.Sleep(5 * time.Millisecond)
			w.Write([]byte("ok"))
		case "/eu1/health":
			time.Sleep(80 * time.Millisecond)
			w.Write([]byte("ok"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	dir := testDirectory()
	dir.Regions = dir.Regions[:2]
	dir.Regions[0].Probe = srv.URL + "/use1/health"
	dir.Regions[1].Probe = srv.URL + "/eu1/health"
	dirJSON, _ = json.Marshal(dir)

	got, err := PickRelay(context.Background(), PickRelayOptions{Network: "aaaaaaaaaaaaaaaaaaaaaaaaaa", DirectoryURL: srv.URL + "/v1/relays", Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != "wss://49.use1.test/v1" {
		t.Fatalf("picked %+v", got)
	}

	_, err = PickRelay(context.Background(), PickRelayOptions{Network: "x", DirectoryURL: srv.URL + "/missing", Timeout: time.Second})
	if CodeOf(err) != CodeUnreachable || !strings.Contains(err.Error(), "answered 404") {
		t.Fatalf("a directory that is not there: %v", err)
	}
}

func TestPickRelayOwnShardCount(t *testing.T) {
	base := testDirectory()
	grown := &RelayDirectory{Version: 1, Regions: []DirectoryRegion{base.Regions[1], base.Regions[2]}}
	grown.Regions[0].Shards = 4096
	grown.Regions[1].Accepting = true
	for _, c := range []struct {
		delays map[string][]int
		want   string
	}{
		{map[string][]int{"eu1.test": {5, 5, 5}, "ap1.test": {80, 80, 80}}, "wss://d61.eu1.test/v1"},
		{map[string][]int{"eu1.test": {80, 80, 80}, "ap1.test": {5, 5, 5}}, "wss://1.ap1.test/v1"},
	} {
		got, err := PickRelay(context.Background(), PickRelayOptions{Network: "7k3q2m8x4v9b1n6c5z0wtrpyhd", Directory: grown, Client: newFakeNet(c.delays).client(), Timeout: time.Second})
		if err != nil || got.URL != c.want {
			t.Errorf("picked %+v, %v; want %s", got, err, c.want)
		}
	}

	single := &RelayDirectory{Version: 1, Regions: []DirectoryRegion{{ID: "one", Probe: "https://use1.test/health", Relay: "wss://relay.test/v1", Accepting: true}}}
	got, err := PickRelay(context.Background(), PickRelayOptions{Network: "x", Directory: single, Client: newFakeNet(map[string][]int{"use1.test": {1, 1, 1}}).client()})
	if err != nil {
		t.Fatal(err)
	}
	got.RTT = 0
	if got != (PickedRelay{URL: "wss://relay.test/v1", Region: "one", Shard: "0"}) {
		t.Fatalf("picked %+v", got)
	}
}

func TestPickRelayNoneAnswers(t *testing.T) {
	base := testDirectory()
	only := &RelayDirectory{Version: 1, Regions: []DirectoryRegion{base.Regions[3], base.Regions[2]}}
	net := newFakeNet(nil)
	t0 := time.Now()
	_, err := PickRelay(context.Background(), PickRelayOptions{Network: "x", Directory: only, Client: net.client(), Timeout: 50 * time.Millisecond})
	if !errors.Is(err, ErrUnreachable) || !strings.Contains(err.Error(), "no accepting region") {
		t.Fatalf("got %v", err)
	}
	if took := time.Since(t0); took > 2*time.Second {
		t.Errorf("a region that never answers is cut off by the timeout: took %v", took)
	}
	if net.called("ap1") {
		t.Error("a region not accepting is not timed")
	}
}

func TestParseDirectory(t *testing.T) {
	good, _ := json.Marshal(testDirectory())
	edit := func(f func(r map[string]any)) string {
		var d map[string]any
		json.Unmarshal(good, &d)
		r := d["regions"].([]any)[0].(map[string]any)
		f(r)
		d["regions"] = []any{r}
		b, _ := json.Marshal(d)
		return string(b)
	}
	bad := []string{
		`null`,
		`[]`,
		strings.Replace(string(good), `"version":1`, `"version":2`, 1),
		edit(func(r map[string]any) { r["shards"] = 0 }),
		edit(func(r map[string]any) { r["shards"] = 1.5 }),
		edit(func(r map[string]any) { r["shards"] = 0x10001 }),
		edit(func(r map[string]any) { r["shards"] = nil }),
		`{"version":1,"regions":[]}`,
		`{"version":1,"regions":[7]}`,
		edit(func(r map[string]any) { r["probe"] = "ftp://x" }),
		edit(func(r map[string]any) { r["relay"] = "https://x" }),
		edit(func(r map[string]any) { r["accepting"] = "yes" }),
		edit(func(r map[string]any) { r["id"] = "" }),
		`{"version":1,"regions":[{"id":"a","probe":"https://a","relay":"wss://a","accepting":true}]} {}`,
	}
	for _, d := range bad {
		if _, err := ParseDirectory([]byte(d)); !errors.Is(err, ErrInvalid) {
			t.Errorf("ParseDirectory(%s): %v, want invalid", d, err)
		}
	}
	got, err := ParseDirectory(good)
	if err != nil || !reflect.DeepEqual(got, testDirectory()) {
		t.Fatalf("ParseDirectory(%s) = %+v, %v", good, got, err)
	}
	// Members this version does not define are ignored; a whole number written with a fraction
	// is still that number, as JSON.parse reads it.
	got, err = ParseDirectory([]byte(`{"version":1,"regions":[{"id":"a","name":"A","probe":"http://a/h","relay":"ws://a","shards":2.0,"accepting":false,"weight":3}],"x":1}`))
	if err != nil || !reflect.DeepEqual(got, &RelayDirectory{Version: 1, Regions: []DirectoryRegion{{ID: "a", Name: "A", Probe: "http://a/h", Relay: "ws://a", Shards: 2}}}) {
		t.Fatalf("got %+v, %v", got, err)
	}

	// A directory built in code is held to the same rules.
	broken := testDirectory()
	broken.Regions[0].Relay = "https://x"
	if _, err := PickRelay(context.Background(), PickRelayOptions{Network: "x", Directory: broken, Client: newFakeNet(nil).client()}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v", err)
	}
	if _, err := PickRelay(context.Background(), PickRelayOptions{Network: "x"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no directory: %v", err)
	}
}
