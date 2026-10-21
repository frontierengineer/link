package relay

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/frontierengineer/link/relay/internal/link"
)

func TestHelloAnnouncesControl(t *testing.T) {
	h := start(t, nil)
	ws, _, err := websocket.DefaultDialer.Dial("ws://"+h.addr+"/v1", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	var hello map[string]any
	if err := ws.ReadJSON(&hello); err != nil {
		t.Fatal(err)
	}
	if f, _ := hello["features"].([]any); hello["type"] != "hello" || len(f) != 1 || f[0] != "control" {
		t.Fatalf("hello %v", hello)
	}
}

// awaitFrom waits for a frame from sender on frames, skipping others.
func awaitFrom(t *testing.T, frames chan []byte, sender link.ID, within time.Duration) ([]byte, time.Duration) {
	t.Helper()
	began := time.Now()
	deadline := time.After(within)
	for {
		select {
		case f, ok := <-frames:
			if !ok {
				t.Fatal("connection ended")
			}
			if len(f) >= 18 && f[0] == 1 && peerOf(f) == sender {
				return f, time.Since(began)
			}
		case <-deadline:
			t.Fatalf("nothing from %s within %v", sender, within)
		}
	}
}

// readFrames reads c in the background: binary frames as they are, text prefixed "text:".
func readFrames(c *client) chan []byte {
	ch := make(chan []byte, 1024)
	go func() {
		for {
			typ, b, err := c.ws.ReadMessage()
			if err != nil {
				close(ch)
				return
			}
			if typ == websocket.TextMessage {
				b = append([]byte("text:"), b...)
			}
			ch <- b
		}
	}()
	return ch
}

// awaitText waits for a text message containing want.
func awaitText(t *testing.T, ch chan []byte, want string, within time.Duration) time.Duration {
	t.Helper()
	began := time.Now()
	for {
		select {
		case f, ok := <-ch:
			if !ok {
				t.Fatal("connection ended")
			}
			if bytes.HasPrefix(f, []byte("text:")) && bytes.Contains(f, []byte(want)) {
				return time.Since(began)
			}
		case <-time.After(within):
			t.Fatalf("no %s within %v", want, within)
		}
	}
}

// The audit's case A: a member that owes the network's bucket seconds still has its usage
// answered and its control relayed at once; only its next data waits.
func TestShapingHoldsDataNotControl(t *testing.T) {
	h := start(t, func(c *Config) { c.RateBps = 400_000 })
	p, w := keys(t, 1), keys(t, 2)
	r := roster(t, 1, p, w)
	pc, wc := h.register(p, p, r), h.register(w, p, r)
	pFrames, wFrames := readFrames(pc), readFrames(wc)
	// One frame of 1 MiB puts the primary about 1.6 s into debt; the frame itself goes whole.
	pc.sendBinary(frame(typeData, w.ID, make([]byte, maxBinary-18)))
	awaitFrom(t, wFrames, p.ID, 5*time.Second)
	began := time.Now()
	pc.send(map[string]any{"type": "usage", "id": "u"})
	if took := awaitText(t, pFrames, `"usage"`, 5*time.Second); took > 300*time.Millisecond {
		t.Fatalf("usage answered after %v", took)
	}
	pc.sendBinary(frame(typeControl, w.ID, []byte("credit")))
	if f, took := awaitFrom(t, wFrames, p.ID, 5*time.Second); f[1] != typeData || string(f[18:]) != "credit" || took > 300*time.Millisecond {
		t.Fatalf("control %q after %v", f, took)
	}
	pc.sendBinary(frame(typeData, w.ID, []byte("later")))
	awaitFrom(t, wFrames, p.ID, 10*time.Second)
	if el := time.Since(began); el < time.Second {
		t.Fatalf("data went through after %v, with the network in debt", el)
	}
}

// The audit's case B: while another member keeps the network at its rate, the primary's
// usage asks and control are not stuck behind the network's shaping.
func TestControlAheadOfABusyNetwork(t *testing.T) {
	h := start(t, func(c *Config) { c.RateBps = 100_000 })
	p, w := keys(t, 1), keys(t, 2)
	r := roster(t, 1, p, w)
	pc, wc := h.register(p, p, r), h.register(w, p, r)
	pFrames, wFrames := readFrames(pc), readFrames(wc)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if wc.ws.WriteMessage(websocket.BinaryMessage, frame(typeData, p.ID, make([]byte, 64<<10-18))) != nil {
				return
			}
		}
	}()
	time.Sleep(time.Second) // the network is at its rate
	// 58 bytes of data put the primary into the network's debt too; what follows is control,
	// which goes ahead of that debt. (Control sent after more data would wait behind that
	// data: one TCP stream is read in order.)
	pc.sendBinary(frame(typeData, w.ID, make([]byte, 40)))
	for i := range 3 {
		pc.send(map[string]any{"type": "usage", "id": strconv.Itoa(i)})
		if took := awaitText(t, pFrames, `"usage"`, 10*time.Second); took > 300*time.Millisecond {
			t.Fatalf("usage %d answered after %v", i, took)
		}
		pc.sendBinary(frame(typeControl, w.ID, []byte("roster")))
		for {
			f, took := awaitFrom(t, wFrames, p.ID, 10*time.Second)
			if string(f[18:]) == "roster" {
				if took > 300*time.Millisecond {
					t.Fatalf("control %d after %v", i, took)
				}
				break
			}
		}
	}
}

// Fragmenting a message cannot slip it past the hold: only a whole frame is control.
func TestFragmentedControlIsHeld(t *testing.T) {
	body := bytes.Repeat([]byte{7}, 1000)
	for name, tc := range map[string]struct {
		send func(c *client, to link.ID)
		held bool
	}{
		"a whole control frame": {func(c *client, to link.ID) { c.sendBinary(frame(typeControl, to, body)) }, false},
		"a control frame in fragments": {func(c *client, to link.ID) {
			f := frame(typeControl, to, body)
			c.writeRaw(rawFrame(false, 2, f[:18], 18))
			c.writeRaw(rawFrame(true, 0, f[18:], len(f)-18))
		}, true},
		"a first fragment shorter than a header": {func(c *client, to link.ID) {
			f := frame(typeControl, to, body)
			c.writeRaw(rawFrame(false, 2, f[:3], 3))
			c.writeRaw(rawFrame(true, 0, f[3:], len(f)-3))
		}, true},
	} {
		t.Run(name, func(t *testing.T) {
			h := start(t, func(c *Config) { c.RateBps = 400_000 })
			p, w := keys(t, 1), keys(t, 2)
			r := roster(t, 1, p, w)
			pc, wc := h.register(p, p, r), h.register(w, p, r)
			wc.sendBinary(frame(typeData, p.ID, make([]byte, maxBinary-18))) // about 1.6 s of debt
			pc.frame()
			began := time.Now()
			tc.send(wc, p.ID)
			f := pc.frame()
			el := time.Since(began)
			if f[1] != typeData || len(f) != 1018 || (el > time.Second) != tc.held {
				t.Fatalf("got %d bytes of type %d after %v", len(f), f[1], el)
			}
		})
	}
}

// Control beyond the network's control budget waits like data.
func TestControlBudget(t *testing.T) {
	h := start(t, func(c *Config) { c.RateBps = 100_000 })
	p, w := keys(t, 1), keys(t, 2)
	r := roster(t, 1, p, w)
	pc, wc := h.register(p, p, r), h.register(w, p, r)
	for range 5 {
		wc.sendBinary(frame(typeData, p.ID, make([]byte, 60_000)))
	}
	for range 5 {
		pc.frame()
	}
	// Two 60 kB control frames fit the 128 KiB burst; the third does not.
	began := time.Now()
	for range 3 {
		wc.sendBinary(frame(typeControl, p.ID, make([]byte, 60_000)))
	}
	var at []time.Duration
	for range 3 {
		pc.frame()
		at = append(at, time.Since(began))
	}
	if at[1] > time.Second || at[2] < time.Second {
		t.Fatalf("control arrived at %v", at)
	}
}

// A member that floods pings without reading costs one pending pong, never a queue: only
// the latest ping is answered.
func TestPongsCoalesce(t *testing.T) {
	h := start(t, nil)
	p := keys(t, 1)
	pc := h.register(p, p, roster(t, 1, p), smallBuffers)
	var pongs atomic.Int64
	var last atomic.Value
	pc.ws.SetPongHandler(func(s string) error {
		pongs.Add(1)
		last.Store(s)
		return nil
	})
	const pings = 200_000
	payload := make([]byte, 125)
	for i := range pings {
		binary.BigEndian.PutUint64(payload, uint64(i))
		if err := pc.ws.WriteControl(websocket.PingMessage, payload, time.Now().Add(5*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	c := h.s.networkOf(netKeys(t, p).ID).members[p.ID]
	c.wmu.Lock()
	queued := c.queued
	c.wmu.Unlock()
	if queued != 0 {
		t.Fatalf("pongs went into the data queue: %d bytes", queued)
	}
	// Now read: the pongs that come are fewer than the pings, and the last answers the last.
	pc.quiet(time.Second)
	n := pongs.Load()
	s, _ := last.Load().(string)
	if n == 0 || n >= pings || len(s) != 125 || binary.BigEndian.Uint64([]byte(s)) != pings-1 {
		t.Fatalf("%d pongs, the last for ping %d", n, binary.BigEndian.Uint64([]byte(s+"\x00\x00\x00\x00\x00\x00\x00\x00")))
	}
	t.Logf("%d pings answered with %d pongs", pings, n)
}

// A connection that has not registered may send 16 frames, control frames included.
func TestFramesBeforeRegistering(t *testing.T) {
	h := start(t, nil)
	p := keys(t, 1)
	ok := h.dial()
	for range maxEarly - 1 {
		ok.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(time.Second))
	}
	ok.send(h.registerMsg(ok, p, netID(p), roster(t, 1, p)))
	for {
		m := ok.json()
		if m["type"] == "registered" {
			break
		}
	}
	over := h.dial()
	for range maxEarly + 1 {
		over.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(time.Second))
	}
	over.expectClose(4000)
}

// A pairing newcomer's pair frames are at most 1024 bytes.
func TestNewcomerPairFrameLimit(t *testing.T) {
	h := start(t, nil)
	p := keys(t, 1)
	pc := h.register(p, p, roster(t, 1, p))
	for _, size := range []int{maxPairFrame, maxPairFrame + 1} {
		n := h.dial()
		n.send(map[string]any{"type": "pair", "network": netID(p), "code": b64(make([]byte, 8))})
		pm := pc.json()
		raw, _ := link.DecodeKey(n.json()["channel"].(string), 16)
		n.sendBinary(frame(typePair, link.ID(raw), make([]byte, size-18)))
		if size == maxPairFrame {
			if f := pc.frame(); len(f) != size {
				t.Fatalf("got %d bytes", len(f))
			}
			n.send(map[string]any{"type": "pairEnd", "channel": pm["channel"]})
			n.expectClose(1000)
		} else {
			n.expectClose(4000)
		}
		if m := pc.json(); m["type"] != "pairEnd" {
			t.Fatalf("got %v", m)
		}
	}
}

// A frame's declared length is not what the relay allocates: buffers grow with the bytes
// that arrive, so members that promise 1 MiB and send little cost little.
func TestDeclaredLengthIsNotAllocated(t *testing.T) {
	h := start(t, nil)
	const members = 64
	var cs []*client
	for i := range members {
		k := keys(t, byte(i+1))
		cs = append(cs, h.register(k, k, roster(t, 1, k)))
	}
	time.Sleep(100 * time.Millisecond)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for _, c := range cs {
		c.writeRaw(rawFrame(true, 2, make([]byte, 100), maxBinary)[:4+8+4+100])
	}
	time.Sleep(300 * time.Millisecond)
	runtime.GC()
	runtime.ReadMemStats(&after)
	grew := int64(after.HeapInuse) - int64(before.HeapInuse)
	if grew > 8<<20 {
		t.Fatalf("heap grew %d bytes for %d partial 1 MiB frames", grew, members)
	}
	t.Logf("heap grew %d KB for %d partial 1 MiB frames", grew>>10, members)
}

// Idle registered connections give their goroutine up, and wake for traffic.
func TestIdleConnectionsPark(t *testing.T) {
	h := start(t, nil)
	if h.s.poll == nil {
		t.Skip("no poller on this platform")
	}
	const n = 200
	p := keys(t, 1)
	var ks []*link.Keys
	for i := range n - 1 {
		ks = append(ks, keys(t, byte(i+2)))
	}
	r := roster(t, 1, p, ks...)
	time.Sleep(100 * time.Millisecond)
	base := runtime.NumGoroutine()
	cs := []*client{h.register(p, p, r)}
	for _, k := range ks {
		cs = append(cs, h.register(k, p, r))
	}
	time.Sleep(200 * time.Millisecond)
	// The test's own gorilla clients run no goroutines while nobody reads.
	if g := runtime.NumGoroutine() - base; g > n/10 {
		t.Fatalf("%d goroutines for %d idle connections", g, n)
	}
	// Every parked connection still relays, in both directions.
	var wg sync.WaitGroup
	for i, c := range cs[1:] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.sendBinary(frame(typeData, p.ID, []byte{byte(i)}))
		}()
	}
	wg.Wait()
	seen := map[byte]bool{}
	for range n - 1 {
		seen[cs[0].frame()[18]] = true
	}
	if len(seen) != n-1 {
		t.Fatalf("%d distinct senders", len(seen))
	}
	cs[0].sendBinary(frame(typeData, ks[7].ID, []byte("back")))
	if f := cs[8].frame(); string(f[18:]) != "back" {
		t.Fatalf("got %q", f)
	}
}

// Back-pressure pauses only the senders feeding a recipient that does not read.
func TestBackPressureIsPerRecipient(t *testing.T) {
	h := start(t, nil)
	p, a, b, c := keys(t, 1), keys(t, 2), keys(t, 3), keys(t, 4)
	r := roster(t, 1, p, a, b, c)
	h.register(p, p, r, smallBuffers) // never reads
	ac, bc, cc := h.register(a, p, r), h.register(b, p, r), h.register(c, p, r)
	go func() {
		for {
			if ac.ws.WriteMessage(websocket.BinaryMessage, frame(typeData, p.ID, make([]byte, 64<<10))) != nil {
				return
			}
		}
	}()
	deadline := time.Now().Add(30 * time.Second)
	for !h.s.networkOf(netKeys(t, p).ID).members[a.ID].paused.Load() {
		if time.Now().After(deadline) {
			t.Fatal("the sender to a recipient that does not read was never paused")
		}
		time.Sleep(5 * time.Millisecond)
	}
	for i := range 100 {
		bc.sendBinary(frame(typeData, c.ID, []byte{byte(i)}))
		if f := cc.frame(); f[18] != byte(i) {
			t.Fatalf("got %x", f)
		}
	}
}

func TestClientIPKeys(t *testing.T) {
	req := func(remote string, xff ...string) *http.Request {
		r := &http.Request{RemoteAddr: remote, Header: http.Header{}}
		for _, v := range xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		return r
	}
	for _, tc := range []struct {
		proxies int
		r       *http.Request
		want    string
	}{
		{0, req("192.0.2.1:5000", "203.0.113.9"), "192.0.2.1"},
		// One proxy: the entry it appended, not the one the client wrote.
		{1, req("10.0.0.1:5000", "203.0.113.9, 198.51.100.7"), "198.51.100.7"},
		{1, req("10.0.0.1:5000", "203.0.113.9", "198.51.100.7"), "198.51.100.7"},
		{2, req("10.0.0.1:5000", "spoofed, 198.51.100.7, 10.0.0.2"), "198.51.100.7"},
		// Fewer entries than proxies: the leftmost is what the first proxy saw.
		{3, req("10.0.0.1:5000", "198.51.100.7, 10.0.0.2"), "198.51.100.7"},
		{1, req("10.0.0.1:5000", "198.51.100.7:4711"), "198.51.100.7"},
		{1, req("10.0.0.1:5000", "garbage"), "10.0.0.1"},
		{1, req("10.0.0.1:5000"), "10.0.0.1"},
		// IPv6 counts by /64; an IPv4-mapped address is IPv4.
		{0, req("[2001:db8:1:2:3:4:5:6]:443"), "2001:db8:1:2::/64"},
		{0, req("[2001:db8:1:2:ffff::1]:443"), "2001:db8:1:2::/64"},
		{0, req("[::ffff:192.0.2.1]:443"), "192.0.2.1"},
	} {
		s := &Server{cfg: Config{TrustProxy: tc.proxies}}
		if got := s.clientIP(tc.r); got != tc.want {
			t.Errorf("%d proxies, %s %v: %s, want %s", tc.proxies, tc.r.RemoteAddr, tc.r.Header.Values("X-Forwarded-For"), got, tc.want)
		}
	}
}

// The primary's side of a pairing exchange is charged to its network; the newcomer's is not.
func TestPrimaryPairFramesAreCharged(t *testing.T) {
	h := start(t, func(c *Config) { c.PingInterval = time.Hour })
	p := keys(t, 1)
	pc := h.register(p, p, roster(t, 1, p))
	n := h.dial()
	n.send(map[string]any{"type": "pair", "network": netID(p), "code": b64(make([]byte, 8))})
	pc.json() // pairing
	raw, _ := link.DecodeKey(n.json()["channel"].(string), 16)
	ch := link.ID(raw)
	n.sendBinary(frame(typePair, ch, make([]byte, 65)))
	pc.frame()
	pc.sendBinary(frame(typePair, ch, make([]byte, 1000)))
	n.frame()
	ask := `{"type":"usage","id":"u"}`
	pc.ws.WriteMessage(websocket.TextMessage, []byte(ask))
	if got := pc.json()["network"].(map[string]any)["bytesHour"]; got != float64(wire(1018)+wire(len(ask))) {
		t.Fatalf("bytesHour %v, want the primary's pair frame and the ask: %d", got, wire(1018)+wire(len(ask)))
	}
}

// dialStatus dials the relay and returns the HTTP status of a refused upgrade (101: upgraded).
func (h *harness) dialStatus() (int, *websocket.Conn) {
	ws, resp, err := websocket.DefaultDialer.Dial("ws://"+h.addr+"/v1", nil)
	if err == nil {
		h.t.Cleanup(func() { ws.Close() })
		return http.StatusSwitchingProtocols, ws
	}
	if resp == nil {
		h.t.Fatal(err)
	}
	return resp.StatusCode, nil
}

// Connections that have not registered are limited per address; registering frees the place.
func TestIPPendingLimit(t *testing.T) {
	h := start(t, func(c *Config) { c.IPPending = 2 })
	p := keys(t, 1)
	a, _ := h.dial(), h.dial()
	if code, _ := h.dialStatus(); code != http.StatusTooManyRequests {
		t.Fatalf("third pending connection: %d", code)
	}
	a.send(h.registerMsg(a, p, netID(p), roster(t, 1, p)))
	if m := a.json(); m["type"] != "registered" {
		t.Fatalf("got %v", m)
	}
	if code, _ := h.dialStatus(); code != http.StatusSwitchingProtocols {
		t.Fatalf("after one registered: %d", code)
	}
}

// Connections in all are limited per address; a closed one frees its place.
func TestIPConnectionsLimit(t *testing.T) {
	h := start(t, func(c *Config) { c.IPConnections = 3 })
	var cs []*client
	for i := range 3 {
		k := keys(t, byte(i+1))
		cs = append(cs, h.register(k, k, roster(t, 1, k)))
	}
	if code, _ := h.dialStatus(); code != http.StatusTooManyRequests {
		t.Fatalf("fourth connection: %d", code)
	}
	cs[0].ws.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, _ := h.dialStatus()
		if code == http.StatusSwitchingProtocols {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("still refused: %d", code)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// registerFrom registers k as h.register does, as if from ip behind one trusted proxy.
func (h *harness) registerFrom(ip string, k, network *link.Keys, rosterJSON []byte) *client {
	h.t.Helper()
	ws, _, err := websocket.DefaultDialer.Dial("ws://"+h.addr+"/v1", http.Header{"X-Forwarded-For": {ip}})
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { ws.Close() })
	c := &client{t: h.t, ws: ws}
	hello := c.json()
	c.challenge, _ = link.B64u.DecodeString(hello["challenge"].(string))
	c.send(h.registerMsg(c, k, netID(network), rosterJSON))
	if m := c.json(); m["type"] != "registered" {
		h.t.Fatalf("expected registered, got %v", m)
	}
	return c
}

// held reports what the relay keeps for a network: nothing, a compact record, or the roster.
func (s *Server) held(id link.ID) string {
	n := s.networkOf(id)
	if n == nil {
		return "forgotten"
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.roster.Raw == nil {
		return "compact"
	}
	return "full"
}

// goIdle disconnects c and waits until the relay counts its network as idle.
func goIdle(t *testing.T, h *harness, c *client, network link.ID) {
	c.ws.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		n := h.s.networkOf(network)
		if n == nil {
			return
		}
		n.mu.Lock()
		idle := len(n.members) == 0
		n.mu.Unlock()
		if idle {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("never idle")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Over LINK_IDLE_ROSTERS_BYTES, room is made at the address holding the most idle rosters:
// its longest idle is cut to a compact record first, a record is forgotten only after all of
// that address's full rosters are cut, and another address's network is not touched.
func TestIdleRostersFairShare(t *testing.T) {
	ks := []*link.Keys{keys(t, 1), keys(t, 2), keys(t, 3), keys(t, 4), keys(t, 5)}
	var rs [][]byte
	for _, k := range ks {
		rs = append(rs, roster(t, 1, k))
	}
	parsed, _ := link.ParseRoster(rs[0])
	full, small := rosterCost(parsed), rosterCost(compactRoster(parsed))
	h := start(t, func(c *Config) {
		c.TrustProxy = 1
		c.IdleRostersBytes = 3 * full
	})
	// The attacker's address holds networks 0 to 3, the other address network 4.
	goIdle(t, h, h.registerFrom("198.51.100.7", ks[4], ks[4], rs[4]), netKeys(t, ks[4]).ID)
	for i := range 4 {
		goIdle(t, h, h.registerFrom("203.0.113.9", ks[i], ks[i], rs[i]), netKeys(t, ks[i]).ID)
	}
	// Five full rosters against room for three: each cut frees a roster less its record, so the
	// attacker's three longest idle are cut, and only the attacker's.
	got := func() []string {
		var out []string
		for _, k := range ks {
			out = append(out, h.s.held(netKeys(t, k).ID))
		}
		return out
	}
	if want := []string{"compact", "compact", "compact", "full", "full"}; !slices.Equal(got(), want) {
		t.Fatalf("held %v, want %v", got(), want)
	}
	// Two more from the attacker: all its full rosters are cut before any record goes, then
	// its records go, longest idle first; the other address's roster stays whole throughout.
	for _, i := range []byte{6, 7} {
		k := keys(t, i)
		goIdle(t, h, h.registerFrom("203.0.113.9", k, k, roster(t, 1, k)), netKeys(t, k).ID)
	}
	if g := got(); g[4] != "full" || slices.Contains(g[:4], "full") {
		t.Fatalf("held %v", g)
	}
	h.s.idle.mu.Lock()
	bytes := h.s.idle.bytes
	h.s.idle.mu.Unlock()
	if bytes > 3*full {
		t.Fatalf("idle rosters hold %d bytes, over %d", bytes, 3*full)
	}
	t.Logf("full roster %d bytes, compact %d; held %v", full, small, got())
}

// A compact record still refuses a revoked member and admits a listed one; the primary
// presenting the version it was cut from brings the roster back whole.
func TestCompactRecordKeepsRevocation(t *testing.T) {
	p, w, x := keys(t, 1), keys(t, 2), keys(t, 3)
	r1, r2 := roster(t, 1, p, w, x), roster(t, 2, p, w) // version 2 revokes x
	parsed, _ := link.ParseRoster(r2)
	h := start(t, func(c *Config) { c.IdleRostersBytes = rosterCost(compactRoster(parsed)) })
	goIdle(t, h, h.register(p, p, r2), netKeys(t, p).ID)
	if got := h.s.held(netKeys(t, p).ID); got != "compact" {
		t.Fatalf("held %s", got)
	}
	// x presents version 1, which lists it: the record of version 2 does not.
	c := h.dial()
	c.send(h.registerMsg(c, x, netID(p), r1))
	c.expectClose(4008)
	// w presents version 1 too: listed, admitted, told version 2 exists.
	c = h.dial()
	c.send(h.registerMsg(c, w, netID(p), r1))
	if m := c.json(); m["type"] != "registered" || m["rosterVersion"] != float64(2) || m["roster"] != nil {
		t.Fatalf("got %v", m)
	}
	h.register(p, p, r2)
	if got := h.s.held(netKeys(t, p).ID); got != "full" {
		t.Fatalf("held %s after the primary came back", got)
	}
}

// Control messages are I-JSON (section 1): a repeated name or an escaped lone surrogate, which
// encoding/json would resolve quietly (last wins, U+FFFD), makes a message malformed, before
// registration and after it.
func TestControlMessagesMustBeIJSON(t *testing.T) {
	h := start(t, nil)
	p, w := keys(t, 1), keys(t, 2)
	r := roster(t, 3, p, w)
	raw := func(c *client, text string) {
		t.Helper()
		if err := c.ws.WriteMessage(websocket.TextMessage, []byte(text)); err != nil {
			t.Fatal(err)
		}
	}
	marshal := func(m map[string]any) string {
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	// A register whose `node` is named twice: the first (a stranger's id) is what a last-wins
	// parser would never see.
	c := h.dial()
	raw(c, `{"node":"`+keys(t, 9).ID.String()+`",`+marshal(h.registerMsg(c, w, netID(p), r))[1:])
	c.expectClose(closeBadRequest)

	// A register carrying an escaped lone surrogate in a member it does not even check.
	c = h.dial()
	raw(c, `{"x":"\ud800",`+marshal(h.registerMsg(c, w, netID(p), r))[1:])
	c.expectClose(closeBadRequest)

	// A register carrying a number out of range, which encoding/json reads without complaint.
	c = h.dial()
	raw(c, `{"x":1e309,`+marshal(h.registerMsg(c, w, netID(p), r))[1:])
	c.expectClose(closeBadRequest)

	// The same register, well formed, is taken.
	c = h.dial()
	raw(c, marshal(h.registerMsg(c, w, netID(p), r)))
	if m := c.json(); m["type"] != "registered" {
		t.Fatalf("registered: %v", m)
	}

	// After registration: a usage request whose id is named twice.
	pc := h.register(p, p, r)
	raw(pc, `{"type":"usage","id":"a","id":"b"}`)
	pc.expectClose(closeBadRequest)
}

// Member names match exactly (section 1): encoding/json would take "TYPE" for "type" and
// "Node" for "node", so a relay decoding with it reads messages no client wrote that way.
func TestControlMessageNamesAreCaseSensitive(t *testing.T) {
	h := start(t, nil)
	p, w := keys(t, 1), keys(t, 2)
	r := roster(t, 3, p, w)
	raw := func(c *client, text string) {
		t.Helper()
		if err := c.ws.WriteMessage(websocket.TextMessage, []byte(text)); err != nil {
			t.Fatal(err)
		}
	}
	for _, rename := range [][2]string{{`"type":`, `"TYPE":`}, {`"node":`, `"Node":`}, {`"roster":`, `"Roster":`}} {
		c := h.dial()
		b, err := json.Marshal(h.registerMsg(c, w, netID(p), r))
		if err != nil {
			t.Fatal(err)
		}
		text := strings.Replace(string(b), rename[0], rename[1], 1)
		if text == string(b) {
			t.Fatalf("no %s in %s", rename[0], b)
		}
		raw(c, text)
		c.expectClose(closeBadRequest)
	}
	// Registered, a usage request whose id is named "ID" has no id.
	pc := h.register(p, p, r)
	raw(pc, `{"type":"usage","ID":"a"}`)
	if m := pc.json(); m["type"] != "error" || m["code"] != "bad_request" {
		t.Fatalf("usage with ID: %v", m)
	}
}

// The control budget is each member's own (section 9): while the network is at its rate, one
// member spending all of its control budget leaves another member's handshakes and control
// prompt. With one budget for the network, the second member's 30 kB control frames waited
// behind the network's debt.
func TestControlBudgetIsPerMember(t *testing.T) {
	h := start(t, func(c *Config) { c.RateBps = 100_000 })
	p, z, w, x := keys(t, 1), keys(t, 2), keys(t, 3), keys(t, 4)
	r := roster(t, 1, p, z, w, x)
	pc, zc, wc, xc := h.register(p, p, r), h.register(z, p, r), h.register(w, p, r), h.register(x, p, r)
	pc.ws.SetReadDeadline(time.Time{})
	pFrames := readFrames(pc)
	stop := make(chan struct{})
	defer close(stop)
	flood := func(c *client, typ byte, size int) {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if c.ws.WriteMessage(websocket.BinaryMessage, frame(typ, p.ID, make([]byte, size))) != nil {
				return
			}
		}
	}
	go flood(zc, typeData, 64<<10-18) // keeps the network at its rate
	time.Sleep(500 * time.Millisecond)
	go flood(wc, typeControl, 30_000) // spends its control budget, and keeps it spent
	time.Sleep(time.Second)
	// The honest member is in the network's debt like anyone (a little data first); then its
	// handshakes and 30 kB control frames (a roster, say) go ahead within its own budget.
	xc.sendBinary(frame(typeData, p.ID, make([]byte, 40)))
	sends := []struct {
		typ  byte
		size int
	}{{typeInit, 100}, {typeControl, 30_000}, {typeInit, 100}, {typeControl, 30_000}, {typeControl, 30_000}}
	for i, m := range sends {
		body := make([]byte, m.size)
		body[3] = byte(i + 1)
		xc.sendBinary(frame(m.typ, p.ID, body))
		for {
			f, took := awaitFrom(t, pFrames, x.ID, 10*time.Second)
			if f[1] == typeData && len(f) == 18+40 {
				continue
			}
			if took > 300*time.Millisecond {
				t.Fatalf("frame %d (type %d, %d bytes) arrived after %v", i, m.typ, m.size, took)
			}
			break
		}
	}
}

// A network slowed to its trickle rate cannot get past it through control frames (section 9).
// Members of a modified client pace control frames to stay just within their own budgets, so
// none is ever refused and held back; without a network ceiling tied to the rate in force,
// together they moved 128 kB a second through a network slowed to 16 kB.
func TestSlowedNetworkControlStaysUnderTrickle(t *testing.T) {
	const trickle = 16384
	h := start(t, func(c *Config) {
		c.RateBps = 1 << 20
		c.QuotaBytesHour = 10_000
		c.TrickleBps = trickle
	})
	p := keys(t, 1)
	others := make([]*link.Keys, 32)
	for i := range others {
		others[i] = keys(t, byte(10+i))
	}
	r := roster(t, 1, p, others...)
	pc := h.register(p, p, r)
	var got atomic.Int64
	pc.ws.SetReadDeadline(time.Time{}) // the test runs past registration's read deadline
	frames := readFrames(pc)
	go func() {
		for f := range frames {
			if len(f) > 18 && f[1] == typeData {
				got.Add(int64(len(f)))
			}
		}
	}()
	stop := make(chan struct{})
	defer close(stop)
	for _, k := range others {
		c := h.register(k, p, r)
		go func() {
			tick := time.NewTicker(time.Second)
			defer tick.Stop()
			for {
				// 4000 bytes on the wire a second: within the member's own 4096.
				if c.ws.WriteMessage(websocket.BinaryMessage, frame(typeControl, p.ID, make([]byte, 4000-18-6))) != nil {
					return
				}
				select {
				case <-stop:
					return
				case <-tick.C:
				}
			}
		}()
	}
	// Past the network ceiling's burst, then a steady window.
	time.Sleep(6 * time.Second)
	from := got.Load()
	const window = 4 * time.Second
	time.Sleep(window)
	rate := float64(got.Load()-from) / window.Seconds()
	if rate > 1.25*trickle {
		t.Fatalf("%.0f bytes a second through a network slowed to %d", rate, trickle)
	}
}

// A member's control budget is its own, kept across its connections: reconnecting does not
// buy a fresh burst (section 9).
func TestControlBudgetCarriesAcrossConnections(t *testing.T) {
	h := start(t, func(c *Config) { c.RateBps = 100_000 })
	p, z, w := keys(t, 1), keys(t, 2), keys(t, 3)
	r := roster(t, 1, p, z, w)
	pc, zc := h.register(p, p, r), h.register(z, p, r)
	pc.ws.SetReadDeadline(time.Time{})
	pFrames := readFrames(pc)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if zc.ws.WriteMessage(websocket.BinaryMessage, frame(typeData, p.ID, make([]byte, 64<<10-18))) != nil {
				return
			}
		}
	}()
	time.Sleep(500 * time.Millisecond) // the network is at its rate
	send := func(c *client, size int) time.Duration {
		c.sendBinary(frame(typeControl, p.ID, make([]byte, size)))
		for {
			f, took := awaitFrom(t, pFrames, w.ID, 10*time.Second)
			if len(f) == 18+size {
				return took
			}
		}
	}
	// The first connection: a little data puts it in the network's debt, then its burst goes.
	wc := h.register(w, p, r)
	wc.sendBinary(frame(typeData, p.ID, make([]byte, 40)))
	for i := range 4 {
		if took := send(wc, 30_000); took > 300*time.Millisecond {
			t.Fatalf("control %d of the first burst after %v", i, took)
		}
	}
	// A new connection for the same member gets no new burst: its control waits like data.
	wc2 := h.register(w, p, r)
	wc2.sendBinary(frame(typeData, p.ID, make([]byte, 40)))
	if took := send(wc2, 30_000); took < 500*time.Millisecond {
		t.Fatalf("a reconnect bought a fresh burst: control after %v", took)
	}
}
