package main

// The driver, built and run as the cross-implementation suite runs it: two drivers (a primary
// and a member) on the real relay, steered over their stdin and stdout.

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

func build(t *testing.T, dir, pkg, out string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), out)
	cmd := exec.Command("go", "build", "-o", bin, pkg)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, b)
	}
	return bin
}

func startRelay(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("LINK_RELAY_BIN")
	if bin == "" {
		bin = build(t, filepath.Join("..", "..", "..", "relay"), "./cmd/link-relay", "link-relay")
	}
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), "LINK_ADDR=127.0.0.1:0")
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	port := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stderr)
		re := regexp.MustCompile(`listening on 127\.0\.0\.1:(\d+)`)
		for sc.Scan() {
			if m := re.FindStringSubmatch(sc.Text()); m != nil {
				port <- m[1]
			}
		}
	}()
	select {
	case p := <-port:
		return "ws://127.0.0.1:" + p + "/v1"
	case <-time.After(15 * time.Second):
		t.Fatal("relay did not start")
		return ""
	}
}

type proc struct {
	t      *testing.T
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	mu     sync.Mutex
	lines  []map[string]any
	nextID int
	exited chan error
}

func spawn(t *testing.T, bin string) *proc {
	t.Helper()
	p := &proc{t: t, cmd: exec.Command(bin), exited: make(chan error, 1)}
	p.cmd.Stderr = os.Stderr
	p.stdin, _ = p.cmd.StdinPipe()
	stdout, _ := p.cmd.StdoutPipe()
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 1<<20), 128<<20)
		for sc.Scan() {
			var v map[string]any
			if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
				t.Errorf("stdout is not one JSON object per line: %q", sc.Text())
				continue
			}
			p.mu.Lock()
			p.lines = append(p.lines, v)
			p.mu.Unlock()
		}
		p.exited <- p.cmd.Wait()
	}()
	t.Cleanup(func() { p.cmd.Process.Kill() })
	return p
}

// call sends a command and waits for its reply.
func (p *proc) call(cmd string, args map[string]any) map[string]any {
	p.t.Helper()
	p.mu.Lock()
	p.nextID++
	id := p.nextID
	p.mu.Unlock()
	msg := map[string]any{"id": id, "cmd": cmd}
	for k, v := range args {
		msg[k] = v
	}
	b, _ := json.Marshal(msg)
	if _, err := p.stdin.Write(append(b, '\n')); err != nil {
		p.t.Fatal(err)
	}
	return p.waitFor(fmt.Sprintf("reply to %s", cmd), func(v map[string]any) bool { return v["id"] == float64(id) })
}

func (p *proc) ok(cmd string, args map[string]any) map[string]any {
	p.t.Helper()
	r := p.call(cmd, args)
	if r["ok"] != true {
		p.t.Fatalf("%s: %v", cmd, r["error"])
	}
	return r
}

func (p *proc) waitFor(what string, match func(map[string]any) bool) map[string]any {
	p.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		for _, v := range p.lines {
			if match(v) {
				p.mu.Unlock()
				return v
			}
		}
		p.mu.Unlock()
		time.Sleep(2 * time.Millisecond)
	}
	p.t.Fatalf("timed out waiting for %s", what)
	return nil
}

// inOrder waits until lines matching each of matches have been written, in that order.
func (p *proc) inOrder(matches ...func(map[string]any) bool) {
	p.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		i := 0
		for _, v := range p.lines {
			if i < len(matches) && matches[i](v) {
				i++
			}
		}
		p.mu.Unlock()
		if i == len(matches) {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	p.t.Fatal("timed out waiting for lines in order")
}

func (p *proc) event(name string, match func(map[string]any) bool) map[string]any {
	p.t.Helper()
	return p.waitFor("event "+name, func(v map[string]any) bool { return v["event"] == name && (match == nil || match(v)) })
}

func TestDriverAgainstTheRelay(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the relay and the driver")
	}
	relay := startRelay(t)
	bin := build(t, ".", ".", "link-driver")
	timing := map[string]any{"backoffInitialMs": 20, "backoffMaxMs": 200, "requestTimeoutMs": 2000}

	pr := spawn(t, bin)
	seed := base64.StdEncoding.EncodeToString(make([]byte, 32))
	ident := pr.ok("identity", map[string]any{"seed": seed})
	if ident["seed"] != seed || ident["id"] != float64(1) || len(ident["node"].(string)) != 26 || len(ident["ed25519"].(string)) != 43 {
		t.Fatalf("identity %v", ident)
	}
	created := pr.ok("createNetwork", map[string]any{"relay": relay})
	roster, netSeed := created["roster"], created["networkSeed"]
	if raw, err := base64.StdEncoding.DecodeString(netSeed.(string)); err != nil || len(raw) != 32 {
		t.Fatalf("networkSeed %v", netSeed)
	}
	if roster.(map[string]any)["network"] == ident["node"] {
		t.Fatal("the network id is the primary's node id")
	}
	if r := pr.call("state", nil); r["error"].(map[string]any)["code"] != "invalid" {
		t.Fatalf("state without a node: %v", r)
	}
	if r := pr.call("connect", map[string]any{"role": "primary", "roster": roster}); r["error"].(map[string]any)["code"] != "invalid" {
		t.Fatalf("a primary without the network seed: %v", r)
	}
	pr.ok("connect", map[string]any{"role": "primary", "roster": roster, "networkSeed": netSeed, "timing": timing})
	// Events raised before a reply are written before it.
	pr.inOrder(
		func(v map[string]any) bool { return v["event"] == "state" && v["state"] == "connecting" },
		func(v map[string]any) bool { return v["event"] == "state" && v["state"] == "connected" },
		func(v map[string]any) bool { return v["id"] == float64(5) && v["ok"] == true },
	)
	if r := pr.call("connect", map[string]any{"role": "primary", "roster": roster, "networkSeed": netSeed}); r["error"].(map[string]any)["code"] != "invalid" {
		t.Fatalf("a second node: %v", r)
	}
	wk := spawn(t, bin)
	wk.ok("identity", nil)
	// The default code (no separate): id 8 zero bytes, none in its link. A separate code has
	// an id of its own. Cancelled with no codeId, the default code is refused as closed.
	const defaultID = "AAAAAAAAAAA"
	dropped := pr.ok("openPairingCode", nil)
	if dropped["codeId"] != defaultID || strings.Contains(dropped["link"].(string), "i=") {
		t.Fatalf("default code %v", dropped)
	}
	sep := pr.ok("openPairingCode", map[string]any{"separate": true})
	if sep["codeId"] == defaultID || !strings.Contains(sep["link"].(string), "&i="+sep["codeId"].(string)+"&") {
		t.Fatalf("separate code %v", sep)
	}
	pr.ok("cancelPairingCode", nil)
	if r := wk.call("pair", map[string]any{"link": dropped["link"]}); r["error"].(map[string]any)["code"] != "pairing" {
		t.Fatalf("a cancelled default code: %v", r)
	}
	pr.event("pairingFailed", func(v map[string]any) bool { return v["reason"] == "unknown-code" && v["codeId"] == defaultID })
	pr.ok("cancelPairingCode", map[string]any{"codeId": sep["codeId"]})

	code := pr.ok("openPairingCode", nil)
	if !strings.HasPrefix(code["link"].(string), "frontier://pair?") || code["expiresAt"].(float64) < float64(time.Now().UnixMilli()) || code["codeId"] != defaultID {
		t.Fatalf("code %v", code)
	}
	// A wrong code: a failed attempt, reported by its reason code.
	l := code["link"].(string)
	wrong := l[:strings.Index(l, "&c=")+3] + "00000000" + l[strings.Index(l, "&c=")+11:]
	if r := wk.call("pair", map[string]any{"link": wrong}); r["error"].(map[string]any)["code"] != "pairing" {
		t.Fatalf("wrong code: %v", r)
	}
	pr.event("pairingFailed", func(v map[string]any) bool { return v["reason"] == "wrong-code" && v["codeId"] == code["codeId"] })
	// Its parts with no codeId pair with the default code.
	paired := wk.ok("pair", map[string]any{"network": roster.(map[string]any)["network"], "code": code["code"], "relay": relay})
	if paired["pinnedNetworkKey"] != roster.(map[string]any)["networkKey"] {
		t.Fatalf("pinned %v, network key %v", paired["pinnedNetworkKey"], roster.(map[string]any)["networkKey"])
	}
	pr.event("paired", func(v map[string]any) bool {
		return v["codeId"] == code["codeId"] && v["version"] == float64(2) && len(v["node"].(string)) == 26
	})
	wk.ok("connect", map[string]any{"role": "member", "roster": paired["roster"], "timing": timing, "autoTake": false})
	wid := wk.ok("state", nil)
	if wid["state"] != "connected" {
		t.Fatalf("state %v", wid)
	}
	pr.event("roster", func(v map[string]any) bool { return v["roster"].(map[string]any)["version"] == float64(2) })

	// Bytes, and a generated payload over 64 KiB (no bytes in the event, only its hash).
	pid := ident["node"].(string)
	wk.ok("send", map[string]any{"peer": pid, "bytes": base64.StdEncoding.EncodeToString([]byte("hello"))})
	m := pr.event("message", func(v map[string]any) bool { return v["size"] == float64(5) })
	if m["bytes"] != base64.StdEncoding.EncodeToString([]byte("hello")) {
		t.Fatalf("message %v", m)
	}
	wk.ok("send", map[string]any{"peer": pid, "size": 200000, "fill": 7})
	want := make([]byte, 200000)
	for i := range want {
		want[i] = byte((7 + i*31) % 256)
	}
	sum := sha256.Sum256(want)
	big := pr.event("message", func(v map[string]any) bool { return v["size"] == float64(200000) })
	if big["sha256"] != hex.EncodeToString(sum[:]) || big["bytes"] != nil {
		t.Fatalf("message %v", big)
	}

	// Without autoTake, a message is announced on arrival and taken on request.
	wState := wk.ok("state", nil)["roster"].(map[string]any)
	var wID string
	for _, mm := range wState["members"].([]any) {
		if id := mm.(map[string]any)["id"].(string); id != pid {
			wID = id
		}
	}
	pr.ok("send", map[string]any{"peer": wID, "bytes": base64.StdEncoding.EncodeToString([]byte("to take"))})
	wk.event("message", func(v map[string]any) bool { return v["size"] == float64(7) })
	if r := wk.call("take", map[string]any{"count": 2, "timeoutMs": 100}); r["error"].(map[string]any)["code"] != "timeout" {
		t.Fatalf("take beyond what waits: %v", r)
	}
	taken := wk.ok("take", map[string]any{"count": 1})["messages"].([]any)
	if len(taken) != 1 || taken[0].(map[string]any)["from"] != pid {
		t.Fatalf("taken %v", taken)
	}
	if r := pr.call("take", nil); r["error"].(map[string]any)["code"] != "invalid" {
		t.Fatalf("take with autoTake: %v", r)
	}
	sess := wk.ok("sessions", map[string]any{"peer": pid})["sessions"].([]any)
	if len(sess) != 1 || sess[0].(map[string]any)["peer"] != pid || sess[0].(map[string]any)["current"] != true {
		t.Fatalf("sessions %v", sess)
	}
	theirs := pr.ok("sessions", nil)["sessions"].([]any)
	if len(theirs) != 1 || theirs[0].(map[string]any)["localIndex"] != sess[0].(map[string]any)["remoteIndex"] {
		t.Fatalf("sessions %v and %v", sess, theirs)
	}

	tr := wk.ok("traffic", nil)
	if tr["total"].(map[string]any)["sent"].(map[string]any)["messages"] != float64(2) {
		t.Fatalf("traffic %v", tr)
	}
	u := pr.ok("usage", nil)
	if u["network"].(map[string]any)["connections"] != float64(2) {
		t.Fatalf("usage %v", u)
	}
	// The relay told each member its network is unshaped; state says so.
	if sh := pr.ok("state", nil)["shaping"]; !reflect.DeepEqual(sh, map[string]any{"rateBps": float64(0), "slowed": false}) {
		t.Fatalf("shaping %v", sh)
	}
	if r := wk.call("send", map[string]any{"peer": "nobody", "bytes": ""}); r["ok"] != false || r["error"].(map[string]any)["code"] != "invalid" {
		t.Fatalf("bad send %v", r)
	}
	if r := wk.call("revoke", map[string]any{"node": pid}); r["error"].(map[string]any)["code"] != "invalid" {
		t.Fatalf("revoke from a member %v", r)
	}

	if r := wk.call("nonsense", nil); r["error"].(map[string]any)["code"] != "internal" {
		t.Fatalf("unknown command %v", r)
	}
	// Alice claims the primary (section 3.1): started again with the network seed, it signs
	// the roster naming itself primary once registered. The relay demotes the former primary in
	// place: it stays connected and goes on as a member.
	wRoster := wk.ok("state", nil)["roster"]
	wk.ok("close", nil)
	if r := wk.call("connect", map[string]any{"role": "primary", "roster": wRoster, "timing": timing}); r["error"].(map[string]any)["code"] != "invalid" {
		t.Fatalf("a primary without the network seed %v", r)
	}
	wk.ok("connect", map[string]any{"role": "primary", "roster": wRoster, "networkSeed": netSeed, "timing": timing})
	claimed := pr.event("roster", func(v map[string]any) bool { return v["roster"].(map[string]any)["primary"] == wID })["roster"].(map[string]any)
	if len(claimed["members"].([]any)) != 2 {
		t.Fatalf("the claim changed the members %v", claimed)
	}
	pr.mu.Lock()
	for _, v := range pr.lines {
		if v["event"] == "disconnect" || v["event"] == "state" && v["state"] != "connecting" && v["state"] != "connected" {
			t.Errorf("the claim disconnected the former primary: %v", v)
		}
	}
	pr.mu.Unlock()
	eventually := func(what string, cond func() bool) {
		for deadline := time.Now().Add(10 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
		}
	}
	eventually("the claim", func() bool { return wk.ok("state", nil)["primary"] == true })
	if ps := pr.ok("state", nil); ps["primary"] != false || ps["state"] != "connected" {
		t.Fatalf("former primary state %v", ps)
	}
	if r := pr.call("openPairingCode", nil); r["error"].(map[string]any)["code"] != "invalid" {
		t.Fatalf("a code from the former primary %v", r)
	}
	if r := pr.call("usage", nil); r["error"].(map[string]any)["code"] != "invalid" {
		t.Fatalf("usage from the former primary %v", r)
	}
	wk.ok("openPairingCode", nil)
	wk.ok("send", map[string]any{"peer": pid, "bytes": base64.StdEncoding.EncodeToString([]byte("after the claim"))})
	pr.event("message", func(v map[string]any) bool {
		return v["bytes"] == base64.StdEncoding.EncodeToString([]byte("after the claim"))
	})
	pr.ok("send", map[string]any{"peer": wID, "bytes": base64.StdEncoding.EncodeToString([]byte("back"))})
	wk.event("message", func(v map[string]any) bool { return v["bytes"] == base64.StdEncoding.EncodeToString([]byte("back")) })
	// The new primary's ask reaches the relay as the primary's: within 10 s of the last ask on
	// the network, it is refused over the budget (one per 10 s), not as from a member.
	if r := wk.call("usage", nil); r["error"].(map[string]any)["code"] != "rate-limited" {
		t.Fatalf("usage of the new primary %v", r)
	}

	// Revocation reaches the member as a 4008, then its state: the new primary revokes the
	// former one. Its only disconnect is this one.
	wk.ok("revoke", map[string]any{"node": pid})
	pr.inOrder(
		func(v map[string]any) bool { return v["event"] == "disconnect" && v["code"] == float64(4008) },
		func(v map[string]any) bool { return v["event"] == "state" && v["state"] == "revoked" },
	)
	if r := pr.call("send", map[string]any{"peer": wID, "bytes": ""}); r["error"].(map[string]any)["code"] != "revoked" {
		t.Fatalf("send after revoke %v", r)
	}

	// exit replies, then the driver exits 0; closing stdin does too.
	pr.ok("exit", nil)
	if err := <-pr.exited; err != nil {
		t.Fatalf("exit: %v", err)
	}
	wk.stdin.Close()
	if err := <-wk.exited; err != nil {
		t.Fatalf("stdin closed: %v", err)
	}
}
