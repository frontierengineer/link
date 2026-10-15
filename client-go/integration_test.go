package link

// The client against the real relay: relay/cmd/link-relay is built into a temporary directory
// once per test process and started on a loopback port per test, configured only through
// LINK_* environment variables, as test/support/relay.ts does.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	relayOnce sync.Once
	relayBin  string
	relayDir  string
	relayErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if relayDir != "" {
		os.RemoveAll(relayDir)
	}
	os.Exit(code)
}

// relayBinary is LINK_RELAY_BIN when set, else a static build of ../relay.
func relayBinary(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("integration tests build and run the relay")
	}
	relayOnce.Do(func() {
		if given := os.Getenv("LINK_RELAY_BIN"); given != "" {
			relayBin = given
			return
		}
		dir, err := os.MkdirTemp("", "link-relay-")
		if err != nil {
			relayErr = err
			return
		}
		relayDir = dir
		relayBin = filepath.Join(dir, "link-relay")
		cmd := exec.Command("go", "build", "-o", relayBin, "./cmd/link-relay")
		cmd.Dir = filepath.Join("..", "relay")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			relayErr = fmt.Errorf("go build relay: %v\n%s", err, out)
		}
	})
	if relayErr != nil {
		t.Fatal(relayErr)
	}
	return relayBin
}

type relayProc struct {
	url string
	cmd *exec.Cmd
	mu  sync.Mutex
	log bytes.Buffer
}

func (r *relayProc) logText() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.log.String()
}

var listening = regexp.MustCompile(`listening on 127\.0\.0\.1:(\d+)`)

// startRelay starts the relay with env on a random loopback port; it stops with the test.
func startRelay(t *testing.T, env map[string]string) *relayProc {
	t.Helper()
	bin := relayBinary(t)
	cmd := exec.Command(bin)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "LINK_") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, "LINK_ADDR=127.0.0.1:0")
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	r := &relayProc{cmd: cmd}
	port := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			line := sc.Text()
			r.mu.Lock()
			r.log.WriteString(line + "\n")
			r.mu.Unlock()
			if m := listening.FindStringSubmatch(line); m != nil {
				select {
				case port <- m[1]:
				default:
				}
			}
		}
	}()
	select {
	case p := <-port:
		r.url = "ws://127.0.0.1:" + p + "/v1"
	case <-time.After(15 * time.Second):
		cmd.Process.Kill()
		t.Fatalf("relay did not start:\n%s", r.logText())
	}
	t.Cleanup(func() {
		cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			cmd.Process.Kill()
		}
	})
	return r
}

var fast = Timing{BackoffInitial: 20 * time.Millisecond, BackoffMax: 200 * time.Millisecond, RequestTimeout: 2 * time.Second}

type liveNet struct {
	t       *testing.T
	relay   *relayProc
	primary *Primary
	members []*Member
	timing  Timing
}

func ctxT(t *testing.T, d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func startLiveNet(t *testing.T, env map[string]string, timing Timing) *liveNet {
	t.Helper()
	r := startRelay(t, env)
	id, _ := NewIdentity()
	roster, err := CreateNetwork(id, r.url, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p, err := ConnectPrimary(ctxT(t, 15*time.Second), MemberOptions{Identity: id, Roster: roster, Timing: timing})
	if err != nil {
		t.Fatal(err)
	}
	n := &liveNet{t: t, relay: r, primary: p, timing: timing}
	t.Cleanup(func() {
		for _, m := range n.members {
			m.Close()
		}
		n.primary.Close()
	})
	return n
}

// pairOnly pairs a new node of kind and returns its identity and roster, unconnected.
func (n *liveNet) pairOnly(kind MemberKind) (*Identity, *Roster) {
	n.t.Helper()
	id, _ := NewIdentity()
	code, err := n.primary.OpenPairingCode(kind, PairingCodeOptions{})
	if err != nil {
		n.t.Fatal(err)
	}
	res, err := Pair(ctxT(n.t, 30*time.Second), PairOptions{Link: code.Link, Identity: id})
	if err != nil {
		n.t.Fatal(err)
	}
	if res.PinnedPrimary != res.Roster.Primary.Ed25519 || res.Roster.member(id.ID()) == nil {
		n.t.Fatal("pair result")
	}
	return id, res.Roster
}

// add pairs a node and connects it; the others learn the roster before it returns.
func (n *liveNet) add(kind MemberKind, mutate ...func(*MemberOptions)) *Member {
	n.t.Helper()
	id, roster := n.pairOnly(kind)
	o := MemberOptions{Identity: id, Roster: roster, Timing: n.timing}
	for _, f := range mutate {
		f(&o)
	}
	m, err := ConnectMember(ctxT(n.t, 15*time.Second), o)
	if err != nil {
		n.t.Fatal(err)
	}
	others := append([]*Member{n.primary.Member}, n.members...)
	n.members = append(n.members, m)
	eventually(n.t, "the others to learn the roster", func() bool {
		for _, o := range others {
			if o.State() == StateConnected && o.Roster().Version < roster.Version {
				return false
			}
		}
		return true
	})
	return m
}

func (n *liveNet) track(m *Member) *Member {
	n.members = append(n.members, m)
	return m
}

func TestLivePairingAndSessionsEveryWay(t *testing.T) {
	n := startLiveNet(t, nil, fast)
	pLog := record(n.primary.Member)
	w := n.add(KindWorker)
	s := n.add(KindSurface)
	if v := n.primary.Roster().Version; v != 3 {
		t.Fatalf("version %d", v)
	}
	kinds := map[string]MemberKind{}
	for _, m := range s.Roster().Members {
		kinds[m.ID] = m.Kind
	}
	if kinds[w.ID()] != KindWorker || kinds[s.ID()] != KindSurface || kinds[n.primary.ID()] != KindPrimary {
		t.Fatalf("kinds %v", kinds)
	}
	all := []*Member{n.primary.Member, w, s}
	for _, from := range all {
		for _, to := range all {
			if from == to {
				continue
			}
			msg := []byte(from.ID()[:6] + "->" + to.ID()[:6])
			if err := from.Send(ctxT(t, 10*time.Second), to.ID(), msg); err != nil {
				t.Fatal(err)
			}
			if got := recv(t, to); got.From != from.ID() || !bytes.Equal(got.Bytes, msg) {
				t.Fatalf("got %+v", got)
			}
		}
	}
	eventually(t, "paired events", func() bool {
		count := 0
		for _, e := range pLog.all() {
			if _, ok := e.(PairedEvent); ok {
				count++
			}
		}
		return count == 2
	})
}

func TestLiveLargeMessagesAndFlowControl(t *testing.T) {
	n := startLiveNet(t, nil, fast)
	w := n.add(KindWorker)
	s := n.add(KindSurface)
	big := pattern(6*1024*1024+17, 3)
	got := make(chan InboundMessage, 4)
	s.OnMessage(func(m InboundMessage) { got <- m })
	if err := w.Send(ctxT(t, 60*time.Second), s.ID(), big); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-got:
		if !bytes.Equal(m.Bytes, big) {
			t.Fatal("differs")
		}
	case <-time.After(60 * time.Second):
		t.Fatal("not delivered")
	}
	if sent := w.Sessions(s.ID())[0].Sent; sent < uint64(len(big)/maxFragment) {
		t.Fatalf("%d frames", sent)
	}
	back := pattern(3*1024*1024, 9)
	if err := s.Send(ctxT(t, 60*time.Second), w.ID(), back); err != nil {
		t.Fatal(err)
	}
	if m := recv(t, w); !bytes.Equal(m.Bytes, back) {
		t.Fatal("back differs")
	}

	// Credit: a receiver that takes nothing holds its senders.
	x := n.add(KindMCP)
	msgs := [][]byte{bytes.Repeat([]byte{1}, 700*1024), bytes.Repeat([]byte{2}, 700*1024), bytes.Repeat([]byte{3}, 700*1024)}
	for _, m := range msgs[:2] {
		if err := w.Send(ctxT(t, 10*time.Second), x.ID(), m); err != nil {
			t.Fatal(err)
		}
	}
	third := w.SendAsync(x.ID(), msgs[2])
	time.Sleep(500 * time.Millisecond)
	select {
	case <-third:
		t.Fatal("the third did not wait")
	default:
	}
	if si := w.Sessions(x.ID())[0]; si.Inflight > InitialCredit || si.SendCredit < 0 {
		t.Fatalf("%+v", si)
	}
	for i, want := range msgs {
		if m := recv(t, x); !bytes.Equal(m.Bytes, want) {
			t.Fatalf("message %d", i)
		}
	}
	if err := <-third; err != nil {
		t.Fatal(err)
	}
	eventually(t, "all credit returned", func() bool { return w.Sessions(x.ID())[0].SendCredit == InitialCredit })

	// Traffic counts match frame for frame between the two ends.
	w.ResetTraffic()
	x.ResetTraffic()
	payload := bytes.Repeat([]byte{7}, 300_000)
	if err := w.Send(ctxT(t, 10*time.Second), x.ID(), payload); err != nil {
		t.Fatal(err)
	}
	recv(t, x)
	eventually(t, "the frames to land", func() bool {
		return x.Traffic().Peers[w.ID()].Received.Frames >= w.Traffic().Peers[x.ID()].Sent.Frames
	})
	sent, rec := w.Traffic().Peers[x.ID()].Sent, x.Traffic().Peers[w.ID()].Received
	if sent.Messages != 1 || sent.Bytes != int64(len(payload)) || rec.Messages != 1 || rec.Bytes != sent.Bytes ||
		sent.FrameBytes <= int64(len(payload)) || float64(sent.FrameBytes) > 1.01*float64(len(payload)) {
		t.Fatalf("traffic sent %+v received %+v", sent, rec)
	}
}

func TestLiveRekeyAndReset(t *testing.T) {
	timing := fast
	timing.RekeyInterval = 250 * time.Millisecond
	timing.RetireGrace = time.Second
	n := startLiveNet(t, nil, timing)
	w := n.add(KindWorker)
	s := n.add(KindSurface)
	indices := map[uint32]bool{}
	for i := range 40 {
		if err := w.Send(ctxT(t, 10*time.Second), s.ID(), []byte(fmt.Sprintf("w%d", i))); err != nil {
			t.Fatal(err)
		}
		indices[currentIndex(w, s.ID())] = true
		time.Sleep(20 * time.Millisecond)
	}
	for i := range 40 {
		if m := recv(t, s); string(m.Bytes) != fmt.Sprintf("w%d", i) {
			t.Fatalf("got %q", m.Bytes)
		}
	}
	if len(indices) < 3 {
		t.Fatalf("%d sessions over 800 ms of 250 ms rekeys", len(indices))
	}
	// A rekey in the middle of a large message never splits it.
	big := pattern(3*1024*1024, 5)
	got := make(chan []byte, 1)
	go func() { m := recv(t, s); got <- m.Bytes }()
	if err := w.Send(ctxT(t, 30*time.Second), s.ID(), big); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(<-got, big) {
		t.Fatal("big message differs")
	}
	eventually(t, "retired sessions to be forgotten", func() bool { return len(w.Sessions(s.ID())) <= 2 })
}

func TestLiveResetAfterAPeerLosesItsState(t *testing.T) {
	n := startLiveNet(t, nil, fast)
	w := n.add(KindWorker)
	s := n.add(KindSurface)
	if err := w.Send(ctxT(t, 10*time.Second), s.ID(), []byte("one")); err != nil {
		t.Fatal(err)
	}
	recv(t, s)
	before := currentIndex(w, s.ID())
	// The surface restarts with no sessions; the worker's next frame is answered reset.
	id, roster := s.Identity(), s.Roster()
	s.Close()
	time.Sleep(100 * time.Millisecond)
	fresh := n.track(mustConnect(t, MemberOptions{Identity: id, Roster: roster, Timing: fast}))
	if err := w.Send(ctxT(t, 10*time.Second), s.ID(), []byte("lost")); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the worker to drop the session", func() bool { return len(w.Sessions(s.ID())) == 0 })
	if err := w.Send(ctxT(t, 10*time.Second), s.ID(), []byte("two")); err != nil {
		t.Fatal(err)
	}
	if m := recv(t, fresh); string(m.Bytes) != "two" {
		t.Fatalf("got %q: the message in the reset frame must be lost", m.Bytes)
	}
	if currentIndex(w, s.ID()) == before {
		t.Fatal("the same session")
	}
}

func mustConnect(t *testing.T, o MemberOptions) *Member {
	t.Helper()
	m, err := ConnectMember(ctxT(t, 15*time.Second), o)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestLiveRevocationResignationAnd4005(t *testing.T) {
	n := startLiveNet(t, nil, fast)
	w := n.add(KindWorker)
	s := n.add(KindSurface)
	x := n.add(KindMCP)
	if err := s.Send(ctxT(t, 10*time.Second), w.ID(), []byte("before")); err != nil {
		t.Fatal(err)
	}
	recv(t, w)
	sLog := record(s)
	r, err := n.primary.Revoke(s.ID())
	if err != nil || r.Version != 5 {
		t.Fatalf("revoke %v", err)
	}
	eventually(t, "revoked", func() bool { return s.State() == StateRevoked })
	eventually(t, "the worker to learn", func() bool { return w.Roster().Version == 5 })
	if len(w.Sessions(s.ID())) != 0 {
		t.Fatal("the worker kept a session with the revoked member")
	}
	if err := w.Send(ctxT(t, 5*time.Second), s.ID(), []byte("x")); CodeOf(err) != CodeInvalid {
		t.Fatal(err)
	}
	if err := s.Send(ctxT(t, 5*time.Second), w.ID(), []byte("x")); CodeOf(err) != CodeRevoked {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond)
	if !slices.Equal(sLog.codes(), []int{CloseNotMember}) || !slices.Equal(sLog.states(), []State{StateRevoked}) {
		t.Fatalf("codes %v states %v", sLog.codes(), sLog.states())
	}
	// A new copy of the revoked identity with its old roster is turned away at registration.
	again, err := NewMember(MemberOptions{Identity: s.Identity(), Roster: s.Roster(), Timing: fast})
	if err != nil {
		t.Fatal(err)
	}
	n.track(again)
	if err := again.WaitConnected(ctxT(t, 10*time.Second)); CodeOf(err) != CodeRevoked {
		t.Fatalf("got %v", err)
	}

	// Resign.
	xLog := record(x)
	if err := x.Resign(ctxT(t, 10*time.Second)); err != nil {
		t.Fatal(err)
	}
	if x.State() != StateRevoked || n.primary.Roster().Version != 6 || n.primary.Roster().member(x.ID()) != nil {
		t.Fatalf("after resign: %s v%d", x.State(), n.primary.Roster().Version)
	}
	eventually(t, "4008", func() bool {
		return slices.Contains(xLog.codes(), CloseNotMember) || slices.Contains(xLog.codes(), CloseNormal)
	})
	eventually(t, "the worker to learn", func() bool { return w.Roster().Version == 6 })

	// 4005: a second copy of the worker replaces the first, which stops for good.
	wLog := record(w)
	cp := n.track(mustConnect(t, MemberOptions{Identity: w.Identity(), Roster: w.Roster(), Timing: fast}))
	eventually(t, "replaced", func() bool { return w.State() == StateReplaced })
	if err := w.Send(ctxT(t, 5*time.Second), n.primary.ID(), []byte("x")); CodeOf(err) != CodeReplaced {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond)
	if !slices.Equal(wLog.codes(), []int{CloseReplaced}) || !slices.Equal(wLog.states(), []State{StateReplaced}) {
		t.Fatalf("codes %v states %v", wLog.codes(), wLog.states())
	}
	if cp.State() != StateConnected {
		t.Fatal("the copy lost its connection")
	}
	if err := cp.Send(ctxT(t, 5*time.Second), n.primary.ID(), []byte("from the copy")); err != nil {
		t.Fatal(err)
	}
	if m := recv(t, n.primary.Member); m.From != w.ID() || string(m.Bytes) != "from the copy" {
		t.Fatalf("%+v", m)
	}
}

func TestLiveUnreachableAndRefused(t *testing.T) {
	n := startLiveNet(t, map[string]string{"LINK_NETWORK_TTL": "500ms"}, fast)
	w := n.add(KindWorker)
	absent, _ := n.pairOnly(KindMCP)
	eventually(t, "the worker to learn of the mcp", func() bool { return w.Roster().member(absent.ID()) != nil })
	start := time.Now()
	if err := w.Send(ctxT(t, 5*time.Second), absent.ID(), []byte("x")); CodeOf(err) != CodeUnreachable {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("not at once")
	}
	// A member whose roster lacks the sender refuses it, then catches up from the primary.
	wID, wRoster := w.Identity(), w.Roster()
	w.Close()
	s := n.add(KindSurface) // a roster the worker never saw
	sID, sRoster := s.Identity(), s.Roster()
	pID, pRoster := n.primary.Identity(), n.primary.Roster()
	s.Close()
	n.primary.Close()
	time.Sleep(1500 * time.Millisecond) // the relay forgets the network
	w2 := n.track(mustConnect(t, MemberOptions{Identity: wID, Roster: wRoster, Timing: fast}))
	s2 := n.track(mustConnect(t, MemberOptions{Identity: sID, Roster: sRoster, Timing: fast}))
	err := s2.Send(ctxT(t, 5*time.Second), w2.ID(), []byte("do you know me?"))
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeRefused || e.Reason != 1 {
		t.Fatalf("got %v", err)
	}
	if w2.Roster().Version != wRoster.Version {
		t.Fatal("caught up without the primary")
	}
	p2, err := ConnectPrimary(ctxT(t, 10*time.Second), MemberOptions{Identity: pID, Roster: pRoster, Timing: fast})
	if err != nil {
		t.Fatal(err)
	}
	n.track(p2.Member)
	newer, err := w2.SyncRoster(ctxT(t, 10*time.Second))
	if err != nil || !newer || w2.Roster().Version != sRoster.Version {
		t.Fatalf("sync %v %v", newer, err)
	}
	if err := s2.Send(ctxT(t, 5*time.Second), w2.ID(), []byte("now you do")); err != nil {
		t.Fatal(err)
	}
	if m := recv(t, w2); string(m.Bytes) != "now you do" {
		t.Fatal(m)
	}
}

func TestLiveRevocationSpreadsWithThePrimaryOffline(t *testing.T) {
	n := startLiveNet(t, map[string]string{"LINK_NETWORK_TTL": "300ms"}, fast)
	wID, _ := n.pairOnly(KindWorker)
	tID, _ := n.pairOnly(KindSurface)
	xID, before := n.pairOnly(KindWorker)
	w := n.track(mustConnect(t, MemberOptions{Identity: wID, Roster: n.primary.Roster(), Timing: fast}))
	tRoster := n.primary.Roster()
	if _, err := n.primary.Revoke(xID.ID()); err != nil {
		t.Fatal(err)
	}
	after := n.primary.Roster().Version
	eventually(t, "the worker to learn", func() bool { return w.Roster().Version == after })
	wRoster := w.Roster()
	w.Close()
	n.primary.Close()
	time.Sleep(800 * time.Millisecond)
	// The tablet and the revoked phone come back first, on the roster from before: a relay
	// that knows nothing newer lets them in, and they talk.
	tm := n.track(mustConnect(t, MemberOptions{Identity: tID, Roster: tRoster, Timing: fast}))
	x := n.track(mustConnect(t, MemberOptions{Identity: xID, Roster: before, Timing: fast}))
	if err := tm.Send(ctxT(t, 5*time.Second), x.ID(), []byte("before")); err != nil {
		t.Fatal(err)
	}
	recv(t, x)
	// The worker returns with the revocation; the primary stays away. The tablet learns it
	// from the worker alone, then refuses the phone by itself.
	w2 := n.track(mustConnect(t, MemberOptions{Identity: wID, Roster: wRoster, Timing: fast}))
	if err := tm.Send(ctxT(t, 5*time.Second), w2.ID(), []byte("hello")); err != nil {
		t.Fatal(err)
	}
	recv(t, w2)
	eventually(t, "the tablet to learn the revocation from its peer", func() bool { return tm.Roster().Version == after })
	if err := tm.Send(ctxT(t, 5*time.Second), x.ID(), []byte("after")); CodeOf(err) != CodeInvalid {
		t.Fatalf("got %v", err)
	}
}

func TestLivePairingCodes(t *testing.T) {
	n := startLiveNet(t, nil, fast)
	pLog := record(n.primary.Member)
	code, err := n.primary.OpenPairingCode(KindWorker, PairingCodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	l, _ := ParsePairingLink(code.Link)
	wrong := l
	wrong.Code = "00000000"
	if l.Code == wrong.Code {
		wrong.Code = "00000001"
	}
	// Five wrong confirmations burn the code; the right one then fails too.
	for i := range CodeAttempts {
		id, _ := NewIdentity()
		_, err := Pair(ctxT(t, 10*time.Second), PairOptions{Target: &wrong, Identity: id})
		if CodeOf(err) != CodePairing {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	id, _ := NewIdentity()
	if _, err := Pair(ctxT(t, 10*time.Second), PairOptions{Link: code.Link, Identity: id}); CodeOf(err) != CodePairing {
		t.Fatalf("a burnt code paired: %v", err)
	}
	eventually(t, "pairingFailed events", func() bool {
		count := 0
		for _, e := range pLog.all() {
			if f, ok := e.(PairingFailedEvent); ok && f.CodeID == code.CodeID {
				count++
			}
		}
		return count >= CodeAttempts+1
	})
	// A used code admits one node; a chosen code pairs in any spelling.
	c2, _ := n.primary.OpenPairingCode(KindSurface, PairingCodeOptions{Code: "2b2b-2b2b"})
	l2, _ := ParsePairingLink(c2.Link)
	l2.Code = "2b2b 2b2b"
	if _, err := Pair(ctxT(t, 10*time.Second), PairOptions{Target: &l2, Identity: id}); err != nil {
		t.Fatal(err)
	}
	other, _ := NewIdentity()
	if _, err := Pair(ctxT(t, 10*time.Second), PairOptions{Link: c2.Link, Identity: other}); CodeOf(err) != CodePairing {
		t.Fatalf("a used code paired again: %v", err)
	}
	// A cancelled code fails; an absent primary is unreachable.
	c3, _ := n.primary.OpenPairingCode(KindMCP, PairingCodeOptions{})
	n.primary.CancelPairingCode(c3.CodeID)
	if _, err := Pair(ctxT(t, 10*time.Second), PairOptions{Link: c3.Link, Identity: other}); CodeOf(err) != CodePairing {
		t.Fatalf("a cancelled code paired: %v", err)
	}
	c4, _ := n.primary.OpenPairingCode(KindMCP, PairingCodeOptions{})
	n.primary.Close()
	time.Sleep(100 * time.Millisecond)
	if _, err := Pair(ctxT(t, 10*time.Second), PairOptions{Link: c4.Link, Identity: other}); CodeOf(err) != CodeUnreachable {
		t.Fatalf("absent primary: %v", err)
	}
	if _, err := Pair(context.Background(), PairOptions{Link: "frontier://pair?v=9", Identity: other}); CodeOf(err) != CodePairing {
		t.Fatalf("bad link: %v", err)
	}
}

func TestLiveUsageAndControlFrames(t *testing.T) {
	n := startLiveNet(t, nil, fast)
	w := n.add(KindWorker)
	s := n.add(KindSurface)
	u, err := n.primary.Usage(ctxT(t, 10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if u.Network.Connections != 3 || u.Network.Limits != (UsageLimits{}) || u.Network.Slowed {
		t.Fatalf("%+v", u)
	}
	// Three at once, then refused until the budget refills.
	limited := 0
	for range 3 {
		if _, err := n.primary.Usage(ctxT(t, 10*time.Second)); CodeOf(err) == CodeRateLimited {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("never rate-limited")
	}
	if err := w.Send(ctxT(t, 5*time.Second), s.ID(), []byte("x")); err != nil {
		t.Fatal(err)
	}
	recv(t, s)
}

func TestLiveRosterAtTheLimitTravelsEverywhere(t *testing.T) {
	r := startRelay(t, nil)
	id, _ := NewIdentity()
	fake := func() RosterMember {
		pub := make([]byte, 32)
		x := make([]byte, 32)
		rand.Read(pub)
		rand.Read(x)
		return RosterMember{ID: NodeIDFromEd25519(pub), Ed25519: b64u(pub), X25519: b64u(x), Kind: KindMCP}
	}
	sign := func(members []RosterMember) *Roster {
		ro, err := SignRoster(UnsignedRoster{Network: id.ID(), Version: 1, IssuedAt: time.Now().UnixMilli(), Relay: r.url,
			Primary: RosterPrimary{Ed25519: b64u(id.edPub)}, Members: append([]RosterMember{MemberFromIdentity(id, KindPrimary)}, members...)}, id)
		if err != nil {
			t.Fatal(err)
		}
		return ro
	}
	// Every entry has the same length, so the room left is a whole number of entries.
	one, _ := canonicalize(fake().tree())
	entry := len(one) + 1
	base, _ := sign([]RosterMember{fake()}).Size()
	var fakes []RosterMember
	for range (MaxRosterBytes-base)/entry - 1 { // room for two more
		fakes = append(fakes, fake())
	}
	p, err := ConnectPrimary(ctxT(t, 15*time.Second), MemberOptions{Identity: id, Roster: sign(fakes), Timing: fast})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	pLog := record(p.Member)
	codes := map[MemberKind]PairingCode{}
	for _, k := range PairingKinds {
		if codes[k], err = p.OpenPairingCode(k, PairingCodeOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	wID, _ := NewIdentity()
	res, err := Pair(ctxT(t, 20*time.Second), PairOptions{Link: codes[KindWorker].Link, Identity: wID})
	if err != nil {
		t.Fatal(err)
	}
	// The primary is busy handing v2 to some 400 members (a handshake each, every one of them
	// unreachable), which takes seconds under the race detector, and longer on a loaded
	// machine: the worker's handshake gets a minute.
	slow := fast
	slow.HandshakeTimeout = time.Minute
	w := mustConnect(t, MemberOptions{Identity: wID, Roster: res.Roster, Timing: slow})
	defer w.Close()
	if err := w.Send(ctxT(t, 60*time.Second), p.ID(), []byte("hello")); err != nil {
		t.Fatal(err)
	}
	recv(t, p.Member)
	// The last member that fits: v3 is just under the limit and reaches the worker in a session.
	sID, _ := NewIdentity()
	if _, err := Pair(ctxT(t, 20*time.Second), PairOptions{Link: codes[KindSurface].Link, Identity: sID}); err != nil {
		t.Fatal(err)
	}
	size, _ := p.Roster().Size()
	if p.Roster().Version != 3 || size > MaxRosterBytes || size <= MaxRosterBytes-entry {
		t.Fatalf("v%d is %d bytes", p.Roster().Version, size)
	}
	eventually(t, "the worker to receive v3 in a session", func() bool { return w.Roster().Version == 3 })
	// It travels in register (and would in registered).
	w.Close()
	w2 := mustConnect(t, MemberOptions{Identity: wID, Roster: w.Roster(), Timing: fast})
	defer w2.Close()
	// The restarted worker opens a fresh session (the primary's old one would be reset).
	if err := w2.Send(ctxT(t, 5*time.Second), p.ID(), []byte("back")); err != nil {
		t.Fatal(err)
	}
	recv(t, p.Member)
	// No room left: a new code is refused at once, and a code opened earlier fails at P5.
	if _, err := p.OpenPairingCode(KindMCP, PairingCodeOptions{}); CodeOf(err) != CodeRosterFull {
		t.Fatalf("got %v", err)
	}
	other, _ := NewIdentity()
	if _, err := Pair(ctxT(t, 20*time.Second), PairOptions{Link: codes[KindMCP].Link, Identity: other}); CodeOf(err) != CodePairing {
		t.Fatalf("got %v", err)
	}
	eventually(t, "pairingFailed", func() bool {
		return slices.ContainsFunc(pLog.all(), func(e Event) bool {
			f, ok := e.(PairingFailedEvent)
			return ok && strings.Contains(f.Reason, "over the 65000-byte limit")
		})
	})
	if p.Roster().Version != 3 {
		t.Fatal("the roster changed")
	}
	// A session message over one Noise message is refused before it is encrypted, so the
	// session stays usable.
	errc := make(chan error, 1)
	locked(p.Member, func() {
		p.sess.sendControl(w2.ID(), sessionMessage{typ: sessRoster, bytes: bytes.Repeat([]byte("x"), 70_000)}, func(err error) { errc <- err })
	})
	if err := <-errc; CodeOf(err) != CodeInvalid {
		t.Fatalf("got %v", err)
	}
	if err := p.Send(ctxT(t, 5*time.Second), w2.ID(), []byte("still here")); err != nil {
		t.Fatal(err)
	}
	if m := recv(t, w2); string(m.Bytes) != "still here" {
		t.Fatal(m)
	}
}

// After P6 the primary pushes the new roster to every member but the newcomer: it has it
// already, sealed in P6, and is not connected yet, so a push would fail and be retried into the
// middle of its first traffic (section 5.3).
func TestLiveThePrimaryDoesNotPushTheRosterToTheNewcomer(t *testing.T) {
	n := startLiveNet(t, nil, fast)
	w := n.add(KindWorker)
	id, roster := n.pairOnly(KindSurface) // paired, not connected
	time.Sleep(200 * time.Millisecond)
	locked(n.primary.Member, func() {
		ps := n.primary.sess.peers[id.ID()]
		if ps != nil && (ps.pending != nil || len(ps.sessions) > 0) {
			t.Error("the primary handshook with the newcomer it had just sealed the roster for")
		}
		if _, retrying := n.primary.prim.retries[id.ID()]; retrying {
			t.Error("the primary is retrying a push to the newcomer")
		}
	})
	// The others got it.
	eventually(t, "the worker to hold the new roster", func() bool { return w.Roster().Version == roster.Version })
	// The newcomer connects and talks with nothing from the primary in the way.
	s := n.track(mustConnect(t, MemberOptions{Identity: id, Roster: roster, Timing: fast}))
	s.ResetTraffic()
	if err := s.Send(ctxT(t, 5*time.Second), w.ID(), []byte("first")); err != nil {
		t.Fatal(err)
	}
	recv(t, w)
	time.Sleep(1500 * time.Millisecond) // past the first push retry the primary would have made
	if p := s.Traffic().Peers[n.primary.ID()]; p.Received.Frames != 0 {
		t.Fatalf("%d frames from the primary in the newcomer's first traffic", p.Received.Frames)
	}
}
