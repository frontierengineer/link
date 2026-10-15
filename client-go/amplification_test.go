package link

// What a peer, or a relay forging and replaying frames, can make a member send or compute:
// each reply and each handshake-init has a per-peer budget, rosters go at most one per peer
// per 250 ms and never twice while one is unsent, and the outbound queue has a bound past
// which the connection is redialled rather than grown.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// gateWrites makes the relay take nothing from id's connection, so all it is sent queues.
func gateWrites(tn *testNet, id string) chan struct{} {
	g := make(chan struct{})
	s := tn.relay.conn(id)
	s.mu.Lock()
	s.gate = g
	s.mu.Unlock()
	return g
}

func queued(m *Member) (n int) {
	locked(m, func() { n = m.relay.bufferedAmount() })
	return
}

func settle(t *testing.T, what string, f func() int) int {
	t.Helper()
	last, stable := -1, 0
	eventually(t, what, func() bool {
		n := f()
		if n == last {
			stable++
		} else {
			stable, last = 0, n
		}
		return stable >= 20
	})
	return last
}

func TestRosterRequestsAreCoalescedPerPeer(t *testing.T) {
	tn := newTestNet(t, 380) // a roster near the 65000-byte limit
	size, _ := tn.roster.Size()
	v, m := tn.start(1), tn.start(2)
	if err := send(t, m, v.ID(), []byte("hi")); err != nil {
		t.Fatal(err)
	}
	recv(t, v)
	conn := tn.relay.conn(v.ID())
	log := record(v)
	g := gateWrites(tn, v.ID())
	defer close(g)
	for range 2000 {
		locked(m, func() { m.sess.sendControl(v.ID(), sessionMessage{typ: sessRosterRequest}, func(error) {}) })
	}
	n := settle(t, "the requests to be handled", func() int { return queued(v) })
	// Far below the outbound bound, which is only a backstop: the connection holds.
	if v.Settle(); len(log.codes()) != 0 || tn.relay.conn(v.ID()) != conn {
		t.Fatalf("the connection was given up: %v", log.codes())
	}
	if n > size+frameOverhead+1024 {
		t.Fatalf("2000 roster-requests queued %d bytes (the roster is %d)", n, size)
	}
	// While that one is unsent nothing more goes, however long it takes.
	tn.clock.Advance(time.Second)
	locked(m, func() { m.sess.sendControl(v.ID(), sessionMessage{typ: sessRosterRequest}, func(error) {}) })
	if n := settle(t, "the request to be handled", func() int { return queued(v) }); n > size+frameOverhead+1024 {
		t.Fatalf("%d bytes queued", n)
	}
}

func TestRosterAnswersAreTimelyAndCoalesced(t *testing.T) {
	tn := newTestNet(t, 3)
	v, m := tn.start(1), tn.start(2)
	if err := send(t, m, v.ID(), []byte("hi")); err != nil {
		t.Fatal(err)
	}
	recv(t, v)
	tn.clock.Advance(CreditDelay) // the credit for "hi" goes now, not amid the answers
	eventually(t, "credit", func() bool { return m.Sessions(v.ID())[0].SendCredit == InitialCredit })
	before := func() int {
		var n int
		locked(m, func() { n = int(m.traffic.total.Received.Frames) })
		return n
	}
	start := before()
	ask := func() {
		locked(m, func() { m.sess.sendControl(v.ID(), sessionMessage{typ: sessRosterRequest}, func(error) {}) })
	}
	// Three at once: one answer, which the other two ride on while it is unsent.
	for range 3 {
		ask()
	}
	if n := settle(t, "the first answer", before); n-start != 1 {
		t.Fatalf("%d answers at once", n-start)
	}
	// Three more within 250 ms of it: none at once, one at the end of the gap.
	for range 3 {
		ask()
	}
	if n := settle(t, "no answer within the gap", before); n-start != 1 {
		t.Fatalf("%d answers within the gap", n-start)
	}
	tn.clock.Advance(rosterGap)
	if n := settle(t, "the coalesced answer", before); n-start != 2 {
		t.Fatalf("%d answers after the gap", n-start)
	}
}

// initPayload is an init's payload: the roster version and a stamp.
func initPayload(version, stamp uint64) []byte { return append(u64be(version), u64be(stamp)...) }

// memberInit is a genuine handshake-init from sender to responder, carrying version and stamp.
func memberInit(tn *testNet, sender, responder *Identity, version, stamp uint64, index uint32) []byte {
	hs, _ := newHandshake(sender, true, tn.roster.Network, responder.xPub[:], nil)
	msg1, _, _, _ := hs.WriteMessage(nil, initPayload(version, stamp))
	from, _ := nodeIDToBytes(sender.ID())
	f, _ := encodeFrame(frameHandshakeInit, from, handshakeInitBody(index, msg1))
	return f
}

func TestRepeatedInitsAreBudgeted(t *testing.T) {
	tn := newTestNet(t, 380)
	size, _ := tn.roster.Size()
	v := tn.start(1)
	tn.start(2)
	g := gateWrites(tn, v.ID())
	defer close(g)
	// 300 genuine inits, each with a new stamp, claiming version 1 (v holds 2).
	for i := range 300 {
		tn.relay.inject(v.ID(), memberInit(tn, tn.ids[2], tn.ids[1], 1, uint64(1790000000000+i), uint32(i)+1))
	}
	settle(t, "the inits to be handled", func() int { return queued(v) })
	var read int
	locked(v, func() { read = v.sess.stats.initsRead })
	if read != memberInitBurst {
		t.Fatalf("%d of 300 inits read, want the burst of %d", read, memberInitBurst)
	}
	// One roster for all of them, and the handshake answers.
	if n := queued(v); n > size+frameOverhead+memberInitBurst*(82+frameOverhead)+1024 {
		t.Fatalf("300 inits queued %d bytes (the roster is %d)", n, size)
	}
	if n := len(v.Sessions(tn.ids[2].ID())); n > maxSessionsPerPeer {
		t.Fatalf("%d sessions", n)
	}
	// The budget refills: 16 a second.
	tn.clock.Advance(time.Second)
	for i := range 40 {
		tn.relay.inject(v.ID(), memberInit(tn, tn.ids[2], tn.ids[1], 1, uint64(1790000001000+i), uint32(1000+i)))
	}
	settle(t, "more inits", func() int {
		var n int
		locked(v, func() { n = v.sess.stats.initsRead })
		return n
	})
	locked(v, func() { read = v.sess.stats.initsRead })
	if read != memberInitBurst+memberInitRate {
		t.Fatalf("%d inits read after a second, want %d", read, memberInitBurst+memberInitRate)
	}
}

// A recorded init replayed (the same bytes again) is dropped unanswered: it opens no session,
// evicts none, draws no roster, and is charged to the id's failure budget.
func TestAReplayedInitIsDropped(t *testing.T) {
	tn := newTestNet(t, 380)
	size, _ := tn.roster.Size()
	v := tn.start(1)
	m := tn.start(2)
	if err := send(t, m, v.ID(), []byte("hi")); err != nil {
		t.Fatal(err)
	}
	recv(t, v)
	session := currentIndex(v, m.ID())
	// The relay replays one genuine init from m, claiming an old version, 300 times. The first
	// copy carries a stamp v has not seen (one before m's own init would be refused at once).
	var first uint64
	locked(v, func() { first = v.sess.stamps[m.ID()] })
	one := memberInit(tn, tn.ids[2], tn.ids[1], 1, first+1, 7)
	g := gateWrites(tn, v.ID())
	defer close(g)
	for range 300 {
		tn.relay.inject(v.ID(), one)
	}
	n := settle(t, "the replays", func() int { return queued(v) })
	// The first is accepted (a session, and the roster pushed to a peer behind); every copy
	// after it is dropped unanswered.
	if n > size+frameOverhead+82+frameOverhead+1024 {
		t.Fatalf("300 copies of one init queued %d bytes", n)
	}
	locked(v, func() {
		if v.sess.stamps[m.ID()] != first+1 {
			t.Errorf("stamp %d", v.sess.stamps[m.ID()])
		}
		// m's own init, the first copy, then failBurst copies read and charged as failures;
		// the rest dropped before any DH.
		if v.sess.stats.initsRead != 2+failBurst {
			t.Errorf("%d inits read, want %d", v.sess.stats.initsRead, 2+failBurst)
		}
	})
	if got := len(v.Sessions(m.ID())); got != 2 {
		t.Fatalf("%d sessions: the copies opened or evicted some", got)
	}
	found := false
	for _, si := range v.Sessions(m.ID()) {
		found = found || si.LocalIndex == session
	}
	if !found {
		t.Fatal("the replays evicted the session in use")
	}
}

// An init whose stamp is not greater than the greatest accepted from that member is refused
// (dropped unanswered); a greater one is accepted.
func TestStampsMustIncrease(t *testing.T) {
	tn := newTestNet(t, 3)
	v := tn.start(1)
	tn.start(2)
	sessions := func() int { return len(v.Sessions(tn.ids[2].ID())) }
	const base = 1790000000000 // the fake clock's start: above the floor
	tn.relay.inject(v.ID(), memberInit(tn, tn.ids[2], tn.ids[1], 2, base, 1))
	eventually(t, "the first init accepted", func() bool { return sessions() == 1 })
	for _, stamp := range []uint64{base - 1, base} {
		tn.relay.inject(v.ID(), memberInit(tn, tn.ids[2], tn.ids[1], 2, stamp, 2))
	}
	time.Sleep(20 * time.Millisecond)
	settle(t, "the old stamps", func() int {
		var n int
		locked(v, func() { n = v.sess.stats.initsRead })
		return n
	})
	if sessions() != 1 {
		t.Fatalf("an older or equal stamp opened a session (%d)", sessions())
	}
	tn.relay.inject(v.ID(), memberInit(tn, tn.ids[2], tn.ids[1], 2, base+1, 3))
	eventually(t, "the newer init accepted", func() bool { return sessions() == 2 })
	// An 8-byte payload (the old form) from a member is a malformed init.
	hs, _ := newHandshake(tn.ids[2], true, tn.roster.Network, tn.ids[1].xPub[:], nil)
	msg1, _, _, _ := hs.WriteMessage(nil, u64be(2))
	from, _ := nodeIDToBytes(tn.ids[2].ID())
	f, _ := encodeFrame(frameHandshakeInit, from, handshakeInitBody(4, msg1))
	tn.relay.inject(v.ID(), f)
	time.Sleep(20 * time.Millisecond)
	if sessions() != 2 {
		t.Fatal("an 8-byte payload opened a session")
	}
}

// Two inits in one millisecond, and after a wall clock stepped back, get increasing stamps.
func TestStampsIncreaseWithinAMillisecond(t *testing.T) {
	tn := newTestNet(t, 2)
	m := tn.start(1)
	var a, b, c uint64
	locked(m, func() { a, b = m.nextStamp(), m.nextStamp() })
	if a < uint64(tn.clock.Now().UnixMilli()) || b != a+1 {
		t.Fatalf("stamps %d, %d in one millisecond", a, b)
	}
	// The wall clock stepped back: the stamps go on increasing.
	tn.clock.StepWall(-time.Hour)
	locked(m, func() { c = m.nextStamp() })
	if c != b+1 {
		t.Fatalf("stamp %d after %d, with the wall clock an hour back", c, b)
	}
	// The wall clock past the last stamp: it is the stamp again.
	tn.clock.StepWall(2 * time.Hour)
	locked(m, func() { c = m.nextStamp() })
	if c != uint64(tn.clock.Now().UnixMilli()) {
		t.Fatalf("stamp %d, wall %d", c, tn.clock.Now().UnixMilli())
	}
}

func TestForgedFramesGetFewRepliesAndStarveNoOtherPeer(t *testing.T) {
	tn := newTestNet(t, 4)
	v := tn.start(1)
	honest := tn.start(3)
	g := gateWrites(tn, v.ID())
	from, _ := nodeIDToBytes(tn.ids[2].ID())
	// Data frames naming indices v does not hold: a reset each, within the peer's budget.
	for i := range 20000 {
		body := binary.BigEndian.AppendUint32(nil, uint32(i)+1)
		f, _ := encodeFrame(frameData, from, append(body, make([]byte, 16)...))
		tn.relay.inject(v.ID(), f)
	}
	// The same index again and again: one reset a second for it.
	same, _ := encodeFrame(frameData, from, append(u32be(99999), make([]byte, 16)...))
	// Inits from a key not on the roster, naming a member: refused within its budget.
	stranger, _ := NewIdentity()
	for i := range 1000 {
		hs, _ := newHandshake(stranger, true, tn.roster.Network, tn.ids[1].xPub[:], nil)
		msg1, _, _, _ := hs.WriteMessage(nil, u64be(2))
		f, _ := encodeFrame(frameHandshakeInit, from, handshakeInitBody(uint32(i)+1, msg1))
		tn.relay.inject(v.ID(), f)
		if i < 100 {
			tn.relay.inject(v.ID(), same)
		}
	}
	n := settle(t, "the forgeries to be handled", func() int { return queued(v) })
	// Resets within the peer's budget; refused for each init read, within the forged ceiling.
	if want := resetBurst*(22+frameOverhead) + failBurst*(19+frameOverhead); n > want {
		t.Fatalf("forged frames queued %d bytes of replies, want at most %d", n, want)
	}
	close(g)
	// The honest peer, untouched by that peer's budgets, is answered at once.
	if err := send(t, honest, v.ID(), []byte("still served")); err != nil {
		t.Fatal(err)
	}
	if m := recv(t, v); string(m.Bytes) != "still served" {
		t.Fatal(m)
	}
	// Per index: once a second.
	locked(v, func() {
		now := v.mono()
		if !v.sess.limits.allowReset("x", false, 1, now) || v.sess.limits.allowReset("x", false, 1, now) ||
			!v.sess.limits.allowReset("x", false, 1, now.Add(resetIndexEvery)) {
			t.Error("a reset per index per second")
		}
	})
}

func TestAnOverflowingQueueIsRedialledAndBudgetsCarryOver(t *testing.T) {
	defer func(n int) { maxChannelBytes = n }(maxChannelBytes)
	maxChannelBytes = 16 << 10
	tn := newTestNet(t, 2)
	log := &eventLog{}
	m := tn.start(1, func(o *MemberOptions) { o.OnEvent = log.add })
	conn := tn.relay.conn(m.ID())
	locked(m, func() { m.sess.limits.allowInit("someone", false, m.mono()) })
	g := gateWrites(tn, m.ID())
	defer close(g)
	msg := []byte(`{"type":"nothing","pad":"` + string(make([]byte, 1000)) + `"}`)
	sent := 0
	locked(m, func() {
		for sent < 1000 && m.relay.sendControl(msg) {
			sent++
		}
	})
	if sent > maxChannelBytes/len(msg)+1 {
		t.Fatalf("queued %d messages past the bound", sent)
	}
	eventually(t, "the connection to be given up", func() bool { return slices.Contains(log.codes(), 1006) })
	tn.clock.Advance(100 * time.Millisecond)
	eventually(t, "redialled", func() bool { return m.State() == StateConnected && tn.relay.conn(m.ID()) != conn })
	locked(m, func() {
		if n := m.sess.limits.strangers.Len(); n != 1 {
			t.Errorf("%d budgets kept across the redial, want the one spent", n)
		}
	})
}

// Handshake-inits from ids off the roster: each id has its own small budget, all of them
// together a ceiling, the ids are remembered in a bounded table, and a member's own budget is
// untouched by any of it. A dropped one asks the primary for its roster, at most once a
// second.
func TestInitsFromIdsOffTheRosterAreBudgeted(t *testing.T) {
	tn := newTestNet(t, 3)
	v := tn.start(1)
	m := tn.start(2)
	initFrom := func(sender *Identity, claimed string, index uint32) []byte {
		hs, _ := newHandshake(sender, true, tn.roster.Network, tn.ids[1].xPub[:], nil)
		msg1, _, _, _ := hs.WriteMessage(nil, u64be(2))
		from, _ := nodeIDToBytes(claimed)
		f, _ := encodeFrame(frameHandshakeInit, from, handshakeInitBody(index, msg1))
		return f
	}
	reads := func() int {
		var n int
		locked(v, func() { n = v.sess.stats.initsRead })
		return n
	}
	stranger, _ := NewIdentity()
	// One id off the roster: a burst of 8, and the rest dropped.
	for i := range 50 {
		tn.relay.inject(v.ID(), initFrom(stranger, stranger.ID(), uint32(i)+1))
	}
	if n := settle(t, "one stranger's inits", reads); n != strangerInitBurst {
		t.Fatalf("%d of one stranger's inits read, want %d", n, strangerInitBurst)
	}
	var asked time.Time
	locked(v, func() { asked = v.askedPrimary })
	if asked.IsZero() {
		t.Fatal("a dropped init from an id off the roster did not ask the primary")
	}
	// 400 more ids, one init each: the ceiling over all of them (256, less the 8 spent).
	for range 400 {
		id, _ := NewIdentity()
		tn.relay.inject(v.ID(), initFrom(id, id.ID(), 1))
	}
	if n := settle(t, "the strangers' inits", reads); n != strangersInitBurst {
		t.Fatalf("%d inits read from ids off the roster, want the ceiling of %d", n, strangersInitBurst)
	}
	locked(v, func() {
		if n := v.sess.limits.strangers.Len(); n != strangerIDs {
			t.Errorf("%d ids remembered, want %d", n, strangerIDs)
		}
	})
	// The member, untouched: its handshake is read and answered.
	if err := send(t, m, v.ID(), []byte("still served")); err != nil {
		t.Fatal(err)
	}
	if got := recv(t, v); string(got.Bytes) != "still served" {
		t.Fatal(got)
	}
}

func TestPerPeerBoundsAreTheSpecs(t *testing.T) {
	if got := peerBufferLimit(DefaultCreditWindow); got != 2*64<<20+4<<20 {
		t.Fatalf("buffer bound %d", got)
	}
	if maxSessionsPerPeer != 8 || maxHeldMessagesPerPeer != 65536 || maxChannelBytes != 64<<20 {
		t.Fatal("bounds differ from section 7.3 and 11")
	}
}

// A fragment that says more follow carries at least one byte; an empty one ends the session.
func TestAnEmptyFragmentSayingMoreFollowEndsTheSession(t *testing.T) {
	tn := newTestNet(t, 3)
	a, b := tn.start(1), tn.start(2)
	if err := send(t, a, b.ID(), []byte("x")); err != nil {
		t.Fatal(err)
	}
	recv(t, b)
	rawSend(t, a, b.ID(), sessionMessage{typ: sessMessage, more: true})
	eventually(t, "the session to end", func() bool { return len(b.Sessions(a.ID())) == 0 })
	// An empty message that says nothing more follows is a message.
	send(t, a, b.ID(), []byte("lost"))
	eventually(t, "reset", func() bool { return len(a.Sessions(b.ID())) == 0 })
	if err := send(t, a, b.ID(), nil); err != nil {
		t.Fatal(err)
	}
	if got := recv(t, b); len(got.Bytes) != 0 {
		t.Fatal(got)
	}
}

// The send cap counts 64 bytes a frame besides its bytes, so many small frames cannot hold
// more memory than the cap says.
func TestTheSendCapCountsFrameOverhead(t *testing.T) {
	defer func(n int) { maxChannelBytes = n }(maxChannelBytes)
	maxChannelBytes = 100 * frameOverhead
	tn := newTestNet(t, 2)
	m := tn.start(1)
	g := gateWrites(tn, m.ID())
	defer close(g)
	sent := 0
	locked(m, func() {
		for sent < 10000 && m.relay.sendControl([]byte(`{}`)) {
			sent++
		}
	})
	if sent > maxChannelBytes/(2+frameOverhead) {
		t.Fatalf("%d two-byte frames queued under a cap of %d bytes", sent, maxChannelBytes)
	}
}

// A relay error's fields reach the application cut to 1 KiB, whole UTF-8 characters.
func TestRelayErrorFieldsAreCut(t *testing.T) {
	tn := newTestNet(t, 2)
	p := tn.start(0)
	got := make(chan RelayErrorEvent, 1)
	p.On(func(e Event) {
		if r, ok := e.(RelayErrorEvent); ok {
			got <- r
		}
	})
	long := strings.Repeat("é", 3000)
	b, _ := json.Marshal(map[string]string{"type": "error", "code": long, "message": long, "id": long})
	tn.relay.conn(p.ID()).push(fakeMsg{text: true, data: b})
	select {
	case e := <-got:
		for _, f := range []string{e.Code, e.Message, e.ID} {
			if len(f) > 1024 || len(f) < 1022 || !utf8.ValidString(f) {
				t.Fatalf("a field of %d bytes (valid UTF-8: %v)", len(f), utf8.ValidString(f))
			}
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no event")
	}
}

// Budgets and the roster hint carry across relay connections: a relay that forces reconnects
// gets nothing fresh for it.
func TestBudgetsCarryAcrossReconnects(t *testing.T) {
	tn := newTestNet(t, 3)
	m := tn.start(1)
	locked(m, func() {
		m.askPrimary()
		for m.sess.limits.allowInit("made-up", false, m.mono()) {
		}
	})
	conn := tn.relay.conn(m.ID())
	conn.kick(CloseGoingAway)
	eventually(t, "disconnected", func() bool { return m.State() == StateDisconnected })
	tn.clock.Advance(100 * time.Millisecond)
	eventually(t, "reconnected", func() bool { return m.State() == StateConnected && tn.relay.conn(m.ID()) != conn })
	locked(m, func() {
		if m.askedPrimary.IsZero() {
			t.Error("the hint time was forgotten on reconnect")
		}
		if m.sess.limits.allowInit("made-up", false, m.mono()) {
			t.Error("an id's spent budget was refilled by the reconnect")
		}
	})
}

// One-byte fragments cost their bytes in reassembly, not a slice each (the reviewer's proof:
// 4 Mi one-byte fragments held 156 MB when each was its own slice).
func TestTinyFragmentsCostTheirBytes(t *testing.T) {
	tn := newTestNet(t, 3)
	v, m := tn.start(1), tn.start(2)
	if err := send(t, m, v.ID(), []byte("hi")); err != nil {
		t.Fatal(err)
	}
	recv(t, v)
	const n = 4 << 20
	runtime.GC()
	var a, b runtime.MemStats
	runtime.ReadMemStats(&a)
	locked(v, func() {
		s := v.sess.peers[m.ID()].current
		for i := 0; i < n; i++ {
			s.allowance = 1 << 30 // credit returns at once while nothing is held; skip the round trip
			v.sess.onFragment(s, true, []byte{byte(i)})
		}
	})
	runtime.GC()
	runtime.ReadMemStats(&b)
	var counted int64
	locked(v, func() { counted = v.sess.peers[m.ID()].buffered })
	grew := int64(b.HeapAlloc) - int64(a.HeapAlloc)
	if counted != n || grew > 3*n {
		t.Fatalf("%d one-byte fragments: %d counted, heap grew %d bytes (%.1f a byte)", n, counted, grew, float64(grew)/float64(n))
	}
}

// Inits labelled with a member's id that fail the key check spend that id's own failure
// budget, never a shared one: several members sending bad-key inits as themselves (or a relay
// forging them under their ids) hold back only those ids, and an honest member still opens
// sessions at once.
func TestBadInitsSpendOnlyTheirOwnIdsBudget(t *testing.T) {
	tn := newTestNet(t, 12)
	v := tn.start(1)
	honest := tn.start(2)
	stranger, _ := NewIdentity()
	reads := func() int {
		var n int
		locked(v, func() { n = v.sess.stats.initsRead })
		return n
	}
	bad := func(index uint32) []byte {
		hs, _ := newHandshake(stranger, true, tn.roster.Network, tn.ids[1].xPub[:], nil)
		msg1, _, _, _ := hs.WriteMessage(nil, u64be(1))
		return handshakeInitBody(index, msg1)
	}
	// Eight members send 40 bad-key inits each, as themselves, through the relay.
	for i := 3; i < 11; i++ {
		m := tn.start(i)
		locked(m, func() {
			for j := range 40 {
				m.sendFrame(frameHandshakeInit, v.ID(), bad(uint32(j)+1))
			}
		})
	}
	// And a relay forges 40 more under the honest member's neighbour's id.
	from, _ := nodeIDToBytes(tn.ids[11].ID())
	for j := range 40 {
		f, _ := encodeFrame(frameHandshakeInit, from, bad(uint32(j)+1))
		tn.relay.inject(v.ID(), f)
	}
	if n := settle(t, "the bad inits", reads); n != 9*failBurst {
		t.Fatalf("%d bad inits read from 9 ids, want %d each", n, failBurst)
	}
	// The honest member, whose own budgets are untouched, is served at once: no time passes.
	before := currentIndex(honest, v.ID())
	if err := send(t, honest, v.ID(), []byte("served")); err != nil {
		t.Fatal(err)
	}
	if got := recv(t, v); string(got.Bytes) != "served" || currentIndex(honest, v.ID()) == before {
		t.Fatal(got)
	}
	// A bad id's budget refills with time: 2 a second.
	tn.clock.Advance(time.Second)
	for j := range 10 {
		f, _ := encodeFrame(frameHandshakeInit, from, bad(uint32(100+j)))
		tn.relay.inject(v.ID(), f)
	}
	if n := settle(t, "more bad inits", reads); n != 9*failBurst+1+failRate {
		t.Fatalf("%d inits read after a second", n)
	}
}

// Resets to ids off the roster have a ceiling over all of them, as their inits do.
func TestResetsToMadeUpIdsHaveACeiling(t *testing.T) {
	tn := newTestNet(t, 2)
	v := tn.start(1)
	g := gateWrites(tn, v.ID())
	defer close(g)
	for range 600 {
		id, _ := NewIdentity()
		from, _ := nodeIDToBytes(id.ID())
		f, _ := encodeFrame(frameData, from, append(u32be(7), make([]byte, 16)...))
		tn.relay.inject(v.ID(), f)
	}
	n := settle(t, "the forged frames", func() int { return queued(v) })
	if want := strangersResetBurst * (22 + frameOverhead); n != want {
		t.Fatalf("%d bytes of resets queued for 600 made-up ids, want the ceiling's %d", n, want)
	}
}

func TestJSONNumbersAreFinite(t *testing.T) {
	for _, in := range []string{`{"a":1e309}`, `[-1e999]`, `{"network":{"quotaUsed":1e400}}`} {
		if _, err := parseJSON([]byte(in)); err == nil {
			t.Errorf("%s accepted", in)
		}
	}
	for _, in := range []string{`{"a":1e308}`, `[-1.5e-400]`, `[0]`} {
		if _, err := parseJSON([]byte(in)); err != nil {
			t.Errorf("%s refused: %v", in, err)
		}
	}
}

// Member-labelled inits that do not even read spend the id's failure budget too.
func TestUnreadableMemberInitsSpendTheFailureBudget(t *testing.T) {
	tn := newTestNet(t, 30)
	v := tn.start(1)
	reads := func() int {
		var n int
		locked(v, func() { n = v.sess.stats.initsRead })
		return n
	}
	for _, id := range tn.ids[2:] {
		from, _ := nodeIDToBytes(id.ID())
		for i := range 10 {
			f, _ := encodeFrame(frameHandshakeInit, from, handshakeInitBody(uint32(i)+1, make([]byte, 120)))
			tn.relay.inject(v.ID(), f)
		}
	}
	if n := settle(t, "the unreadable inits", reads); n != 28*failBurst {
		t.Fatalf("%d unreadable inits read from 28 ids, want %d each", n, failBurst)
	}
}

// A forged member-labelled init claiming an old roster draws no roster push: its version is
// ignored.
func TestAForgedMemberInitDrawsNoRoster(t *testing.T) {
	tn := newTestNet(t, 380)
	size, _ := tn.roster.Size()
	v := tn.start(1)
	g := gateWrites(tn, v.ID())
	defer close(g)
	stranger, _ := NewIdentity()
	from, _ := nodeIDToBytes(tn.ids[2].ID())
	hs, _ := newHandshake(stranger, true, tn.roster.Network, tn.ids[1].xPub[:], nil)
	msg1, _, _, _ := hs.WriteMessage(nil, u64be(1)) // v holds version 2
	f, _ := encodeFrame(frameHandshakeInit, from, handshakeInitBody(1, msg1))
	tn.relay.inject(v.ID(), f)
	n := settle(t, "the forged init", func() int { return queued(v) })
	if n >= size || n != 19+frameOverhead {
		t.Fatalf("a forged init queued %d bytes, want only its refused frame", n)
	}
}

// Every rate, interval and timeout runs on the monotonic clock: a wall clock stepped back an
// hour strands no budget and suppresses no roster offer, and one stepped forward ends no
// connection for silence.
func TestAWallClockStepChangesNoBudget(t *testing.T) {
	tn := newTestNet(t, 3)
	v := tn.start(1, func(o *MemberOptions) { o.liveness = 0 })
	m := tn.start(2)
	// A session between them first: once the wall clock is an hour back, m's stamps would be
	// below v's floor (v started an hour "later") until the wall clock caught up.
	if err := send(t, m, v.ID(), []byte("hi")); err != nil {
		t.Fatal(err)
	}
	recv(t, v)
	reads := func() int {
		var n int
		locked(v, func() { n = v.sess.stats.initsRead })
		return n
	}
	stranger, _ := NewIdentity()
	from, _ := nodeIDToBytes(stranger.ID())
	inits := func(k int) {
		for i := range k {
			hs, _ := newHandshake(stranger, true, tn.roster.Network, tn.ids[1].xPub[:], nil)
			msg1, _, _, _ := hs.WriteMessage(nil, u64be(2))
			f, _ := encodeFrame(frameHandshakeInit, from, handshakeInitBody(uint32(i)+1, msg1))
			tn.relay.inject(v.ID(), f)
		}
	}
	base := reads() // m's own init
	inits(20)
	if n := settle(t, "a stranger's burst", reads); n != base+strangerInitBurst {
		t.Fatalf("%d read", n-base)
	}
	var asked time.Time
	locked(v, func() { asked = v.askedPrimary })
	tn.clock.StepWall(-time.Hour)
	tn.clock.Advance(2 * time.Second) // the hint's backed-off wait, after an ask that brought nothing
	inits(20)
	if n := settle(t, "the refill after the step back", reads); n != base+2*strangerInitBurst {
		t.Fatalf("%d read two seconds after the wall clock went back an hour", n)
	}
	locked(v, func() {
		if !v.askedPrimary.After(asked) {
			t.Error("the roster hint was suppressed by the step back")
		}
	})
	// A roster offer within the gap still goes at its end.
	locked(v, func() { v.sendRoster(m.ID()) }) // goes at once
	eventually(t, "the roster to be written", func() bool {
		var unsent bool
		locked(v, func() { st := v.rosterOut[m.ID()]; unsent = st.inflight || st.ch == nil || st.ch.unsent(st.end) })
		return !unsent
	})
	var first time.Time
	locked(v, func() {
		first = v.rosterOut[m.ID()].last
		v.sendRoster(m.ID()) // within the gap: coalesced to its end
	})
	tn.clock.StepWall(-time.Hour)
	tn.clock.Advance(rosterGap)
	locked(v, func() {
		if st := v.rosterOut[m.ID()]; st.timer != nil || !st.last.After(first) {
			t.Error("the coalesced roster offer did not go after the step back")
		}
	})
	// The relay's pings keep the connection: a wall step forward is no silence.
	conn := tn.relay.conn(v.ID())
	tn.clock.StepWall(24 * time.Hour)
	tn.clock.Advance(30 * time.Second)
	conn.ping()
	time.Sleep(20 * time.Millisecond)
	if v.State() != StateConnected || tn.relay.conn(v.ID()) != conn {
		t.Fatal("a wall step forward ended the connection")
	}
}

// A well-keyed member init whose payload is not the 8-byte version counts as a failed init.
func TestAMalformedPayloadFromAMemberIsAFailedInit(t *testing.T) {
	tn := newTestNet(t, 3)
	v := tn.start(1)
	from, _ := nodeIDToBytes(tn.ids[2].ID())
	for i := range 10 {
		hs, _ := newHandshake(tn.ids[2], true, tn.roster.Network, tn.ids[1].xPub[:], nil)
		msg1, _, _, _ := hs.WriteMessage(nil, []byte{1, 2, 3})
		f, _ := encodeFrame(frameHandshakeInit, from, handshakeInitBody(uint32(i)+1, msg1))
		tn.relay.inject(v.ID(), f)
	}
	n := settle(t, "the malformed inits", func() int {
		var n int
		locked(v, func() { n = v.sess.stats.initsRead })
		return n
	})
	if n != failBurst || len(v.Sessions(tn.ids[2].ID())) != 0 {
		t.Fatalf("%d malformed inits read, want %d", n, failBurst)
	}
}

// The roster hint backs off: after an ask of the primary that brings no newer roster, the wait
// before the next doubles, from a second up to 5 minutes, and a newer roster starts it over.
// (A relay can provoke the hint at every member at once; each ask draws a whole roster.)
func TestTheRosterHintBacksOff(t *testing.T) {
	tn := newTestNet(t, 3)
	tn.start(0)
	m := tn.start(1)
	sent := func() int {
		var n int
		locked(m, func() { n = m.hintsSent })
		return n
	}
	// Something provokes the hint every second; the asks that go (at once, or deferred to the
	// end of a wait) back off.
	var at []time.Duration
	for range 400 {
		before := sent()
		locked(m, func() { m.askPrimary() })
		if sent() > before {
			at = append(at, tn.clock.Mono())
		}
		before = sent()
		tn.clock.Advance(time.Second)
		if sent() > before {
			at = append(at, tn.clock.Mono())
		}
	}
	want := []time.Duration{0, 2, 6, 14, 30, 62, 126, 254}
	for i := range want {
		want[i] *= time.Second
	}
	if !slices.Equal(at, want) {
		t.Fatalf("asks at %v, want %v", at, want)
	}
	// It never waits longer than 5 minutes.
	for range 30 {
		tn.clock.Advance(time.Minute)
		locked(m, func() { m.askPrimary() })
	}
	locked(m, func() {
		if m.hintWait != hintWaitMax {
			t.Errorf("wait %v, want the cap", m.hintWait)
		}
	})
	// A newer roster starts it over: the next ask a second after the last.
	tn.clock.Advance(hintWaitMax)
	locked(m, func() { m.askPrimary() })
	n := sent()
	locked(m, func() { m.adoptRoster(tn.sign(3, tn.ids...)) })
	tn.clock.Advance(time.Second)
	locked(m, func() { m.askPrimary() })
	if sent() != n+1 {
		t.Fatal("a newer roster did not start the backoff over")
	}
}

// A hint the backoff holds back is deferred, not dropped: a member whose wait is at its
// longest, told by registered of a newer roster (a relay keeping a compact record sends only
// the version), asks the primary once the wait is over, and so drops a revoked member.
func TestASuppressedHintIsDeferred(t *testing.T) {
	tn := newTestNet(t, 4)
	pm := tn.start(0)
	v := tn.start(1)
	v3 := tn.sign(3, tn.ids[0], tn.ids[1], tn.ids[2]) // revokes ids[3]
	locked(pm, func() { pm.offerRoster(v3) })         // the primary holds it; v missed the push
	// v's wait is at its longest after unanswered asks; the last ask was just now.
	locked(v, func() { v.askedPrimary, v.hintWait, v.hintAnswered = v.mono(), hintWaitMax, false })
	var s0 int
	locked(v, func() { s0 = v.hintsSent })
	locked(v, func() { v.onRegistered(controlMessage{"type": "registered", "rosterVersion": json.Number("3")}) })
	for range 70 { // up to 7 minutes, past the 5-minute wait, with no further trigger
		tn.clock.Advance(6 * time.Second)
		var n int
		locked(v, func() { n = v.hintsSent })
		if n > s0 {
			break // let the ask's handshake run before more time passes
		}
	}
	eventually(t, "v to learn version 3 from the deferred ask", func() bool { return v.Roster().Version == 3 })
	var s1 int
	locked(v, func() { s1 = v.hintsSent })
	if s1-s0 != 1 {
		t.Fatalf("%d asks over 7 minutes, want the one deferred", s1-s0)
	}
	if _, still := v.Roster().FindMember(tn.ids[3].ID()); still {
		t.Fatal("the revoked member is still on v's roster")
	}
}

// The last stamp per member is kept apart from per-peer state: a peer that goes idle (its
// sessions forgotten) and a relay connection that drops (every session ended) leave it, so a
// replay of the peer's old init is still refused afterwards.
func TestStampsOutliveIdleAndReconnects(t *testing.T) {
	tn := newTestNet(t, 3)
	v := tn.start(1, func(o *MemberOptions) { o.Timing.Idle = time.Minute })
	tn.start(2)
	var first uint64
	old := memberInit(tn, tn.ids[2], tn.ids[1], 2, 1790000000500, 1)
	tn.relay.inject(v.ID(), old)
	eventually(t, "the init accepted", func() bool { return len(v.Sessions(tn.ids[2].ID())) == 1 })
	locked(v, func() { first = v.sess.stamps[tn.ids[2].ID()] })
	// Idle: the session is forgotten.
	tn.clock.Advance(2 * time.Minute)
	eventually(t, "idle expiry", func() bool { return len(v.Sessions(tn.ids[2].ID())) == 0 })
	// And the relay connection drops and comes back: every session ended.
	conn := tn.relay.conn(v.ID())
	conn.kick(CloseGoingAway)
	eventually(t, "disconnected", func() bool { return v.State() == StateDisconnected })
	tn.clock.Advance(100 * time.Millisecond)
	eventually(t, "reconnected", func() bool { return v.State() == StateConnected && tn.relay.conn(v.ID()) != conn })
	// The recorded init, replayed: still refused.
	reads := func() int {
		var n int
		locked(v, func() { n = v.sess.stats.initsRead })
		return n
	}
	before := reads()
	tn.relay.inject(v.ID(), old)
	eventually(t, "the replay read", func() bool { return reads() == before+1 })
	time.Sleep(20 * time.Millisecond)
	if len(v.Sessions(tn.ids[2].ID())) != 0 {
		t.Fatal("a replay after idle and a reconnect opened a session")
	}
	locked(v, func() {
		if v.sess.stamps[tn.ids[2].ID()] != first || first != 1790000000500 {
			t.Errorf("stamp %d, want %d", v.sess.stamps[tn.ids[2].ID()], first)
		}
	})
	// It is forgotten only when the id leaves the roster.
	locked(v, func() { v.adoptRoster(tn.sign(3, tn.ids[0], tn.ids[1])) })
	locked(v, func() {
		if _, kept := v.sess.stamps[tn.ids[2].ID()]; kept {
			t.Error("the stamp of an id off the roster was kept")
		}
	})
}

// stampProbe is a member v and a peer whose inits the test injects, with what v answers.
type stampProbe struct {
	t  *testing.T
	tn *testNet
	v  *Member
	n  uint32
}

func (p *stampProbe) now() uint64 { return uint64(p.tn.clock.Now().UnixMilli()) }

// accepted injects an init from ids[2] stamped stamp and reports whether v answered it.
func (p *stampProbe) accepted(stamp uint64) bool {
	answers := func() int {
		p.tn.relay.mu.Lock()
		defer p.tn.relay.mu.Unlock()
		return p.tn.relay.sentTypes[frameHandshakeResp]
	}
	reads := func() int {
		var n int
		locked(p.v, func() { n = p.v.sess.stats.initsRead })
		return n
	}
	p.n++
	before, read := answers(), reads()
	// The failure budget starts full: these tests are about the stamp rule.
	locked(p.v, func() {
		if l := p.v.sess.limits.members[p.tn.ids[2].ID()]; l != nil {
			l.fails = bucket{}
		}
	})
	p.tn.relay.inject(p.v.ID(), memberInit(p.tn, p.tn.ids[2], p.tn.ids[1], 2, stamp, p.n))
	eventually(p.t, "the init read", func() bool { return reads() > read })
	time.Sleep(30 * time.Millisecond)
	return answers() > before
}

func (p *stampProbe) stored() (uint64, bool) {
	var s uint64
	var ok bool
	locked(p.v, func() { s, ok = p.v.sess.stamps[p.tn.ids[2].ID()] })
	return s, ok
}

// An init stamped more than W = 10 minutes ahead of the responder's wall clock is refused and
// stores nothing (else it could be replayed until the clock caught up); one within W is
// accepted and stored as it is.
func TestStampsFarAheadAreRefused(t *testing.T) {
	tn := newTestNet(t, 3)
	p := &stampProbe{t: t, tn: tn, v: tn.start(1)}
	tn.start(2)
	if p.accepted(p.now() + 24*3600*1000) {
		t.Fatal("an init stamped a day ahead accepted")
	}
	if p.accepted(p.now() + stampWindowMs + 1) {
		t.Fatal("an init stamped just over 10 minutes ahead accepted")
	}
	if _, ok := p.stored(); ok {
		t.Fatal("a refused far-ahead init stored a stamp")
	}
	ahead := p.now() + stampWindowMs - 1000
	if !p.accepted(ahead) {
		t.Fatal("an init stamped within 10 minutes ahead refused")
	}
	if s, _ := p.stored(); s != ahead {
		t.Fatalf("stored %d, want the stamp %d as it is", s, ahead)
	}
}

// The floor is kept on the monotonic clock: a responder that started with its wall clock a
// day ahead, then had it put right, still accepts a fresh init stamped with the real time
// (a floor kept in wall time would have frozen a day ahead); and an init recorded before it
// started is still refused.
func TestAWallCorrectionDoesNotFreezeTheFloor(t *testing.T) {
	tn := newTestNet(t, 3)
	real := uint64(tn.clock.Now().UnixMilli())
	recorded := memberInit(tn, tn.ids[2], tn.ids[1], 2, real-stampWindowMs-60*1000, 99)
	tn.clock.StepWall(24 * time.Hour) // the responder starts with its clock a day ahead
	p := &stampProbe{t: t, tn: tn, v: tn.start(1)}
	tn.start(2)
	tn.clock.StepWall(-24 * time.Hour) // and it is put right
	if !p.accepted(p.now()) {
		t.Fatal("a fresh init refused after the wall clock was put right")
	}
	locked(p.v, func() { delete(p.v.sess.stamps, tn.ids[2].ID()) }) // back to the floor
	reads := func() int {
		var n int
		locked(p.v, func() { n = p.v.sess.stats.initsRead })
		return n
	}
	read := reads()
	tn.relay.inject(p.v.ID(), recorded)
	eventually(t, "the recorded init read", func() bool { return reads() > read })
	time.Sleep(30 * time.Millisecond)
	if _, ok := p.stored(); ok {
		t.Fatal("an init recorded before the start was accepted")
	}
}

// A member with no stamp stored is taken to have one 5 minutes before the later of the
// responder's start and its addition to the roster: after a restart (or a re-add) a relay
// cannot replay inits it recorded earlier.
func TestAfterARestartOldInitsAreRefused(t *testing.T) {
	tn := newTestNet(t, 3)
	tn.clock.Advance(time.Hour)
	now := func() uint64 { return uint64(tn.clock.Now().UnixMilli()) }
	recorded := memberInit(tn, tn.ids[2], tn.ids[1], 2, now()-11*60*1000, 1) // eleven minutes ago
	v := tn.start(1)                                                         // starts (restarts) now
	tn.start(2)
	reads := func() int {
		var n int
		locked(v, func() { n = v.sess.stats.initsRead })
		return n
	}
	answers := func() int {
		tn.relay.mu.Lock()
		defer tn.relay.mu.Unlock()
		return tn.relay.sentTypes[frameHandshakeResp]
	}
	accepted := func(f []byte) bool {
		before, read := answers(), reads()
		tn.relay.inject(v.ID(), f)
		eventually(t, "the init read", func() bool { return reads() > read })
		time.Sleep(30 * time.Millisecond)
		return answers() > before
	}
	if accepted(recorded) {
		t.Fatal("an init recorded ten minutes before the restart accepted")
	}
	if !accepted(memberInit(tn, tn.ids[2], tn.ids[1], 2, now(), 2)) {
		t.Fatal("a fresh init refused")
	}
	// (Re-admission and slow clocks have tests of their own.)
}

// Re-admitted after two minutes, a member's inits recorded before it was revoked are refused:
// its last stamp was retained when it left the roster, and restored when it came back (the
// floor alone, the re-add less W, would have let them through).
func TestAReAdmittedMemberRefusesPreRevocationInits(t *testing.T) {
	tn := newTestNet(t, 3)
	p := &stampProbe{t: t, tn: tn, v: tn.start(1)}
	tn.start(2)
	tn.clock.Advance(time.Hour)
	recorded := p.now()
	if !p.accepted(recorded) {
		t.Fatal("a fresh init refused")
	}
	initBefore := memberInit(tn, tn.ids[2], tn.ids[1], 2, recorded, 50)       // the same stamp, recorded
	locked(p.v, func() { p.v.adoptRoster(tn.sign(3, tn.ids[0], tn.ids[1])) }) // revoked
	tn.clock.Advance(2 * time.Minute)
	locked(p.v, func() { p.v.adoptRoster(tn.sign(4, tn.ids...)) }) // re-admitted
	if s, ok := p.stored(); !ok || s != recorded {
		t.Fatalf("stamp %d (%v) after re-admission, want the retained %d", s, ok, recorded)
	}
	reads := func() int {
		var n int
		locked(p.v, func() { n = p.v.sess.stats.initsRead })
		return n
	}
	read := reads()
	tn.relay.inject(p.v.ID(), initBefore)
	eventually(t, "the recorded init read", func() bool { return reads() > read })
	if s, _ := p.stored(); s != recorded {
		t.Fatal("an init recorded before the revocation was accepted")
	}
	if !p.accepted(p.now()) {
		t.Fatal("a fresh init after re-admission refused")
	}
	// The retained stamps are bounded.
	locked(p.v, func() {
		for i := range retainedCap + 10 {
			p.v.sess.retained.put(fmt.Sprint(i), 1)
		}
		if len(p.v.sess.retained.stamp) != retainedCap || len(p.v.sess.retained.order) != retainedCap {
			t.Errorf("%d retained", len(p.v.sess.retained.stamp))
		}
	})
}

// A member whose clock is 9 minutes slow is accepted right after the responder restarts: the
// floor is the start less W = 10 minutes.
func TestAMemberNineMinutesSlowIsAcceptedAfterARestart(t *testing.T) {
	tn := newTestNet(t, 3)
	tn.clock.Advance(time.Hour)
	p := &stampProbe{t: t, tn: tn, v: tn.start(1)} // starts now
	tn.start(2)
	if !p.accepted(p.now() - 9*60*1000) {
		t.Fatal("a member 9 minutes slow refused right after a restart")
	}
	locked(p.v, func() { delete(p.v.sess.stamps, tn.ids[2].ID()) })
	if p.accepted(p.now() - 11*60*1000) {
		t.Fatal("a member 11 minutes slow accepted right after a restart")
	}
}
