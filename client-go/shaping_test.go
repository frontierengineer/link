package link

import (
	"bytes"
	"reflect"
	"sync"
	"testing"
	"time"
)

// Section 9's shaping notice and section 11's pacing: a member holds the relay's last notice
// and raises an event when it changes, and while shaped hands fragments over at 7/8 of the rate
// in force, a quarter of a second of that at most each, with about a second of it un-credited.

func shapingEvents(l *eventLog) []Shaping {
	var out []Shaping
	for _, e := range l.all() {
		if s, ok := e.(ShapingEvent); ok {
			out = append(out, s.Shaping)
		}
	}
	return out
}

func TestShapingNoticeIsHeldAndRaisedOnChange(t *testing.T) {
	tn := newTestNet(t, 2)
	tn.relay.features = []string{"control", "shaping"}
	tn.start(0)
	a := tn.start(1)
	log := record(a)
	if a.Shaping() != (Shaping{}) {
		t.Fatalf("before any notice: %+v", a.Shaping())
	}
	c := tn.relay.conn(a.ID())
	c.send(map[string]any{"type": "shaping", "rateBps": 1048576, "slowed": false})
	c.send(map[string]any{"type": "shaping", "rateBps": 16384, "slowed": true})
	// The same again changes nothing; malformed notices are ignored.
	c.send(map[string]any{"type": "shaping", "rateBps": 16384, "slowed": true})
	c.send(map[string]any{"type": "shaping", "rateBps": -1, "slowed": false})
	c.send(map[string]any{"type": "shaping", "rateBps": 1.5, "slowed": false})
	c.send(map[string]any{"type": "shaping", "rateBps": 5, "slowed": "no"})
	c.push(fakeMsg{text: true, data: []byte(`{"type":"shaping","rateBps":1e2,"slowed":false}`)})
	c.send(map[string]any{"type": "shaping", "slowed": false})
	c.send(map[string]any{"type": "shaping", "rateBps": 0, "slowed": false})
	eventually(t, "three changes", func() bool { return len(shapingEvents(log)) == 3 })
	want := []Shaping{{RateBps: 1048576}, {RateBps: 16384, Slowed: true}, {}}
	time.Sleep(20 * time.Millisecond)
	if got := shapingEvents(log); !reflect.DeepEqual(got, want) {
		t.Fatalf("events %+v, want %+v", got, want)
	}
	if a.Shaping() != (Shaping{}) {
		t.Fatalf("held %+v", a.Shaping())
	}
}

func TestARelayWithoutTheShapingFeatureLeavesAMemberUnshaped(t *testing.T) {
	tn := newTestNet(t, 2)
	tn.start(0)
	a := tn.start(1)
	tn.relay.conn(a.ID()).send(map[string]any{"type": "shaping", "rateBps": 16384, "slowed": true})
	eventually(t, "a notice from a relay that never says it sends them", func() bool { return a.Shaping().Slowed })
	tn.relay.conn(a.ID()).kick(CloseGoingAway)
	eventually(t, "unshaped at the next registration", func() bool {
		tn.clock.Advance(100 * time.Millisecond)
		return a.State() == StateConnected && a.Shaping() == (Shaping{})
	})
}

// paceNet is a, b and the primary, with every routed frame a sends recorded with the time on
// the members' clock.
type paceFrame struct {
	size int
	typ  byte
	at   time.Duration
}

func paceNet(t *testing.T) (tn *testNet, a, b *Member, frames func() []paceFrame) {
	tn = newTestNet(t, 3)
	tn.start(0)
	long := func(o *MemberOptions) { o.Timing.Idle = time.Hour }
	a, b = tn.start(1, long), tn.start(2, long)
	var mu sync.Mutex
	var seen []paceFrame
	from := a.ID()
	tn.relay.setIntercept(func(src, _ string, frame []byte) [][]byte {
		if src == from {
			mu.Lock()
			seen = append(seen, paceFrame{size: len(frame), typ: frame[1], at: tn.clock.Mono()})
			mu.Unlock()
		}
		return [][]byte{frame}
	})
	return tn, a, b, func() []paceFrame {
		mu.Lock()
		defer mu.Unlock()
		return append([]paceFrame(nil), seen...)
	}
}

// advance moves the members' clock by d in steps, letting their goroutines run between.
func advance(tn *testNet, d, step time.Duration) {
	for moved := time.Duration(0); moved < d; moved += step {
		tn.clock.Advance(step)
		time.Sleep(time.Millisecond)
	}
}

func TestPacingShapedAtTheRelaysRate(t *testing.T) {
	tn, a, b, frames := paceNet(t)
	if err := send(t, a, b.ID(), []byte("up")); err != nil {
		t.Fatal(err)
	}
	recv(t, b)
	const rate = 16384
	largest := pacedFragment(rate)
	if largest != 3584 {
		t.Fatalf("largest fragment %d", largest)
	}
	tn.relay.conn(a.ID()).send(map[string]any{"type": "shaping", "rateBps": rate, "slowed": true})
	eventually(t, "the notice", func() bool { return a.Shaping().RateBps == rate })
	from := len(frames())
	began := tn.clock.Mono()
	big := pattern(200_000, 3)
	done := a.SendAsync(b.ID(), big)
	advance(tn, 1500*time.Millisecond, 10*time.Millisecond)
	// Control goes at once, ahead of the fragments waiting.
	before := len(frames())
	sent := make(chan error, 1)
	locked(a, func() {
		a.sess.sendControl(b.ID(), sessionMessage{typ: sessRosterRequest}, func(err error) { sent <- err })
	})
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	eventually(t, "the control frame", func() bool { return len(frames()) > before })
	if f := frames()[before]; f.typ != frameData || f.size != 39 { // a roster-request
		t.Fatalf("control went as %+v", f)
	}
	var data []paceFrame
	for _, f := range frames()[from:before] {
		if f.typ == frameData {
			data = append(data, f)
		}
	}
	paced := 0
	for i, f := range data {
		if f.size > int(largest)+fragmentFrameOverhead {
			t.Fatalf("a %d-byte frame", f.size)
		}
		if i < len(data)-1 {
			paced += f.size
		}
	}
	elapsed := data[len(data)-1].at - began
	if limit := float64(rate) * 7 / 8 * elapsed.Seconds(); float64(paced) > limit+1 {
		t.Fatalf("%d bytes in %v, over %f", paced, elapsed, limit)
	}
	if len(data) < 4 || len(data) > 8 {
		t.Fatalf("%d fragments in 1.5 s", len(data))
	}
	// Unshaped again: the rest goes at once.
	tn.relay.conn(a.ID()).send(map[string]any{"type": "shaping", "rateBps": 0, "slowed": false})
	go func() {
		for range 200 {
			tn.clock.Advance(50 * time.Millisecond)
			time.Sleep(time.Millisecond)
		}
	}()
	if m := recv(t, b); !bytes.Equal(m.Bytes, big) {
		t.Fatal("differs")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPacingKeepsAboutOneFragmentUncreditedToAReceiverThatTakesNothing(t *testing.T) {
	tn, a, b, _ := paceNet(t)
	const rate = 16384
	tn.relay.conn(a.ID()).send(map[string]any{"type": "shaping", "rateBps": rate, "slowed": false})
	eventually(t, "the notice", func() bool { return a.Shaping().RateBps == rate })
	for range 20 {
		a.SendAsync(b.ID(), make([]byte, 5000))
	}
	advance(tn, 1500*time.Millisecond, 10*time.Millisecond)
	// Nothing is credited back while b holds a message, so the window is max(F, min(0, R/2)) =
	// F: at most one message past it, not the 64 KiB floor.
	s := a.Sessions(b.ID())
	if len(s) != 1 || s[0].Inflight < pacedFragment(rate) || s[0].Inflight >= pacedFragment(rate)+5000 {
		t.Fatalf("sessions %+v", s)
	}
}
