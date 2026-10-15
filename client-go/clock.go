package link

import (
	"sort"
	"sync"
	"time"
)

// clock is the time source of a member: the real one, or a fake one in tests. It keeps two
// times apart. Now is the wall clock, for what the protocol writes down (a registration's ts,
// a roster's issuedAt, a resignation's ts, a code's expiry as shown). Mono is monotonic, for
// every interval, timeout and rate budget, so that a wall clock stepped back (or forward)
// cannot strand a budget, suppress a roster offer or end a session early.
type clock interface {
	Now() time.Time
	// Mono is the time elapsed on a monotonic clock since some fixed point.
	Mono() time.Duration
	// AfterFunc calls f in its own goroutine after d; the returned function stops it.
	AfterFunc(d time.Duration, f func()) (stop func() bool)
}

// monoStart is the real clock's fixed point; time.Since reads its monotonic reading.
var monoStart = time.Now()

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) Mono() time.Duration { return time.Since(monoStart) }

func (realClock) AfterFunc(d time.Duration, f func()) func() bool { return time.AfterFunc(d, f).Stop }

// monoEpoch turns a monotonic duration into a time.Time without a monotonic reading of its
// own, so that the code comparing times stays as it is: these times subtract to monotonic
// differences, and never meet a wall time.
var monoEpoch = time.Unix(0, 0)

// mono is the member's monotonic time.
func (m *Member) mono() time.Time { return monoEpoch.Add(m.clock.Mono()) }

// fakeClock moves only when told to. Timers due by the new time fire in time order, each in
// the calling goroutine of Advance, after the time has moved to their deadline. StepWall moves
// the wall clock alone, as an operator or NTP might.
type fakeClock struct {
	mu      sync.Mutex
	wall    time.Time
	elapsed time.Duration
	seq     int
	timers  map[int]*fakeTimer
}

type fakeTimer struct {
	at  time.Duration // on the monotonic clock
	seq int
	f   func()
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{wall: start, timers: map[int]*fakeTimer{}}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wall
}

func (c *fakeClock) Mono() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.elapsed
}

// StepWall moves the wall clock by d (back, when negative) and leaves the monotonic clock.
func (c *fakeClock) StepWall(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wall = c.wall.Add(d)
}

func (c *fakeClock) AfterFunc(d time.Duration, f func()) func() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	id := c.seq
	c.timers[id] = &fakeTimer{at: c.elapsed + d, seq: id, f: f}
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		_, ok := c.timers[id]
		delete(c.timers, id)
		return ok
	}
}

// Advance moves both clocks by d, firing every timer that falls due on the way, including
// timers those timers set.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	end := c.elapsed + d
	c.mu.Unlock()
	for {
		c.mu.Lock()
		var due []*fakeTimer
		for _, t := range c.timers {
			if t.at <= end {
				due = append(due, t)
			}
		}
		if len(due) == 0 {
			c.wall = c.wall.Add(end - c.elapsed)
			c.elapsed = end
			c.mu.Unlock()
			return
		}
		sort.Slice(due, func(i, j int) bool {
			if due[i].at != due[j].at {
				return due[i].at < due[j].at
			}
			return due[i].seq < due[j].seq
		})
		t := due[0]
		delete(c.timers, t.seq)
		if t.at > c.elapsed {
			c.wall = c.wall.Add(t.at - c.elapsed)
			c.elapsed = t.at
		}
		c.mu.Unlock()
		t.f()
	}
}

// pending is the number of timers waiting, for tests.
func (c *fakeClock) pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.timers)
}
