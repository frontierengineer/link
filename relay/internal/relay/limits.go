package relay

import (
	"sync"
	"time"
)

// ipLimiter allows n events per window per IP address, as a token bucket refilled evenly
// over the window.
type ipLimiter struct {
	n      float64
	window time.Duration
	mu     sync.Mutex
	ips    map[string]*ipBucket
}

type ipBucket struct {
	tokens float64
	last   time.Time
}

func newIPLimiter(n int, window time.Duration) *ipLimiter {
	if n <= 0 {
		return nil
	}
	return &ipLimiter{n: float64(n), window: window, ips: map[string]*ipBucket{}}
}

// allow takes one event for ip. A nil limiter allows everything.
func (l *ipLimiter) allow(ip string, now time.Time) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.ips[ip]
	if b == nil {
		b = &ipBucket{tokens: l.n, last: now}
		l.ips[ip] = b
	}
	b.tokens = min(l.n, b.tokens+now.Sub(b.last).Seconds()*l.n/l.window.Seconds())
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweep forgets addresses whose bucket is full again.
func (l *ipLimiter) sweep(now time.Time) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for ip, b := range l.ips {
		if now.Sub(b.last) >= l.window {
			delete(l.ips, ip)
		}
	}
}

// ipConns counts each address's open connections, and those not registered yet (pairing
// newcomers among them), against LINK_IP_CONNECTIONS and LINK_IP_PENDING (section 9). A nil
// ipConns (both off) counts nothing.
type ipConns struct {
	pending, total int32
	mu             sync.Mutex
	m              map[string]*ipCount
}

// ipCount is one address's connections; each conn holds its address's, and whether it is
// still one of the pending.
type ipCount struct {
	key            string
	pending, total int32
}

func newIPConns(pending, total int) *ipConns {
	if pending <= 0 && total <= 0 {
		return nil
	}
	return &ipConns{pending: int32(pending), total: int32(total), m: map[string]*ipCount{}}
}

// acquire counts a new, unregistered connection from ip, unless that takes the address over
// a limit.
func (l *ipConns) acquire(ip string) (*ipCount, bool) {
	if l == nil {
		return nil, true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.m[ip]
	if a == nil {
		a = &ipCount{key: ip}
	}
	if l.pending > 0 && a.pending >= l.pending || l.total > 0 && a.total >= l.total {
		return nil, false
	}
	a.pending++
	a.total++
	l.m[ip] = a
	return a, true
}

// registered moves a connection of a out of the pending.
func (l *ipConns) registered(a *ipCount) {
	if l == nil || a == nil {
		return
	}
	l.mu.Lock()
	a.pending--
	l.mu.Unlock()
}

// release ends a connection of a, still pending or not.
func (l *ipConns) release(a *ipCount, pending bool) {
	if l == nil || a == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	a.total--
	if pending {
		a.pending--
	}
	if a.total <= 0 {
		delete(l.m, a.key)
	}
}

// spend takes size bytes from a rate bucket of rate bytes per second holding one second of
// burst, kept as one theoretical arrival time (GCRA) on the relay's monotonic clock, and
// returns how long the sender must wait. The bucket may go into debt: a frame is always
// relayed whole, and its sender then waits the debt off.
func spend(tat *int64, now int64, size int, rate int64) time.Duration {
	if rate <= 0 {
		return 0
	}
	t := max(*tat, now) + int64(size)*int64(time.Second)/rate
	*tat = t
	return time.Duration(t - now - int64(time.Second))
}

// allow spends cost from a budget that refills one unit of time per unit of time and holds
// burst, kept as one theoretical arrival time: false, and nothing spent, when it lacks it.
func allow(tat *int64, now, cost, burst int64) bool {
	t := max(*tat, now) + cost
	if t-now > burst {
		return false
	}
	*tat = t
	return true
}

const (
	hourSlots = 12
	slotSpan  = int64(5 * time.Minute)
)

// hourWindow counts bytes over the last hour in twelve five-minute slots, with their sum.
type hourWindow struct {
	slots [hourSlots]uint64
	sum   uint64
	step  int64 // the five-minute step the newest slot belongs to
}

func (w *hourWindow) advance(now int64) {
	step := now / slotSpan
	if d := step - w.step; d >= hourSlots {
		w.slots, w.sum = [hourSlots]uint64{}, 0
	} else {
		for s := w.step + 1; s <= step; s++ {
			w.sum -= w.slots[s%hourSlots]
			w.slots[s%hourSlots] = 0
		}
	}
	w.step = step
}

func (w *hourWindow) add(n uint64, now int64) {
	if now/slotSpan != w.step {
		w.advance(now)
	}
	w.slots[w.step%hourSlots] += n
	w.sum += n
}

func (w *hourWindow) total(now int64) uint64 {
	if now/slotSpan != w.step {
		w.advance(now)
	}
	return w.sum
}
