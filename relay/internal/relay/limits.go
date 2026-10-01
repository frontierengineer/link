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

// bucket is a byte-rate token bucket holding at most one second of tokens. It may go into
// debt: a frame is always relayed whole, and the sender then waits the debt off.
type bucket struct {
	tokens float64
	last   time.Time
}

// take spends n bytes at rate bytes per second and returns how long the sender must wait.
func (b *bucket) take(n int, rate int64, now time.Time) time.Duration {
	if rate <= 0 {
		return 0
	}
	r := float64(rate)
	if b.last.IsZero() {
		b.tokens = r
	} else {
		b.tokens = min(r, b.tokens+now.Sub(b.last).Seconds()*r)
	}
	b.last = now
	b.tokens -= float64(n)
	if b.tokens >= 0 {
		return 0
	}
	return time.Duration(-b.tokens / r * float64(time.Second))
}

// usage counts bytes over a rolling hour (sixty one-minute slots) and a rolling day
// (twenty-four one-hour slots).
type usage struct {
	minutes [60]uint64
	hours   [24]uint64
	minute  int64 // the minute the newest slot belongs to
	hour    int64
}

func (u *usage) advance(now time.Time) {
	m, h := now.Unix()/60, now.Unix()/3600
	if d := m - u.minute; d >= 60 || d < 0 {
		u.minutes = [60]uint64{}
	} else {
		for i := u.minute + 1; i <= m; i++ {
			u.minutes[i%60] = 0
		}
	}
	if d := h - u.hour; d >= 24 || d < 0 {
		u.hours = [24]uint64{}
	} else {
		for i := u.hour + 1; i <= h; i++ {
			u.hours[i%24] = 0
		}
	}
	u.minute, u.hour = m, h
}

func (u *usage) add(n int, now time.Time) {
	u.advance(now)
	u.minutes[u.minute%60] += uint64(n)
	u.hours[u.hour%24] += uint64(n)
}

func (u *usage) totals(now time.Time) (hour, day uint64) {
	if u == nil {
		return 0, 0
	}
	u.advance(now)
	for _, v := range u.minutes {
		hour += v
	}
	for _, v := range u.hours {
		day += v
	}
	return hour, day
}
