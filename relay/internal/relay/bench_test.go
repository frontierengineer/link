package relay

import (
	"io"
	"os"
	"strconv"
	"testing"
	"time"
)

// parkFromEnv lets the suite run with idle connections parked (the default) or each with
// its own reader goroutine (LINK_TEST_NO_PARK=1).
func parkFromEnv(c *Config) { c.ParkIdle = os.Getenv("LINK_TEST_NO_PARK") == "" }

// BenchmarkUnreachableFlood: a member sending small frames to an absent peer while reading
// the answers. One frame and one answer per op.
func BenchmarkUnreachableFlood(b *testing.B) {
	h := start(b, parkFromEnv)
	p, w := keys(b, 1), keys(b, 2)
	pc := h.register(p, p, roster(b, 1, p, w))
	f := rawFrame(true, 2, frame(typeData, w.ID, nil), 18)
	done := make(chan struct{})
	go func() {
		for range b.N {
			if _, _, err := pc.next(10 * time.Second); err != nil {
				panic(err)
			}
		}
		close(done)
	}()
	b.ResetTimer()
	for range b.N {
		pc.writeRaw(f)
	}
	<-done
}

// BenchmarkRelayFrame: one member sends 200-byte routed frames to another, both over bare
// sockets with prebuilt frames, so allocations per op are the relay's own.
func BenchmarkRelayFrame(b *testing.B) {
	for _, size := range []int{200, 16 << 10} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			h := start(b, func(c *Config) {
				parkFromEnv(c)
				c.PingInterval = time.Hour
			})
			p, w := keys(b, 1), keys(b, 2)
			r := roster(b, 1, p, w)
			pc, wc := h.register(p, p, r), h.register(w, p, r)
			out := rawFrame(true, 2, frame(typeData, p.ID, make([]byte, size-18)), size)
			in := make([]byte, wireSize(size))
			pc.ws.NetConn().SetReadDeadline(time.Time{}) // gorilla's, from registering
			done := make(chan struct{})
			go func() {
				defer close(done)
				for range b.N {
					if _, err := io.ReadFull(pc.ws.NetConn(), in); err != nil {
						panic(err)
					}
				}
			}()
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := wc.ws.NetConn().Write(out); err != nil {
					b.Fatal(err)
				}
			}
			<-done
		})
	}
}
