package relay

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"slices"
	"strconv"
	"strings"
)

// closeCodes are the codes the relay closes connections with, counted for /metrics.
var closeCodes = [...]int{
	closeNormal, closeGoingAway, closeProtocol, closeBadRequest, closeRateLimited,
	closeReplaced, closeSlowPeer, closeAuth, closeNotMember,
}

func closeIndex(code int) int {
	return slices.Index(closeCodes[:], code)
}

// AdminHandler serves the operator's API on LINK_ADMIN_ADDR: /health, /metrics, /drain and
// /reload. It has no authentication; it belongs on a private interface.
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "ok")
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		s.writeMetrics(w)
	})
	mux.HandleFunc("POST /drain", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("origin")
		o := s.originNamed(host)
		if o == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "origin not named in the limits file"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]int{"closed": s.Drain(o)})
	})
	mux.HandleFunc("POST /reload", func(w http.ResponseWriter, r *http.Request) {
		if err := s.ReloadLimits(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// Drain closes, 1001 after what is queued for them, every connection that dialled origin o,
// registered or not, and returns how many. Members reconnect (section 11), wherever the
// origin now leads.
func (s *Server) Drain(o *origin) int {
	closed := 0
	s.eachConn(func(c *conn) {
		if c.originRef == o {
			c.closeWith(closeGoingAway, "origin drained", true)
			closed++
		}
	})
	return closed
}

type originCounts struct {
	connections, networks, slowed int
	bytesHour                     uint64
}

// writeMetrics writes the relay's state in the Prometheus text format. It walks every network
// under its own lock, one shard at a time; no network or node id is ever written.
func (s *Server) writeMetrics(w io.Writer) {
	now := s.mono()
	var total int
	for i := range s.shard {
		sh := &s.shard[i]
		sh.mu.Lock()
		total += len(sh.m)
		sh.mu.Unlock()
	}
	var registered, connected, idle int
	var bytesHour uint64
	per := map[*origin]*originCounts{}
	count := func(o *origin) *originCounts {
		oc := per[o]
		if oc == nil {
			oc = &originCounts{}
			per[o] = oc
		}
		return oc
	}
	for i := range s.nets {
		sh := &s.nets[i]
		sh.mu.Lock()
		for _, n := range sh.m {
			n.mu.Lock()
			if len(n.members) == 0 {
				idle++
				n.mu.Unlock()
				continue
			}
			connected++
			registered += len(n.members)
			h := n.hour.total(now)
			bytesHour += h
			_, slowed := s.quotaLocked(n, now)
			for _, mc := range n.members {
				if mc.originRef != nil {
					count(mc.originRef).connections++
				}
			}
			if n.origin != nil {
				oc := count(n.origin)
				oc.networks++
				oc.bytesHour += h
				if slowed {
					oc.slowed++
				}
			}
			n.mu.Unlock()
		}
		sh.mu.Unlock()
	}

	var b strings.Builder
	metric := func(name, help, typ string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}
	metric("link_connections", "Open connections, by whether they have registered.", "gauge")
	fmt.Fprintf(&b, "link_connections{state=\"pending\"} %d\n", max(0, total-registered))
	fmt.Fprintf(&b, "link_connections{state=\"registered\"} %d\n", registered)
	metric("link_networks", "Networks held, by whether a member is connected.", "gauge")
	fmt.Fprintf(&b, "link_networks{state=\"connected\"} %d\n", connected)
	fmt.Fprintf(&b, "link_networks{state=\"idle\"} %d\n", idle)
	metric("link_bytes_hour", "Bytes charged over the last hour to networks with a member connected.", "gauge")
	fmt.Fprintf(&b, "link_bytes_hour %d\n", bytesHour)
	metric("link_closes_total", "Connections the relay closed, by close code.", "counter")
	for i, code := range closeCodes {
		fmt.Fprintf(&b, "link_closes_total{code=\"%d\"} %d\n", code, s.closes[i].Load())
	}

	var named []*origin
	for _, o := range *s.origins.Load() {
		if o.named.Load() {
			named = append(named, o)
		}
	}
	slices.SortFunc(named, func(a, b *origin) int { return cmp.Compare(a.name, b.name) })
	series := []struct {
		name, help string
		v          func(*originCounts) uint64
	}{
		{"link_origin_connections", "Registered connections, by the origin they dialled.", func(c *originCounts) uint64 { return uint64(c.connections) }},
		{"link_origin_networks", "Networks with a member connected, by the origin they were first registered through.", func(c *originCounts) uint64 { return uint64(c.networks) }},
		{"link_origin_bytes_hour", "Bytes charged over the last hour, by network origin.", func(c *originCounts) uint64 { return c.bytesHour }},
		{"link_origin_slowed_networks", "Networks on the trickle rate, their quota spent, by network origin.", func(c *originCounts) uint64 { return uint64(c.slowed) }},
	}
	var zero originCounts
	for _, m := range series {
		metric(m.name, m.help, "gauge")
		for _, o := range named {
			oc := per[o]
			if oc == nil {
				oc = &zero
			}
			fmt.Fprintf(&b, "%s{origin=%s} %d\n", m.name, strconv.Quote(o.name), m.v(oc))
		}
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	metric("go_goroutines", "Goroutines that currently exist.", "gauge")
	fmt.Fprintf(&b, "go_goroutines %d\n", runtime.NumGoroutine())
	metric("go_memstats_heap_inuse_bytes", "Bytes in in-use heap spans.", "gauge")
	fmt.Fprintf(&b, "go_memstats_heap_inuse_bytes %d\n", ms.HeapInuse)
	io.WriteString(w, b.String())
}
