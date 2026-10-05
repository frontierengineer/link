package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gobwas/ws"

	"github.com/frontierengineer/link/relay/internal/link"
)

const shards = 64

// connKeys numbers connections across every Server in the process, so a poller event that
// strays to another server's set (a closed descriptor number reused) finds nothing there.
var connKeys atomic.Uint64

// Server is a relay. Create it with New, run it with Serve, stop it with Shutdown.
type Server struct {
	cfg   Config
	epoch time.Time // mono's zero

	nets [shards]netShard

	chmu     sync.Mutex // guards channels and every conn.pairs
	channels map[link.ID]*channel

	shard [shards]connShard
	conns sync.WaitGroup

	idle    idleRosters
	ipConns *ipConns
	poll    *poller // nil: every connection keeps a reader goroutine

	ipRegister, ipPair, ipNetworks *ipLimiter

	closing  atomic.Bool
	stop     chan struct{}
	stopOnce sync.Once
	httpMu   sync.Mutex
	https    []*http.Server
}

type connShard struct {
	mu sync.Mutex
	m  map[uint64]*conn
}

// netShard holds the networks whose id starts with its index; its mu is taken before any
// network.mu.
type netShard struct {
	mu sync.Mutex
	m  map[link.ID]*network
}

// New makes a relay and starts its timers.
func New(cfg Config) *Server {
	s := &Server{
		cfg:        cfg,
		epoch:      time.Now(),
		channels:   map[link.ID]*channel{},
		ipRegister: newIPLimiter(cfg.IPRegisterPerMin, time.Minute),
		ipPair:     newIPLimiter(cfg.IPPairPerMin, time.Minute),
		ipNetworks: newIPLimiter(cfg.IPNetworksPerHour, time.Hour),
		ipConns:    newIPConns(cfg.IPPending, cfg.IPConnections),
		stop:       make(chan struct{}),
	}
	for i := range s.shard {
		s.shard[i].m = map[uint64]*conn{}
		s.nets[i].m = map[link.ID]*network{}
	}
	if cfg.ParkIdle && cfg.TLSCert == "" {
		p, err := newPoller(s)
		if err != nil && !errors.Is(err, errNoPoller) {
			log.Printf("link-relay: idle connections keep a goroutine each: %v", err)
		}
		s.poll = p
	}
	go s.pingLoop()
	go s.janitorLoop()
	return s
}

// Handler serves /v1 (the WebSocket) and /health.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "ok")
	})
	mux.HandleFunc("GET /v1", s.upgrade)
	return mux
}

// Serve accepts connections on ln until Shutdown. With LINK_TLS_CERT and LINK_TLS_KEY set
// it terminates TLS itself.
func (s *Server) Serve(ln net.Listener) error {
	hs := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    16 << 10, // an upgrade request is a few hundred bytes

		// WebSockets need HTTP/1.1; never negotiate h2.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	s.httpMu.Lock()
	if s.closing.Load() {
		s.httpMu.Unlock()
		return http.ErrServerClosed
	}
	s.https = append(s.https, hs)
	s.httpMu.Unlock()
	if s.cfg.TLSCert != "" {
		return hs.ServeTLS(ln, s.cfg.TLSCert, s.cfg.TLSKey)
	}
	return hs.Serve(ln)
}

// Shutdown stops accepting, closes every connection 1001 after flushing what is queued for
// it, and waits for them to finish or ctx to end (then drops the rest).
func (s *Server) Shutdown(ctx context.Context) error {
	s.closing.Store(true)
	s.httpMu.Lock()
	hss := s.https
	s.httpMu.Unlock()
	for _, hs := range hss {
		hs.Shutdown(ctx)
	}
	s.eachConn(func(c *conn) { c.closeWith(closeGoingAway, "relay shutting down", true) })
	done := make(chan struct{})
	go func() { s.conns.Wait(); close(done) }()
	var err error
	select {
	case <-done:
	case <-ctx.Done():
		s.eachConn(func(c *conn) { c.nc.Close() })
		err = ctx.Err()
	}
	s.stopOnce.Do(func() {
		close(s.stop)
		s.poll.close()
	})
	return err
}

// mono is the relay's monotonic clock, in nanoseconds since New.
func (s *Server) mono() int64 { return int64(time.Since(s.epoch)) }

// eachConn calls f for every connection, one shard at a time, outside the shard's lock.
func (s *Server) eachConn(f func(*conn)) {
	var batch []*conn
	for i := range s.shard {
		batch = s.shardConns(i, batch)
		for _, c := range batch {
			f(c)
		}
	}
}

// shardConns copies shard i's connections into batch, reusing it.
func (s *Server) shardConns(i int, batch []*conn) []*conn {
	clear(batch)
	batch = batch[:0]
	sh := &s.shard[i]
	sh.mu.Lock()
	for _, c := range sh.m {
		batch = append(batch, c)
	}
	sh.mu.Unlock()
	return batch
}

func (s *Server) shardOf(key uint64) *connShard {
	return &s.shard[key%shards]
}

// lookup finds a connection by its key (for the poller).
func (s *Server) lookup(key uint64) *conn {
	sh := s.shardOf(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return sh.m[key]
}

func (s *Server) netShard(id link.ID) *netShard {
	return &s.nets[id[0]%shards]
}

// networkOf finds a network the relay holds.
func (s *Server) networkOf(id link.ID) *network {
	sh := s.netShard(id)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return sh.m[id]
}

func (s *Server) upgrade(w http.ResponseWriter, r *http.Request) {
	if s.closing.Load() {
		http.Error(w, "relay shutting down", http.StatusServiceUnavailable)
		return
	}
	origin := s.originOf(r)
	ip := s.clientIP(r)
	// Refused before the upgrade, so an address over its limits costs one HTTP answer.
	ipc, ok := s.ipConns.acquire(ip)
	if !ok {
		http.Error(w, "too many connections from this address", http.StatusTooManyRequests)
		return
	}
	nc, rw, _, err := ws.UpgradeHTTP(r, w)
	if err != nil {
		s.ipConns.release(ipc, true)
		return
	}
	c := &conn{s: s, nc: nc, ip: ip, ipc: ipc, ipPending: true, origin: origin, done: make(chan struct{})}
	c.rc = rawConnOf(nc)
	if rw != nil && rw.Reader.Buffered() > 0 {
		early, _ := rw.Reader.Peek(rw.Reader.Buffered())
		c.early = bytes.Clone(early)
	}
	rand.Read(c.challenge[:])
	c.key = connKeys.Add(1)
	sh := s.shardOf(c.key)
	sh.mu.Lock()
	if s.closing.Load() {
		sh.mu.Unlock()
		nc.Close()
		s.ipConns.release(ipc, true)
		return
	}
	sh.m[c.key] = c
	s.conns.Add(1)
	sh.mu.Unlock()
	// A fresh goroutine, so the HTTP server's per-connection state and buffers, which live
	// on this handler's stack, are released.
	go c.serve()
}

// originOf is LINK_ORIGIN, else the request's Host, lowercased, without the port when it is
// 80 or 443, whatever the scheme (section 4.1): what a member dialling it signed.
func (s *Server) originOf(r *http.Request) string {
	host := s.cfg.Origin
	if host == "" {
		host = r.Host
	}
	host = strings.ToLower(host)
	if h, p, err := net.SplitHostPort(host); err == nil && (p == "80" || p == "443") {
		if strings.Contains(h, ":") {
			h = "[" + h + "]"
		}
		host = h
	}
	return strings.Clone(host)
}

// clientIP is the key the per-IP limits count a request under (section 9): the peer's
// address, or with LINK_TRUST_PROXY at n, the n-th X-Forwarded-For entry from the right,
// which the outermost trusted proxy wrote; entries further left are the client's own words.
// IPv6 addresses count by their /64, which one subscriber usually holds whole.
func (s *Server) clientIP(r *http.Request) string {
	if n := s.cfg.TrustProxy; n > 0 {
		var hops []string
		for _, h := range r.Header.Values("X-Forwarded-For") {
			hops = append(hops, strings.Split(h, ",")...)
		}
		if len(hops) > 0 {
			if a, ok := parseAddr(hops[max(0, len(hops)-n)]); ok {
				return limiterKey(a)
			}
		}
	}
	if a, ok := parseAddr(r.RemoteAddr); ok {
		return limiterKey(a)
	}
	return strings.Clone(r.RemoteAddr)
}

// parseAddr reads an address, with or without a port.
func parseAddr(v string) (netip.Addr, bool) {
	v = strings.TrimSpace(v)
	if ap, err := netip.ParseAddrPort(v); err == nil {
		return ap.Addr(), true
	}
	a, err := netip.ParseAddr(v)
	return a, err == nil
}

func limiterKey(a netip.Addr) string {
	a = a.Unmap().WithZone("")
	if a.Is4() {
		return a.String()
	}
	return netip.PrefixFrom(a, 64).Masked().String()
}

func (s *Server) unregister(c *conn) {
	if n := c.network; n != nil {
		n.mu.Lock()
		if n.members[c.id] == c {
			delete(n.members, c.id)
			if len(n.members) == 0 {
				n.emptySince = s.mono()
			}
		}
		s.syncIdleLocked(n, c.ip)
		n.mu.Unlock()
		s.trimIdle()
	}
	s.ipConns.release(c.ipc, c.ipPending)
	if ch := c.channel; ch != nil {
		s.endChannel(ch, true, false) // the newcomer left
	}
	s.chmu.Lock()
	var owned []*channel
	for _, ch := range c.pairs {
		owned = append(owned, ch)
	}
	s.chmu.Unlock()
	for _, ch := range owned {
		s.endChannel(ch, false, true) // the primary left
	}
	sh := s.shardOf(c.key)
	sh.mu.Lock()
	delete(sh.m, c.key)
	sh.mu.Unlock()
}

// pingLoop pings every connection once each interval and drops one that has not answered
// the previous ping (section 9). It visits one shard per tick, so the pings of a large relay
// are spread over the interval rather than sent in one burst; a ping is written inline.
func (s *Server) pingLoop() {
	t := time.NewTicker(max(time.Millisecond, s.cfg.PingInterval/shards))
	defer t.Stop()
	var batch []*conn
	for i := 0; ; i = (i + 1) % shards {
		select {
		case <-s.stop:
			return
		case <-t.C:
		}
		batch = s.shardConns(i, batch)
		for _, c := range batch {
			if c.paused.Load() {
				continue // its pong may be sitting unread behind frames we are holding back
			}
			if c.awaitingPong.Swap(true) {
				c.abort()
				continue
			}
			c.ping()
		}
	}
}

// janitorLoop forgets idle networks after LINK_NETWORK_TTL and forgets rate-limit state that
// has refilled. It takes one network shard's lock at a time.
func (s *Server) janitorLoop() {
	t := time.NewTicker(min(time.Minute, max(10*time.Millisecond, s.cfg.NetworkTTL/4)))
	defer t.Stop()
	lastSweep := time.Now()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
		}
		now := s.mono()
		ttl := int64(s.cfg.NetworkTTL)
		for i := range s.nets {
			sh := &s.nets[i]
			sh.mu.Lock()
			for id, n := range sh.m {
				n.mu.Lock()
				if len(n.members) == 0 && now-n.emptySince >= ttl {
					delete(sh.m, id)
					s.dropIdleLocked(n)
				}
				n.mu.Unlock()
			}
			sh.mu.Unlock()
		}
		if wall := time.Now(); wall.Sub(lastSweep) >= time.Minute {
			lastSweep = wall
			s.ipRegister.sweep(wall)
			s.ipPair.sweep(wall)
			s.ipNetworks.sweep(wall)
		}
	}
}

// ListenAndServe listens on cfg.Addr and serves until Shutdown.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return err
	}
	err = s.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
