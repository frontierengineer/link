package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gobwas/ws"

	"github.com/frontierengineer/link/relay/internal/link"
)

const shards = 64

// Server is a relay. Create it with New, run it with Serve, stop it with Shutdown.
type Server struct {
	cfg Config

	mu       sync.Mutex // guards networks; taken before any network.mu
	networks map[link.ID]*network

	chmu     sync.Mutex // guards channels and every conn.pairs
	channels map[link.ID]*channel

	shard  [shards]connShard
	nextID atomic.Uint64
	conns  sync.WaitGroup

	ipRegister, ipPair, ipNetworks *ipLimiter

	closing  atomic.Bool
	stop     chan struct{}
	stopOnce sync.Once
	httpMu   sync.Mutex
	https    []*http.Server
}

type connShard struct {
	mu sync.Mutex
	m  map[*conn]struct{}
}

// New makes a relay and starts its timers.
func New(cfg Config) *Server {
	s := &Server{
		cfg:        cfg,
		networks:   map[link.ID]*network{},
		channels:   map[link.ID]*channel{},
		ipRegister: newIPLimiter(cfg.IPRegisterPerMin, time.Minute),
		ipPair:     newIPLimiter(cfg.IPPairPerMin, time.Minute),
		ipNetworks: newIPLimiter(cfg.IPNetworksPerHour, time.Hour),
		stop:       make(chan struct{}),
	}
	for i := range s.shard {
		s.shard[i].m = map[*conn]struct{}{}
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
	s.stopOnce.Do(func() { close(s.stop) })
	return err
}

func (s *Server) eachConn(f func(*conn)) {
	var all []*conn
	for i := range s.shard {
		sh := &s.shard[i]
		sh.mu.Lock()
		for c := range sh.m {
			all = append(all, c)
		}
		sh.mu.Unlock()
	}
	for _, c := range all {
		f(c)
	}
}

func (s *Server) shardOf(c *conn) *connShard {
	return &s.shard[c.shardIx]
}

func (s *Server) upgrade(w http.ResponseWriter, r *http.Request) {
	if s.closing.Load() {
		http.Error(w, "relay shutting down", http.StatusServiceUnavailable)
		return
	}
	origin := s.originOf(r)
	ip := s.clientIP(r)
	nc, rw, _, err := ws.UpgradeHTTP(r, w)
	if err != nil {
		return
	}
	c := &conn{s: s, nc: nc, r: nc, ip: ip, origin: origin, done: make(chan struct{})}
	if rw != nil && rw.Reader.Buffered() > 0 {
		early, _ := rw.Reader.Peek(rw.Reader.Buffered())
		c.r = io.MultiReader(bytes.NewReader(bytes.Clone(early)), nc)
	}
	rand.Read(c.challenge[:])
	c.shardIx = uint8(s.nextID.Add(1) % shards)
	sh := s.shardOf(c)
	sh.mu.Lock()
	if s.closing.Load() {
		sh.mu.Unlock()
		nc.Close()
		return
	}
	sh.m[c] = struct{}{}
	s.conns.Add(1)
	sh.mu.Unlock()
	// A fresh goroutine, so the HTTP server's per-connection state and buffers, which live
	// on this handler's stack, are released.
	go c.serve()
}

// originOf is LINK_ORIGIN, else the request's Host, lowercased, without a default port.
func (s *Server) originOf(r *http.Request) string {
	if s.cfg.Origin != "" {
		return strings.ToLower(s.cfg.Origin)
	}
	host := strings.ToLower(r.Host)
	if h, p, err := net.SplitHostPort(host); err == nil && (p == "80" || p == "443") {
		if strings.Contains(h, ":") {
			h = "[" + h + "]"
		}
		host = h
	}
	return strings.Clone(host)
}

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			if ip := strings.TrimSpace(first); ip != "" {
				return strings.Clone(ip)
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.Clone(r.RemoteAddr)
	}
	return strings.Clone(host)
}

func (s *Server) unregister(c *conn) {
	if n := c.network; n != nil {
		n.mu.Lock()
		if n.members[c.id] == c {
			delete(n.members, c.id)
			if len(n.members) == 0 {
				n.emptySince = time.Now()
			}
		}
		n.mu.Unlock()
	}
	if ch := c.channel; ch != nil {
		s.endChannel(ch, true)
	}
	s.chmu.Lock()
	var owned []*channel
	for _, ch := range c.pairs {
		owned = append(owned, ch)
	}
	s.chmu.Unlock()
	for _, ch := range owned {
		s.endChannel(ch, false)
	}
	sh := s.shardOf(c)
	sh.mu.Lock()
	delete(sh.m, c)
	sh.mu.Unlock()
}

// pingLoop sends a WebSocket ping to every connection each interval and drops one that has
// not answered the previous ping (section 9).
func (s *Server) pingLoop() {
	t := time.NewTicker(s.cfg.PingInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
		}
		s.eachConn(func(c *conn) {
			if c.paused.Load() {
				return // its pong may be sitting unread behind frames we are holding back
			}
			if c.awaitingPong.Swap(true) {
				c.abort()
				return
			}
			c.enqueue(outFrame{op: ws.OpPing})
		})
	}
}

// janitorLoop forgets idle networks after LINK_NETWORK_TTL, forgets rate-limit state that
// has refilled, and re-evaluates quota alerts as the rolling hour moves on.
func (s *Server) janitorLoop() {
	every := min(time.Second, max(10*time.Millisecond, s.cfg.NetworkTTL/4))
	t := time.NewTicker(every)
	defer t.Stop()
	lastSweep := time.Now()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
		}
		now := time.Now()
		s.mu.Lock()
		for id, n := range s.networks {
			n.mu.Lock()
			if len(n.members) == 0 && now.Sub(n.emptySince) >= s.cfg.NetworkTTL {
				delete(s.networks, id)
				if n.alertTimer != nil {
					n.alertTimer.Stop()
				}
			} else if s.cfg.QuotaBytesHour > 0 {
				s.alertLocked(n, now)
			}
			n.mu.Unlock()
		}
		s.mu.Unlock()
		if now.Sub(lastSweep) >= time.Minute {
			lastSweep = now
			s.ipRegister.sweep(now)
			s.ipPair.sweep(now)
			s.ipNetworks.sweep(now)
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
