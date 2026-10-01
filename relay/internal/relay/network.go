package relay

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strconv"
	"time"

	"github.com/frontierengineer/link/relay/internal/link"

	"sync"
)

// Routed frame layout (section 6).
const (
	frameHeader     = 18
	frameVersion    = 1
	typeInit        = 0x01
	typeResp        = 0x02
	typeData        = 0x03
	typeUnreachable = 0x04
	typeRefused     = 0x05
	typePair        = 0x06
)

const maxClockSkewMs = 300000

// network is what the relay holds for one network: its newest valid roster, its connected
// members, and its usage and shaping state.
type network struct {
	id link.ID

	mu          sync.Mutex
	roster      *link.Roster
	members     map[link.ID]*conn
	emptySince  time.Time
	usage       *usage             // made on the network's first relayed byte
	memberUsage map[link.ID]*usage // made on a member's first relayed byte
	bucket      bucket
	alertBand   int
	alertSlowed bool
	lastAlert   time.Time
	alertTimer  *time.Timer
}

type helloMsg struct {
	Type      string `json:"type"`
	Version   int    `json:"version"`
	Challenge string `json:"challenge"`
}

type registeredMsg struct {
	Type          string `json:"type"`
	Node          string `json:"node"`
	RosterVersion int64  `json:"rosterVersion"`
}

func (c *conn) handleText(data []byte) bool {
	var env struct {
		Type string `json:"type"`
		ID   any    `json:"id"`
	}
	if json.Unmarshal(data, &env) != nil || env.Type == "" {
		c.closeWith(closeBadRequest, "malformed message", false)
		return false
	}
	switch c.state {
	case stateHello:
		switch env.Type {
		case "register":
			return c.register(data)
		case "pair":
			return c.pair(data)
		}
		c.closeWith(closeBadRequest, "register or pair first", false)
		return false
	case statePairing:
		if env.Type == "pairEnd" {
			if ch, ok := c.channelOf(data); ok && ch == c.channel {
				c.s.endChannel(ch, true)
				return false
			}
		}
		c.closeWith(closeBadRequest, "only pair frames and pairEnd while pairing", false)
		return false
	}
	id, _ := env.ID.(string)
	switch env.Type {
	case "roster":
		c.pushRoster(data)
	case "usage":
		c.usageRequest(data)
	case "pairEnd":
		if ch, ok := c.channelOf(data); ok {
			c.s.chmu.Lock()
			mine := c.s.channels[ch.id] == ch && ch.primary == c
			c.s.chmu.Unlock()
			if mine {
				c.s.endChannel(ch, false)
			}
		}
	default:
		c.sendError("bad_request", "unknown message type "+strconv.Quote(env.Type), id)
	}
	return true
}

// register runs the checks of section 4.1, in order, closing on the first failure.
func (c *conn) register(data []byte) bool {
	s, now := c.s, time.Now()
	if !s.ipRegister.allow(c.ip, now) {
		c.sendError("rate_limited", "too many registrations from this address", "")
		c.closeWith(closeRateLimited, "rate limited", true)
		return false
	}
	fail := func(code int, reason string) bool {
		c.closeWith(code, reason, false)
		return false
	}

	// 1. Shape.
	var m struct {
		Network *string         `json:"network"`
		Node    *string         `json:"node"`
		Ed25519 *string         `json:"ed25519"`
		Ts      json.RawMessage `json:"ts"`
		Sig     *string         `json:"sig"`
		Roster  json.RawMessage `json:"roster"`
	}
	if json.Unmarshal(data, &m) != nil || m.Network == nil || m.Node == nil || m.Ed25519 == nil ||
		m.Sig == nil || len(m.Roster) == 0 || m.Roster[0] != '{' {
		return fail(closeBadRequest, "malformed register")
	}
	netID, ok1 := link.ParseID(*m.Network)
	nodeID, ok2 := link.ParseID(*m.Node)
	pub, ok3 := link.DecodeKey(*m.Ed25519, ed25519.PublicKeySize)
	sig, ok4 := link.DecodeKey(*m.Sig, ed25519.SignatureSize)
	ts, err := strconv.ParseUint(string(m.Ts), 10, 63)
	if !ok1 || !ok2 || !ok3 || !ok4 || err != nil {
		return fail(closeBadRequest, "malformed register")
	}
	// 2. The node id is derived from the key.
	if link.IDFromKey(pub) != nodeID {
		return fail(closeAuth, "node id is not derived from the key")
	}
	// 3. The signature, over our origin and our challenge.
	msg := link.RegisterMessage(*m.Network, *m.Node, c.challenge[:], ts, c.origin)
	if !ed25519.Verify(pub, msg, sig) {
		return fail(closeAuth, "bad signature")
	}
	// 4. The time.
	if d := now.UnixMilli() - int64(ts); d > maxClockSkewMs || d < -maxClockSkewMs {
		return fail(closeAuth, "stale timestamp")
	}
	// 5. The roster.
	r, err := link.ParseRoster(m.Roster)
	if err != nil {
		return fail(closeNotMember, "invalid roster")
	}
	if r.Network != netID {
		return fail(closeNotMember, "roster is for another network")
	}
	// 6. Membership.
	if mem := r.Member(nodeID); mem == nil || !bytes.Equal(mem.Ed25519, pub) {
		return fail(closeNotMember, "not a member")
	}
	// 7. Not older than what we hold; then admit.
	return c.admit(r, nodeID, now)
}

func (c *conn) admit(r *link.Roster, id link.ID, now time.Time) bool {
	s := c.s
	s.mu.Lock()
	n := s.networks[r.Network]
	if n == nil {
		if !s.ipNetworks.allow(c.ip, now) {
			s.mu.Unlock()
			c.sendError("rate_limited", "too many new networks from this address", "")
			c.closeWith(closeRateLimited, "rate limited", true)
			return false
		}
		n = &network{id: r.Network, roster: r, members: map[link.ID]*conn{}}
		s.networks[r.Network] = n
	}
	n.mu.Lock()
	s.mu.Unlock()
	if r.Version < n.roster.Version {
		n.mu.Unlock()
		c.closeWith(closeNotMember, "roster is older than the relay's", false)
		return false
	}
	var evict []*conn
	if r.Version > n.roster.Version {
		evict = n.adoptLocked(r)
	}
	old := n.members[id]
	n.members[id] = c
	c.network, c.id, c.state = n, id, stateRegistered
	c.primary = id == n.id
	// Queued before the connection is visible to senders, so it is the first thing sent.
	c.sendJSON(registeredMsg{Type: "registered", Node: id.String(), RosterVersion: n.roster.Version})
	n.mu.Unlock()

	c.nc.SetReadDeadline(time.Time{})
	c.origin = ""
	if old != nil && old != c {
		old.closeWith(closeReplaced, "replaced by a newer connection", false)
	}
	for _, e := range evict {
		e.closeWith(closeNotMember, "not a member", false)
	}
	return true
}

// adoptLocked installs a newer roster and returns the connections of nodes it dropped.
func (n *network) adoptLocked(r *link.Roster) []*conn {
	n.roster = r
	var evict []*conn
	for id, mc := range n.members {
		if r.Member(id) == nil {
			delete(n.members, id)
			evict = append(evict, mc)
		}
	}
	for id := range n.memberUsage {
		if r.Member(id) == nil {
			delete(n.memberUsage, id)
		}
	}
	if len(n.members) == 0 {
		n.emptySince = time.Now()
	}
	return evict
}

// pushRoster is section 4.2: from the primary only, valid and newer.
func (c *conn) pushRoster(data []byte) {
	if !c.primary {
		c.sendError("forbidden", "only the primary pushes rosters", "")
		return
	}
	var m struct {
		Roster json.RawMessage `json:"roster"`
	}
	if json.Unmarshal(data, &m) != nil || len(m.Roster) == 0 {
		c.sendError("bad_request", "roster missing", "")
		return
	}
	r, err := link.ParseRoster(m.Roster)
	if err != nil {
		c.sendError("bad_request", err.Error(), "")
		return
	}
	n := c.network
	if r.Network != n.id {
		c.sendError("bad_request", "roster is for another network", "")
		return
	}
	n.mu.Lock()
	if r.Version <= n.roster.Version {
		older := r.Version < n.roster.Version
		n.mu.Unlock()
		if older {
			c.sendError("bad_request", "roster is older than the relay's", "")
		}
		return
	}
	evict := n.adoptLocked(r)
	n.mu.Unlock()
	for _, e := range evict {
		e.closeWith(closeNotMember, "not a member", false)
	}
}

func (c *conn) handleBinary(f []byte) bool {
	if len(f) < frameHeader || f[0] != frameVersion {
		c.closeWith(closeBadRequest, "malformed frame", false)
		return false
	}
	var peer link.ID
	copy(peer[:], f[2:frameHeader])
	switch c.state {
	case statePairing:
		if f[1] != typePair || peer != c.channel.id {
			c.closeWith(closeBadRequest, "only pair frames on the channel while pairing", false)
			return false
		}
		if dst := c.channel.primary; dst.sendBinary(f) {
			c.waitQueue(dst)
		}
		return true
	case stateRegistered:
		switch f[1] {
		case typeInit, typeResp, typeData, typeRefused:
			c.route(f, peer)
			return true
		case typePair:
			c.s.chmu.Lock()
			ch := c.s.channels[peer]
			c.s.chmu.Unlock()
			if ch == nil || ch.primary != c || !ch.newcomer.sendBinary(f) {
				c.sendBinary(unreachable(peer))
				return true
			}
			c.waitQueue(ch.newcomer)
			return true
		}
	}
	c.closeWith(closeBadRequest, "unexpected frame", false)
	return false
}

func unreachable(peer link.ID) []byte {
	f := make([]byte, frameHeader)
	f[0], f[1] = frameVersion, typeUnreachable
	copy(f[2:], peer[:])
	return f
}

// route forwards a frame to a connected member of the sender's network, with the peer field
// rewritten to the sender, then holds the sender back for shaping and back-pressure.
func (c *conn) route(f []byte, peer link.ID) {
	n, now := c.network, time.Now()
	n.mu.Lock()
	dst := n.members[peer]
	var wait time.Duration
	if dst != nil {
		wait = c.s.accountLocked(n, c.id, len(f), now)
	}
	n.mu.Unlock()
	copy(f[2:frameHeader], c.id[:])
	if dst == nil || !dst.sendBinary(f) {
		c.sendBinary(unreachable(peer))
		return
	}
	c.waitQueue(dst)
	c.sleep(wait)
}

// accountLocked counts a relayed frame and returns how long its sender must wait for the
// network's bucket: LINK_RATE_BPS, or LINK_TRICKLE_BPS once the hourly quota is spent.
func (s *Server) accountLocked(n *network, from link.ID, size int, now time.Time) time.Duration {
	if n.usage == nil {
		n.usage = &usage{}
	}
	n.usage.add(size, now)
	mu := n.memberUsage[from]
	if mu == nil {
		if n.memberUsage == nil {
			n.memberUsage = map[link.ID]*usage{}
		}
		mu = &usage{}
		n.memberUsage[from] = mu
	}
	mu.add(size, now)
	rate := s.cfg.RateBps
	if _, slowed := s.quotaLocked(n, now); slowed {
		rate = s.cfg.TrickleBps
	}
	wait := n.bucket.take(size, rate, now)
	s.alertLocked(n, now)
	return wait
}

func (s *Server) quotaLocked(n *network, now time.Time) (used float64, slowed bool) {
	q := s.cfg.QuotaBytesHour
	if q <= 0 {
		return 0, false
	}
	hour, _ := n.usage.totals(now)
	used = float64(hour) / float64(q)
	return used, used >= 1 && s.cfg.TrickleBps > 0
}

func alertBand(used float64) int {
	switch {
	case used >= 1:
		return 4
	case used >= 0.95:
		return 3
	case used >= 0.8:
		return 2
	case used >= 0.5:
		return 1
	}
	return 0
}

type usageAlertMsg struct {
	Type      string  `json:"type"`
	QuotaUsed float64 `json:"quotaUsed"`
	Slowed    bool    `json:"slowed"`
}

// alertLocked pushes usageAlert to the primary when quotaUsed has crossed 0.5, 0.8, 0.95 or
// 1, or slowed has changed, since the last alert; at most once a second.
func (s *Server) alertLocked(n *network, now time.Time) {
	if s.cfg.QuotaBytesHour <= 0 {
		return
	}
	used, slowed := s.quotaLocked(n, now)
	band := alertBand(used)
	if band == n.alertBand && slowed == n.alertSlowed {
		return
	}
	p := n.members[n.id]
	if p == nil {
		return
	}
	if wait := n.lastAlert.Add(time.Second).Sub(now); wait > 0 {
		if n.alertTimer == nil {
			n.alertTimer = time.AfterFunc(wait, func() {
				n.mu.Lock()
				n.alertTimer = nil
				s.alertLocked(n, time.Now())
				n.mu.Unlock()
			})
		}
		return
	}
	n.alertBand, n.alertSlowed, n.lastAlert = band, slowed, now
	p.sendJSON(usageAlertMsg{Type: "usageAlert", QuotaUsed: used, Slowed: slowed})
}

type usageLimits struct {
	RateBps        int64 `json:"rateBps"`
	QuotaBytesHour int64 `json:"quotaBytesHour"`
	TrickleBps     int64 `json:"trickleBps"`
}

type usageNetwork struct {
	BytesHour   uint64      `json:"bytesHour"`
	BytesDay    uint64      `json:"bytesDay"`
	Connections int         `json:"connections"`
	Limits      usageLimits `json:"limits"`
	QuotaUsed   float64     `json:"quotaUsed"`
	Slowed      bool        `json:"slowed"`
}

type usageMember struct {
	ID        string `json:"id"`
	BytesHour uint64 `json:"bytesHour"`
	BytesDay  uint64 `json:"bytesDay"`
	Connected bool   `json:"connected"`
}

type usageMsg struct {
	Type    string        `json:"type"`
	ID      string        `json:"id"`
	Network usageNetwork  `json:"network"`
	Members []usageMember `json:"members"`
}

// usageRequest is section 4.3.
func (c *conn) usageRequest(data []byte) {
	var m struct {
		ID *string `json:"id"`
	}
	if json.Unmarshal(data, &m) != nil || m.ID == nil {
		c.sendError("bad_request", "usage needs a string id", "")
		return
	}
	if !c.primary {
		c.sendError("forbidden", "only the primary may ask for usage", *m.ID)
		return
	}
	s, n, now := c.s, c.network, time.Now()
	n.mu.Lock()
	hour, day := n.usage.totals(now)
	used, slowed := s.quotaLocked(n, now)
	resp := usageMsg{Type: "usage", ID: *m.ID, Network: usageNetwork{
		BytesHour: hour, BytesDay: day, Connections: len(n.members),
		Limits:    usageLimits{RateBps: s.cfg.RateBps, QuotaBytesHour: s.cfg.QuotaBytesHour, TrickleBps: s.cfg.TrickleBps},
		QuotaUsed: used, Slowed: slowed,
	}, Members: []usageMember{}}
	for _, mem := range n.roster.Members {
		h, d := n.memberUsage[mem.ID].totals(now)
		_, connected := n.members[mem.ID]
		resp.Members = append(resp.Members, usageMember{ID: mem.ID.String(), BytesHour: h, BytesDay: d, Connected: connected})
	}
	n.mu.Unlock()
	c.sendJSON(resp)
}
