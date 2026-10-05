package relay

import (
	"bytes"
	"container/list"
	"crypto/ed25519"
	"encoding/json"
	"strconv"
	"sync"
	"time"

	"github.com/gobwas/ws"

	"github.com/frontierengineer/link/relay/internal/link"
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
	typeReset       = 0x07
	typeControl     = 0x08 // as data; delivered as data
)

const maxClockSkewMs = 300000

// Budgets per network (sections 4.3 and 9).
const (
	ctlRate    = 4096      // bytes per second of control read ahead of shaping
	ctlBurst   = 128 << 10 // and its burst
	usageEvery = 10 * time.Second
	usageBurst = 3
)

// network is what the relay holds for one network: its newest valid roster, its connected
// members, and three small counters of its own (section 9).
type network struct {
	id link.ID

	mu         sync.Mutex
	roster     *link.Roster
	members    map[link.ID]*conn
	emptySince int64         // s.mono()
	idleAt     *list.Element // in Server.idle while nobody is connected
	idleSize   int64
	hour       hourWindow // bytes charged over the last hour
	rateTAT    int64      // the rate bucket, as a theoretical arrival time
	ctlTAT     int64      // the control budget
	usageTAT   int64      // the usage-ask budget
}

// allowControl spends size bytes of the network's control budget, if it has them.
func (n *network) allowControl(s *Server, size int) bool {
	now := s.mono()
	n.mu.Lock()
	defer n.mu.Unlock()
	return allow(&n.ctlTAT, now, int64(size)*int64(time.Second)/ctlRate, ctlBurst*int64(time.Second)/ctlRate)
}

type registeredMsg struct {
	Type          string          `json:"type"`
	Node          string          `json:"node"`
	RosterVersion int64           `json:"rosterVersion"`
	Roster        json.RawMessage `json:"roster,omitempty"` // the relay's, when newer than the node's
}

// handleText handles a control message of wire bytes.
func (c *conn) handleText(data []byte, wire int) bool {
	c.charge(wire)
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
				c.s.endChannel(ch, true, false)
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
				c.s.endChannel(ch, false, true)
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
	// 6 and 7, against the effective roster, under the network's lock.
	return c.admit(r, nodeID, pub, now)
}

// admit settles the effective roster (the newer of the presented one and the relay's; a
// newer presented roster replaces the relay's), checks membership against it, and admits.
func (c *conn) admit(r *link.Roster, id link.ID, pub ed25519.PublicKey, now time.Time) bool {
	s := c.s
	isMember := func(rr *link.Roster) bool {
		m := rr.Member(id)
		return m != nil && bytes.Equal(m.Ed25519, pub)
	}
	sh := s.netShard(r.Network)
	sh.mu.Lock()
	n := sh.m[r.Network]
	if n == nil {
		if !isMember(r) {
			sh.mu.Unlock()
			c.closeWith(closeNotMember, "not a member", false)
			return false
		}
		if !s.ipNetworks.allow(c.ip, now) {
			sh.mu.Unlock()
			c.sendError("rate_limited", "too many new networks from this address", "")
			c.closeWith(closeRateLimited, "rate limited", true)
			return false
		}
		n = &network{id: r.Network, roster: r, members: map[link.ID]*conn{}}
		sh.m[r.Network] = n
	}
	n.mu.Lock()
	sh.mu.Unlock()
	var evict []*conn
	var newer json.RawMessage
	switch {
	case r.Version > n.roster.Version:
		evict = n.adoptLocked(r, s.mono())
	case r.Version < n.roster.Version:
		newer = n.roster.Raw
	}
	member := isMember(n.roster)
	var old *conn
	if member {
		old = n.members[id]
		n.members[id] = c
		c.network, c.id, c.state = n, id, stateRegistered
		c.primary = id == n.id
		// Queued before the connection is visible to senders, so it is the first thing sent.
		c.sendJSON(registeredMsg{Type: "registered", Node: id.String(), RosterVersion: n.roster.Version, Roster: newer})
		if c.ipPending {
			s.ipConns.registered(c.ipc)
			c.ipPending = false
		}
	}
	s.syncIdleLocked(n)
	n.mu.Unlock()
	for _, e := range evict {
		e.closeWith(closeNotMember, "not a member", false)
	}
	if !member {
		c.closeWith(closeNotMember, "not a member", false)
		return false
	}

	c.nc.SetReadDeadline(time.Time{})
	c.origin, c.ip = "", ""
	if old != nil && old != c {
		old.closeWith(closeReplaced, "replaced by a newer connection", false)
	}
	return true
}

// adoptLocked installs a newer roster and returns the connections of nodes it dropped.
func (n *network) adoptLocked(r *link.Roster, now int64) []*conn {
	n.roster = r
	var evict []*conn
	for id, mc := range n.members {
		if r.Member(id) == nil {
			delete(n.members, id)
			evict = append(evict, mc)
		}
	}
	if len(n.members) == 0 {
		n.emptySince = now
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
	evict := n.adoptLocked(r, c.s.mono())
	c.s.syncIdleLocked(n)
	n.mu.Unlock()
	for _, e := range evict {
		e.closeWith(closeNotMember, "not a member", false)
	}
}

// handleBinary handles a routed frame of wire bytes; p has headroom in front of it.
func (c *conn) handleBinary(p []byte, wire int) bool {
	f := p[headroom:]
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
		if dst := c.channel.primary; dst.sendBinary(p) {
			c.waitQueue(dst)
		}
		return true
	case stateRegistered:
		switch f[1] {
		case typeInit, typeResp, typeData, typeRefused, typeReset, typeControl:
			c.route(p, peer, wire)
			return true
		case typePair:
			// The primary's side of pairing is its network's traffic like any other.
			c.charge(wire)
			c.s.chmu.Lock()
			ch := c.s.channels[peer]
			c.s.chmu.Unlock()
			if ch == nil || ch.primary != c || !ch.newcomer.sendBinary(p) {
				c.reply(ws.OpBinary, unreachable(peer))
				return true
			}
			c.waitQueue(ch.newcomer)
			return true
		}
	}
	c.closeWith(closeBadRequest, "unexpected frame", false)
	return false
}

// unreachable is the relay's answer for a peer that is not connected, headroom in front.
func unreachable(peer link.ID) []byte {
	p := make([]byte, headroom+frameHeader)
	f := p[headroom:]
	f[0], f[1] = frameVersion, typeUnreachable
	copy(f[2:], peer[:])
	return p
}

// route charges a frame to the sender's network, whether or not it can be delivered, and
// forwards it to a connected member of that network with the peer field rewritten to the
// sender (and control delivered as data), then holds the sender back for back-pressure.
func (c *conn) route(p []byte, peer link.ID, wire int) {
	f := p[headroom:]
	n, now := c.network, c.s.mono()
	n.mu.Lock()
	dst := n.members[peer]
	wait := c.s.chargeLocked(n, wire, now)
	n.mu.Unlock()
	c.holdFor(now, wait)
	copy(f[2:frameHeader], c.id[:])
	if f[1] == typeControl {
		f[1] = typeData
	}
	if dst == nil || !dst.sendBinary(p) {
		c.reply(ws.OpBinary, unreachable(peer))
		return
	}
	c.waitQueue(dst)
}

// chargeLocked counts size bytes against the network and returns how long its senders must
// wait for its bucket: LINK_RATE_BPS, or LINK_TRICKLE_BPS once the hourly quota is spent.
func (s *Server) chargeLocked(n *network, size int, now int64) time.Duration {
	n.hour.add(uint64(size), now)
	rate := s.cfg.RateBps
	if _, slowed := s.quotaLocked(n, now); slowed {
		rate = s.cfg.TrickleBps
	}
	return spend(&n.rateTAT, now, size, rate)
}

func (s *Server) quotaLocked(n *network, now int64) (used float64, slowed bool) {
	q := s.cfg.QuotaBytesHour
	if q <= 0 {
		return 0, false
	}
	used = float64(n.hour.total(now)) / float64(q)
	return used, used >= 1 && s.cfg.TrickleBps > 0
}

type usageLimits struct {
	RateBps        int64 `json:"rateBps"`
	QuotaBytesHour int64 `json:"quotaBytesHour"`
	TrickleBps     int64 `json:"trickleBps"`
}

type usageNetwork struct {
	BytesHour   uint64      `json:"bytesHour"`
	Connections int         `json:"connections"`
	Limits      usageLimits `json:"limits"`
	QuotaUsed   float64     `json:"quotaUsed"`
	Slowed      bool        `json:"slowed"`
}

type usageMsg struct {
	Type    string       `json:"type"`
	ID      string       `json:"id"`
	Network usageNetwork `json:"network"`
}

// usageRequest is section 4.3: the primary's, within the network's ask budget, answered with
// the network's totals.
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
	s, n, now := c.s, c.network, c.s.mono()
	n.mu.Lock()
	if !allow(&n.usageTAT, now, int64(usageEvery), usageBurst*int64(usageEvery)) {
		n.mu.Unlock()
		c.sendError("rate_limited", "usage asked too often", *m.ID)
		return
	}
	used, slowed := s.quotaLocked(n, now)
	resp := usageMsg{Type: "usage", ID: *m.ID, Network: usageNetwork{
		BytesHour: n.hour.total(now), Connections: len(n.members),
		Limits:    usageLimits{RateBps: s.cfg.RateBps, QuotaBytesHour: s.cfg.QuotaBytesHour, TrickleBps: s.cfg.TrickleBps},
		QuotaUsed: used, Slowed: slowed,
	}}
	n.mu.Unlock()
	c.reply(ws.OpText, marshal(resp))
}
