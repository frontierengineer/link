package relay

import (
	"crypto/rand"
	"encoding/json"
	"time"

	"github.com/frontierengineer/link/relay/internal/link"
)

// channel joins a newcomer to its network's primary while they pair (section 5.2).
type channel struct {
	id       link.ID
	newcomer *conn
	primary  *conn
	timer    *time.Timer
}

type pairingMsg struct {
	Type    string `json:"type"`
	Channel string `json:"channel"`
	Code    string `json:"code,omitempty"`
}

type pairEndMsg struct {
	Type    string `json:"type"`
	Channel string `json:"channel"`
}

func (c *conn) pair(data []byte) bool {
	s, now := c.s, time.Now()
	var m struct {
		Network *string `json:"network"`
		Code    *string `json:"code"`
	}
	if json.Unmarshal(data, &m) != nil || m.Network == nil || m.Code == nil {
		c.closeWith(closeBadRequest, "malformed pair", false)
		return false
	}
	netID, ok := link.ParseID(*m.Network)
	if _, okCode := link.DecodeKey(*m.Code, 8); !ok || !okCode {
		c.closeWith(closeBadRequest, "malformed pair", false)
		return false
	}
	if !s.ipPair.allow(c.ip, now) {
		c.sendError("rate_limited", "too many pairing attempts from this address", "")
		c.closeWith(closeRateLimited, "rate limited", true)
		return false
	}
	s.mu.Lock()
	n := s.networks[netID]
	s.mu.Unlock()
	var p *conn
	if n != nil {
		n.mu.Lock()
		p = n.members[netID]
		n.mu.Unlock()
	}
	if p == nil {
		c.sendError("unreachable", "the network's primary is not connected", "")
		c.closeWith(closeNormal, "nothing to pair with", true)
		return false
	}
	ch := &channel{newcomer: c, primary: p}
	rand.Read(ch.id[:])
	s.chmu.Lock()
	s.channels[ch.id] = ch
	if p.pairs == nil {
		p.pairs = map[link.ID]*channel{}
	}
	p.pairs[ch.id] = ch
	ch.timer = time.AfterFunc(s.cfg.PairTimeout, func() { s.endChannel(ch, true) })
	s.chmu.Unlock()
	c.state, c.channel = statePairing, ch
	c.nc.SetReadDeadline(time.Time{})
	chID := link.B64u.EncodeToString(ch.id[:])
	// The primary hears first, so it knows the channel before the newcomer's first frame.
	if !p.sendJSON(pairingMsg{Type: "pairing", Channel: chID, Code: *m.Code}) {
		s.endChannel(ch, false)
		return false
	}
	c.sendJSON(pairingMsg{Type: "pairing", Channel: chID})
	return true
}

// channelOf reads the channel named by a pairEnd message.
func (c *conn) channelOf(data []byte) (*channel, bool) {
	var m struct {
		Channel string `json:"channel"`
	}
	if json.Unmarshal(data, &m) != nil {
		return nil, false
	}
	raw, ok := link.DecodeKey(m.Channel, link.IDLen)
	if !ok {
		return nil, false
	}
	c.s.chmu.Lock()
	defer c.s.chmu.Unlock()
	ch := c.s.channels[link.ID(raw)]
	return ch, ch != nil
}

// endChannel ends a pairing channel once: the newcomer is closed 1000 after what is queued
// for it (the primary's last pair frame among it) is written. notifyPrimary tells the
// primary the channel is gone when it did not end it itself.
func (s *Server) endChannel(ch *channel, notifyPrimary bool) {
	s.chmu.Lock()
	if s.channels[ch.id] != ch {
		s.chmu.Unlock()
		return
	}
	delete(s.channels, ch.id)
	delete(ch.primary.pairs, ch.id)
	ch.timer.Stop()
	s.chmu.Unlock()
	if notifyPrimary {
		ch.primary.sendJSON(pairEndMsg{Type: "pairEnd", Channel: link.B64u.EncodeToString(ch.id[:])})
	}
	ch.newcomer.closeWith(closeNormal, "pairing ended", true)
}
