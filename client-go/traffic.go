package link

import "time"

// Traffic counts one direction.
type Traffic struct {
	// Whole application messages, and their payload bytes.
	Messages int64 `json:"messages"`
	Bytes    int64 `json:"bytes"`
	// Routed frames of every type (handshakes, credit and control included) and their full
	// size, header included: what the relay charges. Pairing frames are not counted.
	Frames     int64 `json:"frames"`
	FrameBytes int64 `json:"frameBytes"`
}

// PeerTraffic counts both directions with one peer, or in total.
type PeerTraffic struct {
	Sent     Traffic `json:"sent"`
	Received Traffic `json:"received"`
}

// RelayTraffic is the UTF-8 bytes of control messages exchanged with the relay.
type RelayTraffic struct {
	Sent     int64 `json:"sent"`
	Received int64 `json:"received"`
}

// TrafficReport is what this member sent and received since Since, per peer and in total.
// The relay keeps no per-member figures: each member counts its own.
type TrafficReport struct {
	Since int64                  `json:"since"` // Unix milliseconds: creation, or the last ResetTraffic
	Total PeerTraffic            `json:"total"`
	Relay RelayTraffic           `json:"relay"`
	Peers map[string]PeerTraffic `json:"peers"`
}

type trafficState struct {
	since     time.Time
	total     PeerTraffic
	peers     map[string]*PeerTraffic
	relayBase RelayTraffic
}

func (t *trafficState) reset(now time.Time) {
	t.since = now
	t.total = PeerTraffic{}
	t.peers = map[string]*PeerTraffic{}
}

// maxTrafficPeers bounds the peers counted one by one: far more than a roster holds, but a
// hostile relay naming made-up senders cannot grow the map beyond it. Past it, frames from
// peers not yet counted go to the total alone.
const maxTrafficPeers = 4096

// peer is the counters of a peer, or nil once maxTrafficPeers are counted.
func (t *trafficState) peer(_ *Member, id string) *PeerTraffic {
	p := t.peers[id]
	if p == nil {
		if len(t.peers) >= maxTrafficPeers {
			return nil
		}
		p = &PeerTraffic{}
		t.peers[id] = p
	}
	return p
}

func pick(p *PeerTraffic, sent bool) *Traffic {
	if sent {
		return &p.Sent
	}
	return &p.Received
}

func (t *trafficState) frame(m *Member, sent bool, peer string, size int) {
	for _, p := range []*PeerTraffic{&t.total, t.peer(m, peer)} {
		if p != nil {
			c := pick(p, sent)
			c.Frames++
			c.FrameBytes += int64(size)
		}
	}
}

func (t *trafficState) message(m *Member, sent bool, peer string, size int) {
	for _, p := range []*PeerTraffic{&t.total, t.peer(m, peer)} {
		if p != nil {
			c := pick(p, sent)
			c.Messages++
			c.Bytes += int64(size)
		}
	}
}

func (m *Member) countSent(peer string, size int) { m.traffic.message(m, true, peer, size) }

// Traffic reports what this member sent and received, per peer and in total, since it was
// created or ResetTraffic was called. It is always on.
func (m *Member) Traffic() TrafficReport {
	m.lock()
	defer m.unlock()
	r := TrafficReport{
		Since: m.traffic.since.UnixMilli(),
		Total: m.traffic.total,
		Relay: RelayTraffic{Sent: m.relay.textSent - m.traffic.relayBase.Sent, Received: m.relay.textReceived - m.traffic.relayBase.Received},
		Peers: map[string]PeerTraffic{},
	}
	for id, p := range m.traffic.peers {
		r.Peers[id] = *p
	}
	return r
}

// ResetTraffic starts the counts over.
func (m *Member) ResetTraffic() {
	m.lock()
	defer m.unlock()
	m.traffic.reset(m.clock.Now())
	m.traffic.relayBase = RelayTraffic{Sent: m.relay.textSent, Received: m.relay.textReceived}
}
