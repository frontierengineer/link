package relay

import (
	"container/list"
	"sync"
)

// idleRosters bounds what the relay keeps for networks nobody is connected to: their rosters,
// by signed size, in the order they went idle. Past LINK_IDLE_ROSTERS_BYTES the longest idle
// are forgotten first. Forgetting is what a restart does: the relay's copy is a cache, and the
// next member to register brings the roster back (section 4.2). So a node that creates
// networks to fill memory only pushes other idle caches out, never a network in use.
type idleRosters struct {
	mu    sync.Mutex // a leaf: taken under network.mu, nothing is taken under it
	order list.List  // *network, longest idle first
	bytes int64
}

// syncIdleLocked puts n in the idle order, or takes it out, as its members say; under n.mu.
func (s *Server) syncIdleLocked(n *network) {
	if s.cfg.IdleRostersBytes <= 0 {
		return
	}
	idle := len(n.members) == 0
	size := int64(len(n.roster.Raw))
	l := &s.idle
	l.mu.Lock()
	defer l.mu.Unlock()
	switch {
	case idle && n.idleAt == nil:
		n.idleAt, n.idleSize = l.order.PushBack(n), size
		l.bytes += size
	case idle:
		l.bytes += size - n.idleSize // a newer roster while idle
		n.idleSize = size
	case n.idleAt != nil:
		l.forgetLocked(n)
	}
}

func (l *idleRosters) forgetLocked(n *network) {
	l.order.Remove(n.idleAt)
	l.bytes -= n.idleSize
	n.idleAt, n.idleSize = nil, 0
}

// dropIdleLocked takes n out of the idle order as the relay forgets it; under n.mu.
func (s *Server) dropIdleLocked(n *network) {
	if n.idleAt == nil {
		return
	}
	s.idle.mu.Lock()
	s.idle.forgetLocked(n)
	s.idle.mu.Unlock()
}

// trimIdle forgets the longest idle networks while their rosters are over the budget. It is
// called holding no lock.
func (s *Server) trimIdle() {
	limit := s.cfg.IdleRostersBytes
	if limit <= 0 {
		return
	}
	for {
		s.idle.mu.Lock()
		if s.idle.bytes <= limit || s.idle.order.Len() == 0 {
			s.idle.mu.Unlock()
			return
		}
		n := s.idle.order.Front().Value.(*network)
		s.idle.mu.Unlock()
		sh := s.netShard(n.id)
		sh.mu.Lock()
		n.mu.Lock()
		// Still idle and still held: forget it. (A member that registered meanwhile took it out
		// of the order, and the loop looks at the next.)
		if n.idleAt != nil && len(n.members) == 0 && sh.m[n.id] == n {
			delete(sh.m, n.id)
			s.dropIdleLocked(n)
		}
		n.mu.Unlock()
		sh.mu.Unlock()
	}
}
