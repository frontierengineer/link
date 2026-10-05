package relay

import (
	"container/heap"
	"container/list"
	"sync"

	"github.com/frontierengineer/link/relay/internal/link"
)

// idleRosters bounds what the relay keeps for networks nobody is connected to
// (LINK_IDLE_ROSTERS_BYTES). The relay's roster is a cache of what the primary signed: the
// next member to register brings it back (section 4.2). While kept, it closes revoked members
// at registration and hands newer rosters to members that were offline.
//
// Each idle network counts against the address of the last member connected to it. Over the
// budget, room is made at the address holding the most: its longest idle roster is first cut
// to a compact record (version and member ids, enough to keep refusing revoked members), and
// only a compact record is forgotten outright. So an address that creates networks to fill
// memory evicts its own first, and a network of an address holding little is the last to go.
type idleRosters struct {
	mu     sync.Mutex // a leaf: taken under network.mu, nothing is taken under it
	owners map[string]*idleOwner
	byMost ownerHeap
	bytes  int64
}

// idleOwner is one address's idle networks, longest idle first.
type idleOwner struct {
	key   string
	order list.List // *network
	bytes int64
	index int // in byMost
}

type ownerHeap []*idleOwner

func (h ownerHeap) Len() int           { return len(h) }
func (h ownerHeap) Less(i, j int) bool { return h[i].bytes > h[j].bytes }
func (h ownerHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index, h[j].index = i, j
}
func (h *ownerHeap) Push(x any) {
	o := x.(*idleOwner)
	o.index = len(*h)
	*h = append(*h, o)
}
func (h *ownerHeap) Pop() any {
	old := *h
	o := old[len(old)-1]
	old[len(old)-1] = nil
	*h = old[:len(old)-1]
	return o
}

// rosterCost estimates the memory a held roster takes: the signed bytes and the parsed
// entries of a full roster, or the entries alone of a compact one.
func rosterCost(r *link.Roster) int64 {
	if r.Raw == nil {
		return 64 + 56*int64(len(r.Members))
	}
	return 64 + int64(len(r.Raw)) + 88*int64(len(r.Members))
}

// compactRoster keeps of r what judges membership: its network, version and member ids. A
// member's id is derived from its key, so the id alone admits only the holder of that key.
func compactRoster(r *link.Roster) *link.Roster {
	c := &link.Roster{Network: r.Network, Version: r.Version, Members: make([]link.Member, len(r.Members))}
	for i, m := range r.Members {
		c.Members[i] = link.Member{ID: m.ID}
	}
	return c
}

// syncIdleLocked puts n in the idle accounting, or takes it out, as its members say; under
// n.mu. owner is the address of the connection that changed it.
func (s *Server) syncIdleLocked(n *network, owner string) {
	if s.cfg.IdleRostersBytes <= 0 {
		return
	}
	l := &s.idle
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(n.members) > 0 {
		if n.idleAt != nil {
			l.removeLocked(n)
		}
		return
	}
	if n.idleAt != nil {
		l.resizeLocked(n) // a newer or a compacted roster while idle
		return
	}
	if l.owners == nil {
		l.owners = map[string]*idleOwner{}
	}
	o := l.owners[owner]
	if o == nil {
		o = &idleOwner{key: owner}
		l.owners[owner] = o
		heap.Push(&l.byMost, o)
	}
	n.idleAt, n.idleOwner, n.idleSize = o.order.PushBack(n), o, rosterCost(n.roster)
	o.bytes += n.idleSize
	l.bytes += n.idleSize
	heap.Fix(&l.byMost, o.index)
}

func (l *idleRosters) resizeLocked(n *network) {
	o, size := n.idleOwner, rosterCost(n.roster)
	o.bytes += size - n.idleSize
	l.bytes += size - n.idleSize
	n.idleSize = size
	heap.Fix(&l.byMost, o.index)
}

func (l *idleRosters) removeLocked(n *network) {
	o := n.idleOwner
	o.order.Remove(n.idleAt)
	o.bytes -= n.idleSize
	l.bytes -= n.idleSize
	n.idleAt, n.idleOwner, n.idleSize = nil, nil, 0
	if o.order.Len() == 0 {
		heap.Remove(&l.byMost, o.index)
		delete(l.owners, o.key)
	} else {
		heap.Fix(&l.byMost, o.index)
	}
}

// dropIdleLocked takes n out of the idle accounting as the relay forgets it; under n.mu.
func (s *Server) dropIdleLocked(n *network) {
	if n.idleAt == nil {
		return
	}
	s.idle.mu.Lock()
	s.idle.removeLocked(n)
	s.idle.mu.Unlock()
}

// trimIdle makes room while idle rosters are over the budget: at the address holding the
// most, its longest idle roster is compacted, or forgotten if it already is. It is called
// holding no lock.
func (s *Server) trimIdle() {
	limit := s.cfg.IdleRostersBytes
	if limit <= 0 {
		return
	}
	for {
		s.idle.mu.Lock()
		if s.idle.bytes <= limit || len(s.idle.byMost) == 0 {
			s.idle.mu.Unlock()
			return
		}
		n := s.idle.byMost[0].order.Front().Value.(*network)
		s.idle.mu.Unlock()
		sh := s.netShard(n.id)
		sh.mu.Lock()
		n.mu.Lock()
		// Still idle and still held. (A member that registered meanwhile took it out, and the
		// loop looks again.)
		if n.idleAt != nil && len(n.members) == 0 && sh.m[n.id] == n {
			if n.roster.Raw != nil {
				n.roster = compactRoster(n.roster)
				s.idle.mu.Lock()
				s.idle.resizeLocked(n)
				// Behind the owner's other rosters, so its full ones are cut before any record goes.
				n.idleOwner.order.MoveToBack(n.idleAt)
				s.idle.mu.Unlock()
			} else {
				delete(sh.m, n.id)
				s.dropIdleLocked(n)
			}
		}
		n.mu.Unlock()
		sh.mu.Unlock()
	}
}
