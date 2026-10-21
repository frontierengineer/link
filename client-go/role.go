package link

// Being the primary (section 3.1) is a trait of a member: it holds the network seed and its
// roster names it primary. A node started with the seed whose roster names another member
// claims the primary once registered, by signing the roster that names it; a node whose roster
// later names another member stops acting as the primary in place, on the same connection.
// The seed is the caller's: this package never stores, sends or deletes it.

// IsPrimary reports whether this node is the primary now: it holds the network seed and its
// roster names it primary.
func (m *Member) IsPrimary() bool {
	m.lock()
	defer m.unlock()
	return m.prim != nil
}

// HoldsNetworkSeed reports whether this node was given the network seed.
func (m *Member) HoldsNetworkSeed() bool {
	m.lock()
	defer m.unlock()
	return m.netKey != nil
}

// syncRole follows the roster held: the primary's state exists while this node holds the seed
// and the roster names it primary, and ends in place, its connection untouched, otherwise.
func (m *Member) syncRole() {
	if m.netKey != nil && m.roster.PrimaryID() == m.identity.ID() {
		if m.prim == nil {
			m.prim = newPrimaryState(m)
		}
		return
	}
	if m.prim != nil {
		ps := m.prim
		m.prim = nil
		ps.stop()
	}
}

// claim is section 3.1's "becoming the primary", once, at the first registration: a node
// holding the seed whose roster names another member primary signs the next roster naming
// itself primary, the members unchanged, and publishes it.
func (m *Member) claim() {
	self := m.identity.ID()
	if m.netKey == nil || m.roster.Primary == self || m.roster.member(self) == nil {
		return
	}
	u := m.nextUnsigned(m.roster.Members)
	u.Primary = self
	next, err := SignRoster(u, m.netKey)
	if err != nil {
		return
	}
	m.publish(next, "")
}
