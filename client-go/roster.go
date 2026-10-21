package link

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"time"
)

// The roster (section 3): the signed list of a network's members. The network key signs it,
// held by the primary alone; every member checks it against the network key it pinned.

// MaxRosterBytes is the most a roster's JCS encoding, signature included, may take
// (section 3): one session message.
const MaxRosterBytes = 65000

const rosterLabel = "frontier-link/1/roster"

// RosterMember is one roster entry. Keys are b64u of their 32 raw bytes.
type RosterMember struct {
	ID      string
	Ed25519 string
	X25519  string
	extra   map[string]any // members this version of the protocol does not define, kept as signed
}

// UnsignedRoster is a roster before the network key signs it.
type UnsignedRoster struct {
	Network    string
	Version    int64
	IssuedAt   int64 // Unix milliseconds
	Relay      string
	NetworkKey string // b64u of the network key's public half; Network is derived from it
	Primary    string // the node id of the primary, the member holding the network seed
	Members    []RosterMember
}

// Roster is a signed roster. Values of this type are never modified in place by this
// package; Clone before changing one. Members it does not define are kept as received, since
// the signature covers them.
type Roster struct {
	UnsignedRoster
	Signature string
	extra     map[string]any
}

// FindMember returns the entry for id.
func (r *Roster) FindMember(id string) (RosterMember, bool) {
	if m := r.member(id); m != nil {
		return *m, true
	}
	return RosterMember{}, false
}

// PrimaryID is the node id the roster names primary: the member holding the network seed
// (section 3.1).
func (r *Roster) PrimaryID() string { return r.Primary }

func (r *Roster) member(id string) *RosterMember {
	i, ok := slices.BinarySearchFunc(r.Members, id, func(m RosterMember, id string) int { return cmp.Compare(m.ID, id) })
	if ok {
		return &r.Members[i]
	}
	// A roster not yet validated may be unsorted.
	for i := range r.Members {
		if r.Members[i].ID == id {
			return &r.Members[i]
		}
	}
	return nil
}

// Clone is a deep copy that is safe to change or hand out.
func (r *Roster) Clone() *Roster {
	c := *r
	c.Members = slices.Clone(r.Members)
	return &c
}

func (m RosterMember) tree() map[string]any {
	t := make(map[string]any, 3+len(m.extra))
	for k, v := range m.extra {
		t[k] = v
	}
	t["id"], t["ed25519"], t["x25519"] = m.ID, m.Ed25519, m.X25519
	return t
}

func (u *UnsignedRoster) tree() map[string]any {
	members := make([]any, len(u.Members))
	for i, m := range u.Members {
		members[i] = m.tree()
	}
	return map[string]any{
		"network":    u.Network,
		"version":    u.Version,
		"issuedAt":   u.IssuedAt,
		"relay":      u.Relay,
		"networkKey": u.NetworkKey,
		"primary":    u.Primary,
		"members":    members,
	}
}

func (r *Roster) tree(withSignature bool) map[string]any {
	t := r.UnsignedRoster.tree()
	for k, v := range r.extra {
		if k != "signature" {
			t[k] = v
		}
	}
	if withSignature {
		t["signature"] = r.Signature
	}
	return t
}

// JCS is the roster's RFC 8785 encoding, signature included: what a session message carries.
func (r *Roster) JCS() ([]byte, error) { return canonicalize(r.tree(true)) }

// Size is the length of the roster's JCS encoding, signature included.
func (r *Roster) Size() (int, error) {
	b, err := r.JCS()
	return len(b), err
}

// SigningBytes is UTF-8("frontier-link/1/roster") || JCS(roster without "signature").
func (r *Roster) SigningBytes() ([]byte, error) {
	canon, err := canonicalize(r.tree(false))
	if err != nil {
		return nil, err
	}
	return append([]byte(rosterLabel), canon...), nil
}

// MarshalJSON writes the roster with its members in the order the TypeScript client writes
// them (network, version, issuedAt, relay, networkKey, primary, members, signature), then any
// others.
func (r Roster) MarshalJSON() ([]byte, error) {
	b := []byte(`{"network":`)
	var err error
	if b, err = appendJCSString(b, r.Network); err != nil {
		return nil, err
	}
	b = fmt.Appendf(b, `,"version":%d,"issuedAt":%d,"relay":`, r.Version, r.IssuedAt)
	if b, err = appendJCSString(b, r.Relay); err != nil {
		return nil, err
	}
	b = append(b, `,"networkKey":`...)
	if b, err = appendJCSString(b, r.NetworkKey); err != nil {
		return nil, err
	}
	b = append(b, `,"primary":`...)
	if b, err = appendJCSString(b, r.Primary); err != nil {
		return nil, err
	}
	b = append(b, `,"members":[`...)
	for i, m := range r.Members {
		if i > 0 {
			b = append(b, ',')
		}
		known := map[string]any{"id": m.ID, "ed25519": m.Ed25519, "x25519": m.X25519}
		if b, err = appendOrdered(b, []string{"id", "ed25519", "x25519"}, known, m.extra); err != nil {
			return nil, err
		}
	}
	b = append(b, `],"signature":`...)
	if b, err = appendJCSString(b, r.Signature); err != nil {
		return nil, err
	}
	for _, k := range sortedKeys(r.extra) {
		if k == "signature" {
			continue
		}
		b = append(b, ',')
		if b, err = appendJCSString(b, k); err != nil {
			return nil, err
		}
		b = append(b, ':')
		if b, err = appendJCS(b, r.extra[k]); err != nil {
			return nil, err
		}
	}
	return append(b, '}'), nil
}

func appendOrdered(b []byte, order []string, known, extra map[string]any) ([]byte, error) {
	var err error
	b = append(b, '{')
	first := true
	put := func(k string, v any) {
		if err != nil {
			return
		}
		if !first {
			b = append(b, ',')
		}
		first = false
		if b, err = appendJCSString(b, k); err == nil {
			b = append(b, ':')
			b, err = appendJCS(b, v)
		}
	}
	for _, k := range order {
		put(k, known[k])
	}
	for _, k := range sortedKeys(extra) {
		if _, dup := known[k]; !dup {
			put(k, extra[k])
		}
	}
	return append(b, '}'), err
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, compareUTF16)
	return keys
}

// UnmarshalJSON reads a roster strictly (no duplicate keys, no lone surrogates) and checks
// its shape: the types of the members the protocol defines. Validity is Problem's.
func (r *Roster) UnmarshalJSON(data []byte) error {
	tree, err := parseJSON(data)
	if err != nil {
		return err
	}
	got, err := rosterFromTree(tree)
	if err != nil {
		return err
	}
	*r = *got
	return nil
}

// DecodeRoster reads a roster's JSON and checks its shape, not its validity.
func DecodeRoster(data []byte) (*Roster, error) {
	var r Roster
	if err := r.UnmarshalJSON(data); err != nil {
		return nil, err
	}
	return &r, nil
}

// ValidateRoster reads a roster's JSON and checks every validity rule of section 3.
func ValidateRoster(data []byte) (*Roster, error) {
	r, err := DecodeRoster(data)
	if err != nil {
		return nil, err
	}
	if err := r.Problem(); err != nil {
		return nil, err
	}
	return r, nil
}

func rosterFromTree(tree any) (*Roster, error) {
	obj, ok := tree.(map[string]any)
	if !ok {
		return nil, errors.New("not an object")
	}
	r := &Roster{}
	var err error
	if r.Network, ok = obj["network"].(string); !ok {
		return nil, errors.New("network is not a node id")
	}
	if r.Version, ok = safeInteger(obj["version"]); !ok {
		return nil, errors.New("version is not a positive integer")
	}
	if r.IssuedAt, ok = safeInteger(obj["issuedAt"]); !ok {
		return nil, errors.New("issuedAt is not a non-negative integer")
	}
	if r.Relay, ok = obj["relay"].(string); !ok {
		return nil, errors.New("relay is not a string")
	}
	if r.NetworkKey, ok = obj["networkKey"].(string); !ok {
		return nil, errors.New("networkKey: not a string")
	}
	if r.Primary, ok = obj["primary"].(string); !ok {
		return nil, errors.New("primary is not a node id")
	}
	members, ok := obj["members"].([]any)
	if !ok {
		return nil, errors.New("members is not an array")
	}
	r.Members = make([]RosterMember, 0, len(members))
	for _, mv := range members {
		m, ok := mv.(map[string]any)
		if !ok {
			return nil, errors.New("member is not an object")
		}
		var e RosterMember
		if e.ID, ok = m["id"].(string); !ok {
			return nil, errors.New("member id is not a node id")
		}
		if e.Ed25519, ok = m["ed25519"].(string); !ok {
			return nil, errors.New("member ed25519: not a string")
		}
		if e.X25519, ok = m["x25519"].(string); !ok {
			return nil, errors.New("member x25519: not a string")
		}
		e.extra = without(m, "id", "ed25519", "x25519")
		r.Members = append(r.Members, e)
	}
	if r.Signature, ok = obj["signature"].(string); !ok {
		return nil, errors.New("signature: not a string")
	}
	r.extra = without(obj, "network", "version", "issuedAt", "relay", "networkKey", "primary", "members", "signature")
	return r, err
}

func without(m map[string]any, keys ...string) map[string]any {
	var out map[string]any
	for k, v := range m {
		if slices.Contains(keys, k) {
			continue
		}
		if out == nil {
			out = map[string]any{}
		}
		out[k] = v
	}
	return out
}

// Problem says why the roster is not valid (section 3, "Valid"), or returns nil.
func (r *Roster) Problem() error {
	if !IsNodeID(r.Network) {
		return errors.New("network is not an id")
	}
	if r.Version < 1 || r.Version > 1<<53-1 {
		return errors.New("version is not a positive integer")
	}
	if r.IssuedAt < 0 || r.IssuedAt > 1<<53-1 {
		return errors.New("issuedAt is not a non-negative integer")
	}
	networkKey, err := fromB64uLen(r.NetworkKey, 32, "networkKey")
	if err != nil {
		return err
	}
	if NodeIDFromEd25519(networkKey) != r.Network {
		return errors.New("network is not derived from networkKey")
	}
	if !IsNodeID(r.Primary) {
		return errors.New("primary is not a node id")
	}
	listed := false
	for i, m := range r.Members {
		if !IsNodeID(m.ID) {
			return errors.New("member id is not a node id")
		}
		if i > 0 && r.Members[i-1].ID >= m.ID {
			return errors.New("members are not sorted by id (or repeat)")
		}
		ed, err := fromB64uLen(m.Ed25519, 32, "member ed25519")
		if err != nil {
			return err
		}
		if _, err := fromB64uLen(m.X25519, 32, "member x25519"); err != nil {
			return err
		}
		if NodeIDFromEd25519(ed) != m.ID {
			return fmt.Errorf("member %s: id is not derived from its ed25519", m.ID)
		}
		if m.ID == r.Primary {
			listed = true
		}
	}
	if !listed {
		return errors.New("primary is not a member")
	}
	size, err := r.Size()
	if err != nil {
		return err
	}
	if size > MaxRosterBytes {
		return fmt.Errorf("roster is %d bytes, over the %d-byte limit", size, MaxRosterBytes)
	}
	sig, err := fromB64uLen(r.Signature, 64, "signature")
	if err != nil {
		return err
	}
	signed, err := r.SigningBytes()
	if err != nil {
		return err
	}
	if !verifyEd25519(networkKey, signed, sig) {
		return errors.New("signature does not verify")
	}
	return nil
}

// AcceptanceProblem applies section 3's acceptance rule: valid, signed by the pinned network
// key, and newer than the version held. It returns the reason for refusal, or nil to accept.
func AcceptanceProblem(candidate *Roster, pinnedNetworkKey string, heldVersion int64) error {
	if err := candidate.Problem(); err != nil {
		return err
	}
	if candidate.NetworkKey != pinnedNetworkKey {
		return errors.New("roster is signed by another network key")
	}
	if candidate.Version <= heldVersion {
		return errors.New("roster is not newer than the one held")
	}
	return nil
}

// MemberFromIdentity is the roster entry for an identity.
func MemberFromIdentity(id *Identity) RosterMember {
	return RosterMember{ID: id.ID(), Ed25519: b64u(id.edPub), X25519: b64u(id.xPub[:])}
}

// SignRoster sorts the members by id, then signs with the network key.
func SignRoster(u UnsignedRoster, key *NetworkKey) (*Roster, error) {
	u.Members = slices.Clone(u.Members)
	slices.SortFunc(u.Members, func(a, b RosterMember) int { return cmp.Compare(a.ID, b.ID) })
	r := &Roster{UnsignedRoster: u}
	signed, err := r.SigningBytes()
	if err != nil {
		return nil, err
	}
	r.Signature = b64u(key.Sign(signed))
	if err := r.Problem(); err != nil {
		return nil, fmt.Errorf("SignRoster: %w", err)
	}
	return r, nil
}

// CreateNetwork makes a new network (section 3.1): it mints a network seed, apart from the
// node's own (or takes networkSeed when not nil), and signs the first roster with its key:
// version 1, primary alone. It returns the roster and the network seed: persist the seed as
// secretly as the node's own, and hand it to the primary as MemberOptions.NetworkSeed.
func CreateNetwork(primary *Identity, relay string, now time.Time, networkSeed []byte) (*Roster, []byte, error) {
	if networkSeed == nil {
		var err error
		if networkSeed, err = NewNetworkSeed(); err != nil {
			return nil, nil, err
		}
	}
	key, err := NetworkKeyFromSeed(networkSeed)
	if err != nil {
		return nil, nil, err
	}
	r, err := SignRoster(UnsignedRoster{
		Network:    key.ID(),
		Version:    1,
		IssuedAt:   now.UnixMilli(),
		Relay:      relay,
		NetworkKey: b64u(key.edPub),
		Primary:    primary.ID(),
		Members:    []RosterMember{MemberFromIdentity(primary)},
	}, key)
	if err != nil {
		return nil, nil, err
	}
	return r, key.Seed(), nil
}

// x25519Of decodes a member's X25519 key.
func (m *RosterMember) x25519Of() ([]byte, error) { return fromB64uLen(m.X25519, 32, "x25519") }

// sameKey compares a member's b64u key with raw bytes in constant time.
func sameKey(b64 string, raw []byte) bool {
	k, err := fromB64uLen(b64, 32, "key")
	return err == nil && len(raw) == 32 && equalBytes(k, raw)
}
