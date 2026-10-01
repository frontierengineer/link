package link

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// RosterContext prefixes the bytes a primary signs for a roster.
const RosterContext = "frontier-link/1/roster"

// Member kinds.
const (
	KindPrimary = "primary"
	KindWorker  = "worker"
	KindSurface = "surface"
	KindMCP     = "mcp"
)

const maxSafeInteger = 1<<53 - 1

// Member is one roster entry.
type Member struct {
	ID      ID
	Ed25519 ed25519.PublicKey
	Kind    string
}

// Roster is a roster that passed every validity rule of section 3.
type Roster struct {
	Network  ID
	Version  int64
	IssuedAt int64
	Primary  ed25519.PublicKey
	Members  []Member
	Raw      json.RawMessage // as received, for forwarding unchanged
}

// Member returns the entry for id, or nil.
func (r *Roster) Member(id ID) *Member {
	for i := range r.Members {
		if r.Members[i].ID == id {
			return &r.Members[i]
		}
	}
	return nil
}

// SigningInput is UTF-8("frontier-link/1/roster") || JCS(roster without "signature").
func SigningInput(roster map[string]any) ([]byte, error) {
	unsigned := make(map[string]any, len(roster))
	for k, v := range roster {
		if k != "signature" {
			unsigned[k] = v
		}
	}
	canon, err := Canonicalize(unsigned)
	if err != nil {
		return nil, err
	}
	return append([]byte(RosterContext), canon...), nil
}

// ParseRoster parses raw JSON and checks every validity rule of section 3, the signature
// included. A nil error means the roster is valid.
func ParseRoster(raw []byte) (*Roster, error) {
	tree, err := ParseJSON(raw)
	if err != nil {
		return nil, err
	}
	obj, ok := tree.(map[string]any)
	if !ok {
		return nil, errors.New("roster: not an object")
	}
	r := &Roster{Raw: json.RawMessage(bytes.Clone(raw))}

	netStr, ok := obj["network"].(string)
	if !ok {
		return nil, errors.New("roster: network missing")
	}
	if r.Network, ok = ParseID(netStr); !ok {
		return nil, errors.New("roster: network is not a node id")
	}
	if r.Version, err = integer(obj["version"]); err != nil || r.Version < 1 {
		return nil, errors.New("roster: version must be a positive integer")
	}
	if r.IssuedAt, err = integer(obj["issuedAt"]); err != nil || r.IssuedAt < 0 {
		return nil, errors.New("roster: issuedAt must be a non-negative integer")
	}
	if _, ok := obj["relay"].(string); !ok {
		return nil, errors.New("roster: relay missing")
	}
	primary, ok := obj["primary"].(map[string]any)
	if !ok {
		return nil, errors.New("roster: primary missing")
	}
	if r.Primary, err = keyField(primary, "ed25519"); err != nil {
		return nil, fmt.Errorf("roster: primary: %w", err)
	}
	members, ok := obj["members"].([]any)
	if !ok || len(members) == 0 {
		return nil, errors.New("roster: members missing")
	}
	primaries := 0
	for i, mv := range members {
		m, ok := mv.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("roster: member %d is not an object", i)
		}
		idStr, _ := m["id"].(string)
		id, ok := ParseID(idStr)
		if !ok {
			return nil, fmt.Errorf("roster: member %d: bad id", i)
		}
		pub, err := keyField(m, "ed25519")
		if err != nil {
			return nil, fmt.Errorf("roster: member %d: %w", i, err)
		}
		if _, err := keyField(m, "x25519"); err != nil {
			return nil, fmt.Errorf("roster: member %d: %w", i, err)
		}
		if IDFromKey(pub) != id {
			return nil, fmt.Errorf("roster: member %d: id is not derived from its key", i)
		}
		kind, _ := m["kind"].(string)
		switch kind {
		case KindPrimary:
			primaries++
			if !bytes.Equal(pub, r.Primary) || id != r.Network {
				return nil, errors.New("roster: the primary member does not match primary and network")
			}
		case KindWorker, KindSurface, KindMCP:
		default:
			return nil, fmt.Errorf("roster: member %d: unknown kind %q", i, kind)
		}
		if i > 0 && idStr <= members[i-1].(map[string]any)["id"].(string) {
			return nil, errors.New("roster: members are not sorted by id")
		}
		r.Members = append(r.Members, Member{ID: id, Ed25519: pub, Kind: kind})
	}
	if primaries != 1 {
		return nil, errors.New("roster: exactly one member must be the primary")
	}
	if IDFromKey(r.Primary) != r.Network {
		return nil, errors.New("roster: network is not derived from the primary key")
	}
	sigStr, ok := obj["signature"].(string)
	if !ok {
		return nil, errors.New("roster: signature missing")
	}
	sig, ok := DecodeKey(sigStr, ed25519.SignatureSize)
	if !ok {
		return nil, errors.New("roster: signature malformed")
	}
	msg, err := SigningInput(obj)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(r.Primary, msg, sig) {
		return nil, errors.New("roster: signature does not verify")
	}
	return r, nil
}

func keyField(m map[string]any, name string) (ed25519.PublicKey, error) {
	s, _ := m[name].(string)
	k, ok := DecodeKey(s, 32)
	if !ok {
		return nil, fmt.Errorf("%s is not a b64u 32-byte key", name)
	}
	return ed25519.PublicKey(k), nil
}

// integer accepts a JSON number written as an integer within the IEEE-754 safe range.
func integer(v any) (int64, error) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, errors.New("not a number")
	}
	i, err := strconv.ParseInt(string(n), 10, 64)
	if err != nil || i > maxSafeInteger || i < -maxSafeInteger {
		return 0, errors.New("not a safe integer")
	}
	return i, nil
}

// SignRoster adds a "signature" member to roster, signed by the primary's key.
func SignRoster(roster map[string]any, primary ed25519.PrivateKey) error {
	msg, err := SigningInput(roster)
	if err != nil {
		return err
	}
	roster["signature"] = B64u.EncodeToString(ed25519.Sign(primary, msg))
	return nil
}
