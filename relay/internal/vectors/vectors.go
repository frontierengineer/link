// Package vectors generates spec/vectors/relay.json: key and id derivation of nodes and of
// networks, signed rosters (valid and invalid), registration signatures and routed frames, from
// fixed seeds.
package vectors

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/frontierengineer/link/relay/internal/link"
)

type keyVector struct {
	Seed          string `json:"seed"`
	Ed25519Seed   string `json:"ed25519Seed"`
	Ed25519       string `json:"ed25519"`
	X25519Private string `json:"x25519Private"`
	X25519        string `json:"x25519"`
	NodeID        string `json:"nodeId"`
	NodeIDRaw     string `json:"nodeIdRaw"`
}

// networkVector is a network seed and what follows from it (section 2).
type networkVector struct {
	Seed         string `json:"seed"`
	Ed25519Seed  string `json:"ed25519Seed"`
	Ed25519      string `json:"ed25519"`
	NetworkID    string `json:"networkId"`
	NetworkIDRaw string `json:"networkIdRaw"`
}

type rosterVector struct {
	Description  string          `json:"description"`
	Roster       json.RawMessage `json:"roster"`
	JCS          string          `json:"jcs,omitempty"`
	SigningInput string          `json:"signingInput,omitempty"`
	Signature    string          `json:"signature,omitempty"`
	Valid        bool            `json:"valid"`
}

// ed25519Vector is a signature check and its verdict under section 1's rule.
type ed25519Vector struct {
	Description string `json:"description"`
	Pub         string `json:"pub"`
	Msg         string `json:"msg"`
	Sig         string `json:"sig"`
	Valid       bool   `json:"valid"`
}

// rosterTextVector is a roster as the bytes a parser reads, for rules about the text itself.
type rosterTextVector struct {
	Description string `json:"description"`
	Text        string `json:"text"`
	Valid       bool   `json:"valid"`
}

type registrationVector struct {
	Description string `json:"description"`
	Network     string `json:"network"`
	Node        string `json:"node"`
	Ed25519     string `json:"ed25519"`
	Challenge   string `json:"challenge"`
	Ts          uint64 `json:"ts"`
	Origin      string `json:"origin"`
	Message     string `json:"message"`
	Sig         string `json:"sig"`
}

type frameVector struct {
	Description string `json:"description"`
	Sent        string `json:"sent"`
	Delivered   string `json:"delivered"`
}

type file struct {
	About         []string             `json:"about"`
	Keys          []keyVector          `json:"keys"`
	Networks      []networkVector      `json:"networks"`
	Rosters       []rosterVector       `json:"rosters"`
	RosterTexts   []rosterTextVector   `json:"rosterTexts"`
	Ed25519       []ed25519Vector      `json:"ed25519"`
	Registrations []registrationVector `json:"registrations"`
	Frames        []frameVector        `json:"frames"`
}

var b64 = link.B64u.EncodeToString

// Seeds are fixed; everything else follows from them (Ed25519 signatures are deterministic).
func seeds() [][]byte {
	inc := func(from byte) []byte {
		b := make([]byte, 32)
		for i := range b {
			b[i] = from + byte(i)
		}
		return b
	}
	return [][]byte{inc(0x00), inc(0x20), bytes.Repeat([]byte{0x42}, 32), bytes.Repeat([]byte{0xff}, 32)}
}

// networkSeeds are the network seeds, apart from every node's.
func networkSeeds() [][]byte {
	inc := make([]byte, 32)
	for i := range inc {
		inc[i] = 0x80 + byte(i)
	}
	return [][]byte{inc, bytes.Repeat([]byte{0x77}, 32)}
}

func member(k *link.Keys) map[string]any {
	return map[string]any{"id": k.ID.String(), "ed25519": b64(k.Ed25519Public), "x25519": b64(k.X25519Public)}
}

// rosterObject builds an unsigned roster of network n naming primary, with members sorted by id.
func rosterObject(n *link.NetworkKeys, version int64, primary *link.Keys, ms ...*link.Keys) map[string]any {
	list := make([]map[string]any, 0, len(ms))
	for _, m := range ms {
		list = append(list, member(m))
	}
	slices.SortFunc(list, func(a, b map[string]any) int {
		return bytes.Compare([]byte(a["id"].(string)), []byte(b["id"].(string)))
	})
	members := make([]any, len(list))
	for i, m := range list {
		members[i] = m
	}
	return map[string]any{
		"network":    n.ID.String(),
		"version":    version,
		"issuedAt":   int64(1790000000000),
		"relay":      "wss://eu.frontierengineer.link/v1",
		"networkKey": b64(n.Ed25519Public),
		"primary":    primary.ID.String(),
		"members":    members,
	}
}

func canonical(v map[string]any) json.RawMessage {
	b, err := link.Canonicalize(v)
	if err != nil {
		panic(err)
	}
	return b
}

func signedVector(desc string, r map[string]any, signer ed25519.PrivateKey) rosterVector {
	input, err := link.SigningInput(r)
	if err != nil {
		panic(err)
	}
	sig := ed25519.Sign(signer, input)
	r["signature"] = b64(sig)
	return rosterVector{
		Description:  desc,
		Roster:       canonical(r),
		JCS:          b64(input[len(link.RosterContext):]),
		SigningInput: b64(input),
		Signature:    b64(sig),
	}
}

// rosterTexts are rosters given as text: each invalid one is a signed roster written so that a
// lenient parser (last name wins, a lone surrogate becomes U+FFFD, 12.0 is 12) reads the
// signed roster back.
func rosterTexts(n *link.NetworkKeys, all []*link.Keys) []rosterTextVector {
	signedWith := func(edit func(map[string]any)) string {
		r := rosterObject(n, 12, all[0], all...)
		edit(r)
		return string(signedVector("", r, n.Ed25519).Roster)
	}
	signedText := func(relay string) string { return signedWith(func(r map[string]any) { r["relay"] = relay }) }
	// An extra member holding n arrays, one inside the next: the roster object is one more.
	nested := func(n int) any {
		var v any = []any{}
		for i := 1; i < n; i++ {
			v = []any{v}
		}
		return v
	}
	zeroIssued := signedWith(func(r map[string]any) { r["issuedAt"] = int64(0) })
	base := signedText("wss://eu.frontierengineer.link/v1")
	once := func(s, old, new string) string {
		if !strings.Contains(s, old) {
			panic("rosterTexts: no " + old)
		}
		return strings.Replace(s, old, new, 1)
	}
	replacement := signedText("wss://eu.frontierengineer.link/v1?\uFFFD")
	pair := signedText("wss://eu.frontierengineer.link/v1?\U0001F600")
	return []rosterTextVector{
		{"the JCS text of a valid roster", base, true},
		{"the same roster with whitespace between tokens", " \n" + strings.ReplaceAll(strings.ReplaceAll(base, ",\"", ",\n  \""), "\":", "\" : ") + "\n", true},
		{"version named twice, the signed value last", `{"version":999,` + base[1:], false},
		{"a member's x25519 named twice, the signed value last", once(base, `"x25519":`, `"x25519":"AAAA","x25519":`), false},
		{"version written 12.0", once(base, `"version":12`, `"version":12.0`), false},
		{"version written 1.2e1", once(base, `"version":12`, `"version":1.2e1`), false},
		{"issuedAt written 1.79e12", once(base, `"issuedAt":1790000000000`, `"issuedAt":1.79e12`), false},
		{"U+FFFD in relay, escaped", once(replacement, "\uFFFD", `\ufffd`), true},
		{"an escaped lone high surrogate where the network key signed U+FFFD", once(replacement, "\uFFFD", `\ud800`), false},
		{"an escaped lone low surrogate where the network key signed U+FFFD", once(replacement, "\uFFFD", `\udfff`), false},
		{"U+1F600 in relay, escaped as a surrogate pair", once(pair, "\U0001F600", `\ud83d\ude00`), true},
		{"issuedAt 0", zeroIssued, true},
		{"issuedAt written -0", once(zeroIssued, `"issuedAt":0`, `"issuedAt":-0`), false},
		{"nested 32 deep (an extra member of 31 arrays)", signedWith(func(r map[string]any) { r["x"] = nested(31) }), true},
		{"nested 33 deep (an extra member of 32 arrays)", signedWith(func(r map[string]any) { r["x"] = nested(32) }), false},
		{"an extra member 1e309, a number out of range", `{"x":1e309,` + base[1:], false},
	}
}

// Generate returns the file's bytes.
func Generate() ([]byte, error) {
	var ks []*link.Keys
	f := file{About: []string{
		"Generated by relay/cmd/vectors; relay/internal/vectors checks this file matches. Do not edit.",
		"Binary values are b64u (base64url, no padding) unless named hex.",
		"keys: seed -> HKDF-derived Ed25519 seed and key, clamped X25519 private key and its public key, node id (b32 of the first 16 bytes of SHA-256(ed25519)) and its raw bytes in hex.",
		"networks: network seed -> HKDF-derived Ed25519 seed (info \"frontier-link/1/network\") and the network key, network id (b32 of the first 16 bytes of SHA-256(network key)) and its raw bytes in hex. Networks are named by index: network 0 and network 1.",
		"rosters: roster is the full signed roster in JCS form. For signed cases jcs is JCS(roster without signature), signingInput is UTF-8(\"frontier-link/1/roster\") || jcs, signature is the Ed25519 signature by the network key. valid is whether a relay or member must find it valid (section 3).",
		"rosterTexts: text is a roster exactly as a parser reads it (UTF-8, escapes as written); valid is whether a relay or member must find it valid. Every JSON document is I-JSON (section 1): a repeated name, an escaped lone surrogate, a number out of range (1e309) or more than 32 arrays and objects open at once makes it invalid, as does a version or issuedAt not written as a non-negative integer literal, digits only (section 3), whatever a lenient parser would make of it.",
		"ed25519: pub, msg and sig (b64u) and whether section 1's verification accepts them: A and R canonical (y < p, no x = 0 with the sign bit set), neither of small order, S < L, and the cofactorless equation [S]B = R + [k]A. Cases where a lax or cofactored verifier would answer otherwise say so.",
		"registrations: message is lenStr(\"frontier-link/1/register\") || lenStr(network) || lenStr(node) || challenge || u64be(ts) || lenStr(origin); sig is the node's Ed25519 signature over it.",
		"frames: a routed frame (hex) as a member sends it and as the relay delivers it, with the peer field rewritten to the sender's raw id (and control, type 8, delivered as data, type 3).",
	}}
	for _, s := range seeds() {
		k, err := link.DeriveKeys(s)
		if err != nil {
			return nil, err
		}
		ks = append(ks, k)
		f.Keys = append(f.Keys, keyVector{
			Seed: b64(s), Ed25519Seed: b64(k.Ed25519Seed), Ed25519: b64(k.Ed25519Public),
			X25519Private: b64(k.X25519Private), X25519: b64(k.X25519Public),
			NodeID: k.ID.String(), NodeIDRaw: hex.EncodeToString(k.ID[:]),
		})
	}
	var ns []*link.NetworkKeys
	for _, s := range networkSeeds() {
		n, err := link.DeriveNetworkKeys(s)
		if err != nil {
			return nil, err
		}
		ns = append(ns, n)
		f.Networks = append(f.Networks, networkVector{
			Seed: b64(s), Ed25519Seed: b64(n.Ed25519Seed), Ed25519: b64(n.Ed25519Public),
			NetworkID: n.ID.String(), NetworkIDRaw: hex.EncodeToString(n.ID[:]),
		})
	}
	a, b, c, d := ks[0], ks[1], ks[2], ks[3]
	n0, n1 := ns[0], ns[1]
	all := []*link.Keys{a, b, c, d}
	withLabel := rosterObject(n0, 12, a, all...)
	for _, m := range withLabel["members"].([]any) {
		if m.(map[string]any)["id"] == d.ID.String() {
			m.(map[string]any)["kind"] = "label"
		}
	}

	valid := []rosterVector{
		signedVector("network 0, seed 0 the primary alone, version 1", rosterObject(n0, 1, a, a), n0.Ed25519),
		signedVector("network 0, four members, seed 0 the primary, version 12", rosterObject(n0, 12, a, all...), n0.Ed25519),
		signedVector("network 0 once seed 1 claimed the primary: seed 0, which created it, an ordinary member, version 13",
			rosterObject(n0, 13, b, all...), n0.Ed25519),
		signedVector("network 1: seed 2 is the primary, seed 0 a member", rosterObject(n1, 3, c, c, a), n1.Ed25519),
		signedVector("a member carrying a field the protocol does not define (kind): signed, and otherwise ignored", withLabel, n0.Ed25519),
	}
	for i := range valid {
		valid[i].Valid = true
	}
	f.Rosters = append(f.Rosters, valid...)

	invalid := func(desc string, mutate func(map[string]any), signer ed25519.PrivateKey) {
		r := rosterObject(n0, 13, a, all...)
		mutate(r)
		f.Rosters = append(f.Rosters, signedVector(desc, r, signer))
	}
	members := func(r map[string]any) []any { return r["members"].([]any) }
	byID := func(r map[string]any, k *link.Keys) map[string]any {
		for _, m := range members(r) {
			if m.(map[string]any)["id"] == k.ID.String() {
				return m.(map[string]any)
			}
		}
		panic("no such member")
	}
	invalid("signed by the primary's own node key, not the network key", func(map[string]any) {}, a.Ed25519)
	invalid("signed by a member's node key", func(map[string]any) {}, b.Ed25519)
	invalid("signed by another network's key", func(map[string]any) {}, n1.Ed25519)
	invalid("members not sorted by id", func(r map[string]any) { m := members(r); m[0], m[1] = m[1], m[0] }, n0.Ed25519)
	invalid("a member's id is not derived from its ed25519", func(r map[string]any) {
		byID(r, b)["ed25519"] = b64(c.Ed25519Public)
	}, n0.Ed25519)
	invalid("network is not the id derived from networkKey", func(r map[string]any) {
		r["networkKey"] = b64(n1.Ed25519Public)
	}, n1.Ed25519)
	invalid("network is the primary's node id, signed by its node key (the old rule), with networkKey missing", func(r map[string]any) {
		delete(r, "networkKey")
		r["network"] = a.ID.String()
		r["primary"] = map[string]any{"ed25519": b64(a.Ed25519Public)}
	}, a.Ed25519)
	invalid("primary missing", func(r map[string]any) { delete(r, "primary") }, n0.Ed25519)
	invalid("primary is not a node id", func(r map[string]any) { r["primary"] = "PRIMARY" }, n0.Ed25519)
	invalid("primary is not a member (the network id)", func(r map[string]any) { r["primary"] = n0.ID.String() }, n0.Ed25519)
	invalid("primary is not a member (a member removed)", func(r map[string]any) {
		r["members"] = slices.DeleteFunc(members(r), func(m any) bool { return m.(map[string]any)["id"] == a.ID.String() })
	}, n0.Ed25519)
	invalid("version 0", func(r map[string]any) { r["version"] = int64(0) }, n0.Ed25519)
	invalid("version is not an integer", func(r map[string]any) { r["version"] = 13.5 }, n0.Ed25519)
	{
		// Changed after signing: the signature no longer covers it.
		v := signedVector("version changed after signing", rosterObject(n0, 13, a, all...), n0.Ed25519)
		var r map[string]any
		dec := json.NewDecoder(bytes.NewReader(v.Roster))
		dec.UseNumber()
		if err := dec.Decode(&r); err != nil {
			return nil, err
		}
		r["version"] = int64(14)
		f.Rosters = append(f.Rosters, rosterVector{Description: v.Description, Roster: canonical(r)})
	}

	f.RosterTexts = rosterTexts(n0, all)
	f.Ed25519 = ed25519Vectors(a, b)

	challenge := make([]byte, 32)
	for i := range challenge {
		challenge[i] = byte(i + 1)
	}
	reg := func(desc string, k *link.Keys, network *link.NetworkKeys, ts uint64, origin string) {
		msg := link.RegisterMessage(network.ID.String(), k.ID.String(), challenge, ts, origin)
		f.Registrations = append(f.Registrations, registrationVector{
			Description: desc, Network: network.ID.String(), Node: k.ID.String(), Ed25519: b64(k.Ed25519Public),
			Challenge: b64(challenge), Ts: ts, Origin: origin, Message: b64(msg), Sig: b64(ed25519.Sign(k.Ed25519, msg)),
		})
	}
	reg("a member of network 0 on the public relay (default port omitted)", b, n0, 1790000000000, "eu.frontierengineer.link")
	reg("the primary of network 0 on a self-hosted relay with a port", a, n0, 1790000123456, "relay.example:8443")

	body := []byte{0, 0, 0, 7, 0xde, 0xad, 0xbe, 0xef}
	sent := append(append([]byte{1, 0x03}, a.ID[:]...), body...)
	delivered := append(append([]byte{1, 0x03}, b.ID[:]...), body...)
	f.Frames = append(f.Frames, frameVector{
		Description: "data from seed 1 to seed 0 (the primary), receiver index 7",
		Sent:        hex.EncodeToString(sent), Delivered: hex.EncodeToString(delivered),
	})
	unreach := append([]byte{1, 0x04}, c.ID[:]...)
	f.Frames = append(f.Frames, frameVector{
		Description: "a frame for seed 2, which is not connected, and the relay's unreachable answer (the peer field names seed 2)",
		Sent:        hex.EncodeToString(append(append([]byte{1, 0x01}, c.ID[:]...), 0, 0, 0, 1)), Delivered: hex.EncodeToString(unreach),
	})
	control := []byte{0, 0, 0, 7, 0x0c, 0x0a, 0xfe}
	f.Frames = append(f.Frames, frameVector{
		Description: "control from seed 1 to seed 0 (type 8), delivered as data (type 3): same body, peer rewritten",
		Sent:        hex.EncodeToString(append(append([]byte{1, 0x08}, a.ID[:]...), control...)),
		Delivered:   hex.EncodeToString(append(append([]byte{1, 0x03}, b.ID[:]...), control...)),
	})

	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
