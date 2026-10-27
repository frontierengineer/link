package link

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// A network made with no relay, and placed later (section 3.2), and the pairing parameters
// (section 5.1).

func mustJCS(t *testing.T, r *Roster) string {
	t.Helper()
	b, err := r.JCS()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func isInvalid(err error) bool { return errors.Is(err, ErrInvalid) }

func TestClientVectorsPlacing(t *testing.T) {
	var v struct {
		Roster struct {
			Placing struct {
				PrimarySeed, NetworkSeed, Relay string
				Members                         []RosterMember
				CreatedAt, PlacedAt             int64
				Unplaced, Placed                json.RawMessage
				PlacedAccepted                  []struct {
					Name, Relay string
					Roster      json.RawMessage
				}
				Refused []struct {
					Name, NetworkSeed, Relay string
					Roster                   json.RawMessage
				}
			}
		}
	}
	loadJSON(t, "spec/vectors/client.json", &v)
	p := v.Roster.Placing
	if len(p.Members) != 1 || len(p.Refused) < 5 {
		t.Fatal("placing vectors did not load")
	}
	seed, _ := hex.DecodeString(p.NetworkSeed)
	created, gotSeed, err := CreateNetworkWith(NetworkOptions{
		Primary: mustIdentity(t, unhexT(t, p.PrimarySeed)), Members: p.Members, NowMs: p.CreatedAt, NetworkSeed: seed,
	})
	if err != nil || !bytes.Equal(gotSeed, seed) {
		t.Fatal(err)
	}
	unplaced, err := ValidateRoster(p.Unplaced)
	if err != nil {
		t.Fatal(err)
	}
	if mustJCS(t, created) != mustJCS(t, unplaced) {
		t.Errorf("createNetwork:\n got  %s\n want %s", mustJCS(t, created), mustJCS(t, unplaced))
	}
	if unplaced.IsPlaced() {
		t.Error("the unplaced roster is placed")
	}
	want, err := ValidateRoster(p.Placed)
	if err != nil {
		t.Fatal(err)
	}
	placed, err := PlaceNetwork(unplaced, seed, p.Relay, p.PlacedAt)
	if err != nil {
		t.Fatal(err)
	}
	if mustJCS(t, placed) != mustJCS(t, want) || !placed.IsPlaced() {
		t.Errorf("placeNetwork:\n got  %s\n want %s", mustJCS(t, placed), mustJCS(t, want))
	}
	for _, c := range p.PlacedAccepted {
		w, err := ValidateRoster(c.Roster)
		if err != nil {
			t.Fatal(err)
		}
		got, err := PlaceNetwork(unplaced, seed, c.Relay, p.PlacedAt)
		if err != nil || mustJCS(t, got) != mustJCS(t, w) {
			t.Errorf("%s: %v", c.Name, err)
		}
	}
	for _, c := range p.Refused {
		r, err := DecodeRoster(c.Roster)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := PlaceNetwork(r, unhexT(t, c.NetworkSeed), c.Relay, p.PlacedAt); !isInvalid(err) {
			t.Errorf("%s: %v, want invalid", c.Name, err)
		}
	}
}

func TestClientVectorsPairingParams(t *testing.T) {
	var v struct {
		Pairing struct {
			Params struct {
				Network, Code, CodeIDB64u, Relay, Params, Link, Fragment string
				Unicode                                                  struct {
					Network, Code, CodeID, Relay, Params string
				}
				Parse []struct {
					Name, Params string
					Valid        bool
					Parsed       *struct{ Network, Code, CodeID, Relay string }
				}
			}
		}
	}
	loadJSON(t, "spec/vectors/client.json", &v)
	q := v.Pairing.Params
	parts := PairingLink{Network: q.Network, Code: q.Code, CodeID: q.CodeIDB64u, Relay: q.Relay}
	if s, err := BuildPairingParams(parts); err != nil || s != q.Params {
		t.Errorf("params %q %v", s, err)
	}
	if s, err := BuildPairingLink(parts); err != nil || s != q.Link {
		t.Errorf("link %q %v", s, err)
	}
	if p, err := ParsePairingLink(q.Link); err != nil || p != parts {
		t.Errorf("link parsed %+v %v", p, err)
	}
	_, fragment, _ := strings.Cut(q.Fragment, "#")
	if p, err := ParsePairingParams(fragment); err != nil || p != parts {
		t.Errorf("fragment parsed %+v %v", p, err)
	}
	uc := PairingLink{Network: q.Unicode.Network, Code: q.Unicode.Code, CodeID: q.Unicode.CodeID, Relay: q.Unicode.Relay}
	if s, err := BuildPairingParams(uc); err != nil || s != q.Unicode.Params {
		t.Errorf("unicode params %q %v", s, err)
	}
	if len(q.Parse) < 10 {
		t.Fatal("parse cases did not load")
	}
	for _, c := range q.Parse {
		p, err := ParsePairingParams(c.Params)
		if c.Valid {
			if err != nil || c.Parsed == nil || p != (PairingLink{Network: c.Parsed.Network, Code: c.Parsed.Code, CodeID: c.Parsed.CodeID, Relay: c.Parsed.Relay}) {
				t.Errorf("%s: %+v %v", c.Name, p, err)
			}
		} else if !isInvalid(err) {
			t.Errorf("%s: %v, want invalid", c.Name, err)
		}
	}
}

func unhexT(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCreateNetworkWithAndPlaceNetwork(t *testing.T) {
	p := mustIdentity(t, bytes.Repeat([]byte{1}, 32))
	w := mustIdentity(t, bytes.Repeat([]byte{2}, 32))
	seed := bytes.Repeat([]byte{0x80}, 32)
	r, gotSeed, err := CreateNetworkWith(NetworkOptions{Primary: p, Members: []RosterMember{MemberFromIdentity(w)}, NetworkSeed: seed})
	if err != nil || !bytes.Equal(gotSeed, seed) {
		t.Fatal(err)
	}
	if r.Relay != "" || r.IsPlaced() || r.Version != 1 || len(r.Members) != 2 || r.Primary != p.ID() {
		t.Fatalf("%+v", r.UnsignedRoster)
	}
	if time.Since(time.UnixMilli(r.IssuedAt)) > time.Minute {
		t.Error("NowMs 0 is not the current time")
	}
	// The existing CreateNetwork is unchanged.
	if old, _, err := CreateNetwork(p, "wss://r/v1", time.Now(), seed); err != nil || !old.IsPlaced() {
		t.Fatal(err)
	}
	// Refusals.
	cases := map[string]NetworkOptions{
		"no primary":           {},
		"the primary listed":   {Primary: p, Members: []RosterMember{MemberFromIdentity(p)}},
		"a member twice":       {Primary: p, Members: []RosterMember{MemberFromIdentity(w), MemberFromIdentity(w)}},
		"an id not derived":    {Primary: p, Members: []RosterMember{{ID: p.ID(), Ed25519: b64u(w.Ed25519Public()), X25519: b64u(w.X25519Public())}}},
		"a short key":          {Primary: p, Members: []RosterMember{{ID: w.ID(), Ed25519: b64u(w.Ed25519Public()), X25519: "AAAA"}}},
		"a seed of 31 bytes":   {Primary: p, NetworkSeed: make([]byte, 31)},
		"a negative timestamp": {Primary: p, NowMs: -1},
	}
	for name, o := range cases {
		if _, _, err := CreateNetworkWith(o); !isInvalid(err) {
			t.Errorf("%s: %v, want invalid", name, err)
		}
	}
	many := make([]RosterMember, 500)
	for i := range many {
		id, _ := NewIdentity()
		many[i] = MemberFromIdentity(id)
	}
	if _, _, err := CreateNetworkWith(NetworkOptions{Primary: p, Members: many}); !errors.Is(err, ErrRosterFull) {
		t.Errorf("500 members: %v", err)
	}

	placed, err := PlaceNetwork(r, seed, "wss://relay.example/v1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !placed.IsPlaced() || placed.Version != 2 || placed.Relay != "wss://relay.example/v1" || placed.IssuedAt < r.IssuedAt {
		t.Fatalf("%+v", placed.UnsignedRoster)
	}
	if err := AcceptanceProblem(placed, r.NetworkKey, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := PlaceNetwork(placed, seed, "wss://elsewhere/v1", 0); !isInvalid(err) {
		t.Errorf("placed twice: %v", err)
	}
	if _, err := PlaceNetwork(r, bytes.Repeat([]byte{0x81}, 32), "wss://relay.example/v1", 0); !isInvalid(err) {
		t.Errorf("another seed: %v", err)
	}
	for _, bad := range []string{"", "https://relay.example/v1", "relay.example/v1", "wss://", "wss:///v1", "ws:/x", "WSS://relay.example/v1", "wss://a b/v1"} {
		if _, err := PlaceNetwork(r, seed, bad, 0); !isInvalid(err) {
			t.Errorf("relay %q: %v", bad, err)
		}
	}
	// A field the protocol does not define, on the roster, is kept as signed.
	ext := r.Clone()
	ext.extra = map[string]any{"future": []any{json.Number("1"), "x"}}
	sb, _ := ext.SigningBytes()
	key, _ := NetworkKeyFromSeed(seed)
	ext.Signature = b64u(key.Sign(sb))
	if err := ext.Problem(); err != nil {
		t.Fatal(err)
	}
	placedExt, err := PlaceNetwork(ext, seed, "wss://relay.example/v1", 0)
	if err != nil || !strings.Contains(mustJCS(t, placedExt), `"future":[1,"x"]`) {
		t.Fatalf("%v %s", err, mustJCS(t, placedExt))
	}
}

func TestAnUnplacedNetworkIsNotDialledWithoutARelayURL(t *testing.T) {
	p := mustIdentity(t, bytes.Repeat([]byte{1}, 32))
	w := mustIdentity(t, bytes.Repeat([]byte{2}, 32))
	r, seed, err := CreateNetworkWith(NetworkOptions{Primary: p, Members: []RosterMember{MemberFromIdentity(w)}})
	if err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]func() error{
		"NewMember": func() error { _, err := NewMember(MemberOptions{Identity: w, Roster: r}); return err },
		"NewPrimary": func() error {
			_, err := NewPrimary(MemberOptions{Identity: p, Roster: r, NetworkSeed: seed})
			return err
		},
		"ConnectPrimary": func() error {
			_, err := ConnectPrimary(ctxT(t, time.Second), MemberOptions{Identity: p, Roster: r, NetworkSeed: seed})
			return err
		},
	} {
		if err := f(); !isInvalid(err) || !strings.Contains(err.Error(), "no relay yet") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestLiveAnUnplacedNetworkPlacedRegistersAndPairs(t *testing.T) {
	relay := startRelay(t, nil)
	p, _ := NewIdentity()
	listed, _ := NewIdentity()
	r, seed, err := CreateNetworkWith(NetworkOptions{Primary: p, Members: []RosterMember{MemberFromIdentity(listed)}})
	if err != nil {
		t.Fatal(err)
	}
	// Given a relay URL of its own, a primary of the unplaced network dials it, and its links
	// name it.
	early, err := ConnectPrimary(ctxT(t, 15*time.Second), MemberOptions{Identity: p, Roster: r, NetworkSeed: seed, RelayURL: relay.url, Timing: fast})
	if err != nil {
		t.Fatal(err)
	}
	code, err := early.OpenPairingCode(PairingCodeOptions{})
	if err != nil || !strings.Contains(code.Link, "&r="+encodeURIComponent(relay.url)) {
		t.Fatalf("%v %s", err, code.Link)
	}
	early.Close()

	placed, err := PlaceNetwork(r, seed, relay.url, 0)
	if err != nil {
		t.Fatal(err)
	}
	prim, err := ConnectPrimary(ctxT(t, 15*time.Second), MemberOptions{Identity: p, Roster: placed, NetworkSeed: seed, Timing: fast})
	if err != nil {
		t.Fatal(err)
	}
	defer prim.Close()
	m, err := ConnectMember(ctxT(t, 15*time.Second), MemberOptions{Identity: listed, Roster: placed, Timing: fast})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	code, err = prim.OpenPairingCode(PairingCodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	newcomer, _ := NewIdentity()
	res, err := Pair(ctxT(t, 30*time.Second), PairOptions{Link: code.Link, Identity: newcomer})
	if err != nil || res.Roster.Version != 3 || res.Roster.Relay != relay.url {
		t.Fatalf("%v %+v", err, res)
	}
	n, err := ConnectMember(ctxT(t, 15*time.Second), MemberOptions{Identity: newcomer, Roster: res.Roster, Timing: fast})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	eventually(t, "the listed member to learn version 3", func() bool { return m.Roster().Version >= 3 })
	if err := m.Send(ctxT(t, 10*time.Second), newcomer.ID(), []byte("placed")); err != nil {
		t.Fatal(err)
	}
	if got := recv(t, n); got.From != listed.ID() || string(got.Bytes) != "placed" {
		t.Fatalf("%+v", got)
	}
}
