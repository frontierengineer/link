package vectors

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/frontierengineer/link/relay/internal/link"
)

const committed = "../../../spec/vectors/relay.json"

func TestCommittedFileMatches(t *testing.T) {
	want, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(committed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("spec/vectors/relay.json is out of date: run `go run ./cmd/vectors` in relay/")
	}
}

// The file, read back as a client would, agrees with the relay's own verification.
func TestVectorsVerify(t *testing.T) {
	raw, err := os.ReadFile(committed)
	if err != nil {
		t.Fatal(err)
	}
	var f file
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	keys := map[string]*link.Keys{}
	for _, kv := range f.Keys {
		seed, _ := link.B64u.DecodeString(kv.Seed)
		k, err := link.DeriveKeys(seed)
		if err != nil {
			t.Fatal(err)
		}
		if b64(k.Ed25519Public) != kv.Ed25519 || b64(k.X25519Public) != kv.X25519 || k.ID.String() != kv.NodeID ||
			hex.EncodeToString(k.ID[:]) != kv.NodeIDRaw {
			t.Fatalf("keys for seed %s disagree", kv.Seed)
		}
		keys[kv.NodeID] = k
	}
	if len(f.Networks) == 0 {
		t.Fatal("expected networks")
	}
	for _, nv := range f.Networks {
		seed, _ := link.B64u.DecodeString(nv.Seed)
		n, err := link.DeriveNetworkKeys(seed)
		if err != nil {
			t.Fatal(err)
		}
		if b64(n.Ed25519Seed) != nv.Ed25519Seed || b64(n.Ed25519Public) != nv.Ed25519 || n.ID.String() != nv.NetworkID ||
			hex.EncodeToString(n.ID[:]) != nv.NetworkIDRaw {
			t.Fatalf("network keys for seed %s disagree", nv.Seed)
		}
	}
	valid := 0
	for _, rv := range f.Rosters {
		_, err := link.ParseRoster(rv.Roster)
		if (err == nil) != rv.Valid {
			t.Errorf("%s: valid=%v but ParseRoster says %v", rv.Description, rv.Valid, err)
		}
		if rv.Valid {
			valid++
			input, _ := link.B64u.DecodeString(rv.SigningInput)
			jcs, _ := link.B64u.DecodeString(rv.JCS)
			if !bytes.Equal(input, append([]byte(link.RosterContext), jcs...)) {
				t.Errorf("%s: signingInput is not the context and jcs", rv.Description)
			}
		}
	}
	if valid == 0 || valid == len(f.Rosters) {
		t.Fatal("expected both valid and invalid rosters")
	}
	if len(f.RosterTexts) == 0 {
		t.Fatal("expected roster texts")
	}
	for _, rv := range f.RosterTexts {
		if _, err := link.ParseRoster([]byte(rv.Text)); (err == nil) != rv.Valid {
			t.Errorf("roster text %q: valid=%v but ParseRoster says %v", rv.Description, rv.Valid, err)
		}
	}
	// Every Ed25519 vector, through the relay's one verification; and the rule matters: plain
	// crypto/ed25519 answers some of them otherwise.
	if len(f.Ed25519) == 0 {
		t.Fatal("expected ed25519 vectors")
	}
	lax := 0
	for _, v := range f.Ed25519 {
		pub, _ := link.B64u.DecodeString(v.Pub)
		msg, _ := link.B64u.DecodeString(v.Msg)
		sig, _ := link.B64u.DecodeString(v.Sig)
		if got := link.VerifyEd25519(pub, msg, sig); got != v.Valid {
			t.Errorf("ed25519 %q: valid=%v but VerifyEd25519 says %v", v.Description, v.Valid, got)
		}
		if len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, msg, sig) != v.Valid {
			lax++
		}
	}
	if lax == 0 {
		t.Error("crypto/ed25519 alone agrees with every vector: they test nothing beyond it")
	}
	for _, rv := range f.Registrations {
		k := keys[rv.Node]
		ch, _ := link.B64u.DecodeString(rv.Challenge)
		msg := link.RegisterMessage(rv.Network, rv.Node, ch, rv.Ts, rv.Origin)
		sig, _ := link.B64u.DecodeString(rv.Sig)
		if b64(msg) != rv.Message || !ed25519.Verify(k.Ed25519Public, msg, sig) {
			t.Errorf("%s: does not verify", rv.Description)
		}
	}
}
