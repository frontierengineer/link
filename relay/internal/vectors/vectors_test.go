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
