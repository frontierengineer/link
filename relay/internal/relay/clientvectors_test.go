package relay

// spec/vectors/client.json is written by the TypeScript client. The relay checks every item
// in it that the relay itself understands: key and id derivation, roster JCS bytes,
// signatures and validity, registration signatures and the origin they are bound to, and
// routed frames, which go through the real routing code and must come out as recorded.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/frontierengineer/link/relay/internal/link"
)

type clientVectors struct {
	Keys []struct {
		Seed, Ed25519Seed, Ed25519Public, Ed25519PublicB64u string
		X25519Private, X25519Public, X25519PublicB64u       string
		NodeIDBytes                                         string `json:"nodeIdBytes"`
		NodeID                                              string `json:"nodeId"`
	}
	Roster struct {
		Signing struct {
			Roster      json.RawMessage
			JCS         string `json:"jcs"`
			SignedBytes string
			Signature   string
		}
		Unicode struct {
			Roster json.RawMessage
			JCS    string `json:"jcs"`
		}
		Valid, Invalid []struct {
			Name   string
			Roster json.RawMessage
		}
		Acceptance []struct {
			Name          string
			Roster        json.RawMessage
			PinnedPrimary string
			HeldVersion   int64
			Accept        bool
		}
	}
	Register []struct {
		Seed, URL, Origin, Network, Node, Challenge string
		Ts                                          uint64
		SignedBytes, Sig                            string
	}
	Noise struct {
		Network   string
		Initiator struct{ Node, Seed string }
		Responder struct{ Node, Seed string }
		Message1  struct{ FrameSent, FrameDelivered string }
		Message2  struct{ FrameSent, FrameDelivered string }
		Transport []struct{ Direction, FrameSent string }
	}
	Frames []struct {
		Name              string
		Type              byte
		Peer, Body, Frame string
	}
}

func readClientVectors(t *testing.T) *clientVectors {
	t.Helper()
	raw, err := os.ReadFile("../../../spec/vectors/client.json")
	if err != nil {
		t.Fatal(err)
	}
	var v clientVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Keys) == 0 || len(v.Register) == 0 || len(v.Frames) == 0 || len(v.Roster.Invalid) == 0 {
		t.Fatal("client.json is missing sections")
	}
	return &v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestClientVectorsKeys(t *testing.T) {
	for _, kv := range readClientVectors(t).Keys {
		k, err := link.DeriveKeys(unhex(t, kv.Seed))
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]string{
			"ed25519Seed":       hex.EncodeToString(k.Ed25519Seed),
			"ed25519Public":     hex.EncodeToString(k.Ed25519Public),
			"ed25519PublicB64u": b64(k.Ed25519Public),
			"x25519Private":     hex.EncodeToString(k.X25519Private),
			"x25519Public":      hex.EncodeToString(k.X25519Public),
			"x25519PublicB64u":  b64(k.X25519Public),
			"nodeIdBytes":       hex.EncodeToString(k.ID[:]),
			"nodeId":            k.ID.String(),
		}
		want := map[string]string{
			"ed25519Seed": kv.Ed25519Seed, "ed25519Public": kv.Ed25519Public, "ed25519PublicB64u": kv.Ed25519PublicB64u,
			"x25519Private": kv.X25519Private, "x25519Public": kv.X25519Public, "x25519PublicB64u": kv.X25519PublicB64u,
			"nodeIdBytes": kv.NodeIDBytes, "nodeId": kv.NodeID,
		}
		for name, w := range want {
			if got[name] != w {
				t.Errorf("seed %s: %s = %s, client says %s", kv.Seed, name, got[name], w)
			}
		}
		if id, ok := link.ParseID(kv.NodeID); !ok || id != k.ID {
			t.Errorf("seed %s: node id %s does not parse back", kv.Seed, kv.NodeID)
		}
	}
}

// jcsWithoutSignature canonicalises a roster with its signature removed, as the relay does
// before verifying it.
func jcsWithoutSignature(t *testing.T, raw []byte) []byte {
	t.Helper()
	tree, err := link.ParseJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	input, err := link.SigningInput(tree.(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	return input[len(link.RosterContext):]
}

func TestClientVectorsRosters(t *testing.T) {
	v := readClientVectors(t).Roster

	s := v.Signing
	if got := jcsWithoutSignature(t, s.Roster); string(got) != s.JCS {
		t.Errorf("signing: JCS differs\nrelay:  %s\nclient: %s", got, s.JCS)
	}
	tree, _ := link.ParseJSON(s.Roster)
	input, _ := link.SigningInput(tree.(map[string]any))
	if hex.EncodeToString(input) != s.SignedBytes {
		t.Error("signing: signed bytes differ")
	}
	r, err := link.ParseRoster(s.Roster)
	if err != nil {
		t.Fatalf("signing: the relay refuses the client's signed roster: %v", err)
	}
	sig, _ := link.B64u.DecodeString(s.Signature)
	if !ed25519.Verify(r.Primary, input, sig) {
		t.Error("signing: the signature does not verify")
	}

	if got := jcsWithoutSignature(t, v.Unicode.Roster); string(got) != v.Unicode.JCS {
		t.Errorf("unicode: JCS differs\nrelay:  %s\nclient: %s", got, v.Unicode.JCS)
	}
	if _, err := link.ParseRoster(v.Unicode.Roster); err != nil {
		t.Errorf("unicode: the relay refuses it: %v", err)
	}

	for _, c := range v.Valid {
		if _, err := link.ParseRoster(c.Roster); err != nil {
			t.Errorf("valid %q: the relay refuses it: %v", c.Name, err)
		}
	}
	for _, c := range v.Invalid {
		if _, err := link.ParseRoster(c.Roster); err == nil {
			t.Errorf("invalid %q: the relay accepts it", c.Name)
		}
	}
	// The relay has no pinned key, but it applies the same rule to the key it holds: a
	// roster replaces another only if valid, for the same primary, and newer.
	for _, c := range v.Acceptance {
		r, err := link.ParseRoster(c.Roster)
		pinned, _ := link.B64u.DecodeString(c.PinnedPrimary)
		accept := err == nil && bytes.Equal(r.Primary, pinned) && r.Version > c.HeldVersion
		if accept != c.Accept {
			t.Errorf("acceptance %q: relay says %v, client says %v", c.Name, accept, c.Accept)
		}
	}
}

func TestClientVectorsRegistration(t *testing.T) {
	s := &Server{cfg: Defaults()}
	for _, rv := range readClientVectors(t).Register {
		u, err := url.Parse(rv.URL)
		if err != nil {
			t.Fatal(err)
		}
		// The relay sees the Host header the client sends for this URL.
		if got := s.originOf(&http.Request{Host: u.Host}); got != rv.Origin {
			t.Errorf("%s: relay origin %q, client signed %q", rv.URL, got, rv.Origin)
		}
		k, err := link.DeriveKeys(unhex(t, rv.Seed))
		if err != nil {
			t.Fatal(err)
		}
		if k.ID.String() != rv.Node {
			t.Errorf("%s: node %s is not derived from the seed", rv.URL, rv.Node)
		}
		ch, _ := link.B64u.DecodeString(rv.Challenge)
		msg := link.RegisterMessage(rv.Network, rv.Node, ch, rv.Ts, rv.Origin)
		if hex.EncodeToString(msg) != rv.SignedBytes {
			t.Errorf("%s: signed bytes differ", rv.URL)
		}
		sig, _ := link.B64u.DecodeString(rv.Sig)
		if !ed25519.Verify(k.Ed25519Public, msg, sig) {
			t.Errorf("%s: the signature does not verify", rv.URL)
		}
	}
}

func TestClientVectorsFrameLayout(t *testing.T) {
	types := map[string]byte{
		"handshake-init": typeInit, "handshake-resp": typeResp, "data": typeData, "unreachable": typeUnreachable,
		"refused": typeRefused, "pair": typePair, "reset": typeReset,
	}
	for _, f := range readClientVectors(t).Frames {
		b := unhex(t, f.Frame)
		if want, ok := types[f.Name]; !ok || want != f.Type {
			t.Errorf("%s: type %d, relay knows it as %d", f.Name, f.Type, want)
		}
		if len(b) < frameHeader || b[0] != frameVersion || b[1] != f.Type ||
			hex.EncodeToString(b[2:frameHeader]) != f.Peer || hex.EncodeToString(b[frameHeader:]) != f.Body {
			t.Errorf("%s: the relay reads the frame differently", f.Name)
		}
	}
}

// The client's Noise frames, sent through the relay between the two members they name,
// arrive exactly as the client recorded them.
func TestClientVectorsRouted(t *testing.T) {
	v := readClientVectors(t)
	primary, err := link.DeriveKeys(unhex(t, v.Keys[0].Seed))
	if err != nil {
		t.Fatal(err)
	}
	if primary.ID.String() != v.Noise.Network {
		t.Fatalf("the noise network %s is not keys[0]", v.Noise.Network)
	}
	ik, _ := link.DeriveKeys(unhex(t, v.Noise.Initiator.Seed))
	rk, _ := link.DeriveKeys(unhex(t, v.Noise.Responder.Seed))
	if ik.ID.String() != v.Noise.Initiator.Node || rk.ID.String() != v.Noise.Responder.Node {
		t.Fatal("the noise nodes are not derived from their seeds")
	}
	h := start(t, nil)
	r := roster(t, 1, primary, ik, rk)
	ini := h.register(ik, primary, r)
	res := h.register(rk, primary, r)

	through := func(name string, from, to *client, sent, delivered []byte) {
		t.Helper()
		from.sendBinary(sent)
		if got := to.frame(); !bytes.Equal(got, delivered) {
			t.Errorf("%s: delivered\n%x\nclient recorded\n%x", name, got, delivered)
		}
	}
	through("message 1", ini, res, unhex(t, v.Noise.Message1.FrameSent), unhex(t, v.Noise.Message1.FrameDelivered))
	through("message 2", res, ini, unhex(t, v.Noise.Message2.FrameSent), unhex(t, v.Noise.Message2.FrameDelivered))
	if len(v.Noise.Transport) == 0 {
		t.Fatal("no transport frames")
	}
	for _, tr := range v.Noise.Transport {
		sent := unhex(t, tr.FrameSent)
		delivered := bytes.Clone(sent)
		from, to, sender := ini, res, ik
		if tr.Direction == "responder->initiator" {
			from, to, sender = res, ini, rk
		}
		copy(delivered[2:frameHeader], sender.ID[:])
		through(tr.Direction, from, to, sent, delivered)
	}
}
