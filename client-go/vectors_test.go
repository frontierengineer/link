package link

// Every applicable vector, read from the files the other implementations use:
// spec/vectors/client.json (from the TypeScript client), spec/vectors/relay.json (from the
// relay), and the client's RFC 9382 and cacophony Noise vectors.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/flynn/noise"
)

var vectorRoot = filepath.Join("..")

func loadJSON(t *testing.T, rel string, v any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorRoot, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}
}

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

func ub(t *testing.T, s string) []byte {
	t.Helper()
	b, err := fromB64u(s)
	if err != nil {
		t.Fatalf("b64u %q: %v", s, err)
	}
	return b
}

func eqHex(t *testing.T, what string, got []byte, want string) {
	t.Helper()
	if hex.EncodeToString(got) != want {
		t.Errorf("%s:\n got  %x\n want %s", what, got, want)
	}
}

func mustIdentity(t *testing.T, seed []byte) *Identity {
	t.Helper()
	id, err := IdentityFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type clientVectors struct {
	Keys []struct {
		Seed, Ed25519Seed, Ed25519Public, Ed25519PublicB64u, X25519Private, X25519Public, X25519PublicB64u, NodeIDBytes, NodeID string
	} `json:"keys"`
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
		Valid []struct {
			Name   string
			Roster json.RawMessage
		}
		Invalid []struct {
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
		Seed, URL, Origin, Network, Node, Challenge, SignedBytes, Sig string
		TS                                                            int64
	}
	Resign struct {
		Seed, Network, Node, SignedBytes, Sig string
		TS                                    int64
	}
	Pairing struct {
		Link              struct{ Network, Code, CodeIDB64u, Relay, Link string }
		CodeNormalisation []struct{ Input, Code string }
	}
	Spake2 struct {
		RFC9382 []rfcVector `json:"rfc9382"`
		Profile struct {
			CodeInput, Code, Display, CodeID, CodeIDB64u, IDA, IDB, W, XRandom, YRandom, X, Y string
			PA, PB, K, TT, HashTT, Ke, Ka, KcA, KcB, CA, CB, Okm                              string
			P5Plaintext, P5, P6Plaintext, P6, NewcomerSeed                                    string
		}
	}
	Noise struct {
		Protocol, Network, Prologue string
		Initiator, Responder        struct {
			Node, Seed, StaticPrivate, EphemeralPrivate string
			Index                                       uint32
		}
		Message1, Message2 struct{ Payload, Noise, FrameSent, FrameDelivered string }
		HandshakeHash      string
		Transport          []struct {
			Direction                        string
			Nonce                            int
			Plaintext, Ciphertext, FrameSent string
		}
	}
	HandshakeStamps struct {
		Encoding []struct {
			WallNowMs int64
			LastStamp uint64
			Stamp     uint64
		}
		Initiator, Responder string
		WindowMs             int64
		ResponderStartedMs   int64
		Steps                []struct {
			Description, EphemeralPrivate, Payload, Noise string
			Stamp, Stored                                 *uint64
			Accepted                                      bool
			ResponderWallNowMs                            int64
			Event                                         string // "removed" or "readmitted"; else an init
		}
	}
	Frames []struct {
		Name              string
		Type              int
		Peer, Body, Frame string
	}
	SessionMessages []struct{ Name, Encoding string }
}

type rfcVector struct {
	A, B, W, X, Y, PA, PB, K, TT, HashTT, Ke, Ka, KcA, KcB string
	CA                                                     string `json:"cA"`
	CB                                                     string `json:"cB"`
	Aconf, Bconf                                           string
}

func loadClientVectors(t *testing.T) *clientVectors {
	var v clientVectors
	loadJSON(t, "spec/vectors/client.json", &v)
	if len(v.Keys) == 0 || len(v.Roster.Invalid) < 10 || len(v.Frames) != 8 {
		t.Fatal("client.json did not load as expected")
	}
	return &v
}

func TestClientVectorsKeys(t *testing.T) {
	v := loadClientVectors(t)
	for _, k := range v.Keys {
		id := mustIdentity(t, hx(t, k.Seed))
		eqHex(t, "ed25519 seed", id.edPriv.Seed(), k.Ed25519Seed)
		eqHex(t, "ed25519 public", id.Ed25519Public(), k.Ed25519Public)
		eqHex(t, "x25519 private", id.xPriv[:], k.X25519Private)
		eqHex(t, "x25519 public", id.X25519Public(), k.X25519Public)
		if b64u(id.edPub) != k.Ed25519PublicB64u || b64u(id.xPub[:]) != k.X25519PublicB64u {
			t.Error("b64u keys differ")
		}
		raw, err := nodeIDToBytes(id.ID())
		if err != nil || id.ID() != k.NodeID {
			t.Errorf("node id %s, want %s", id.ID(), k.NodeID)
		}
		eqHex(t, "node id bytes", raw[:], k.NodeIDBytes)
	}
}

func TestClientVectorsRosters(t *testing.T) {
	v := loadClientVectors(t)
	s := v.Roster.Signing
	r, err := DecodeRoster(s.Roster)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Problem(); err != nil {
		t.Fatalf("signing roster invalid: %v", err)
	}
	signed, _ := r.SigningBytes()
	eqHex(t, "signed bytes", signed, s.SignedBytes)
	if string(signed[len(rosterLabel):]) != s.JCS {
		t.Error("jcs differs")
	}
	// Ed25519 is deterministic: the primary (keys[0]) signs the same signature.
	primary := mustIdentity(t, hx(t, v.Keys[0].Seed))
	again, err := SignRoster(r.UnsignedRoster, primary)
	if err != nil || again.Signature != s.Signature || r.Signature != s.Signature {
		t.Errorf("re-signed %v %v", again, err)
	}
	u, err := DecodeRoster(v.Roster.Unicode.Roster)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := u.SigningBytes(); string(b[len(rosterLabel):]) != v.Roster.Unicode.JCS {
		t.Errorf("unicode jcs:\n got  %s\n want %s", b[len(rosterLabel):], v.Roster.Unicode.JCS)
	}
	if err := u.Problem(); err != nil {
		t.Errorf("unicode roster: %v", err)
	}
	for _, c := range v.Roster.Valid {
		if _, err := ValidateRoster(c.Roster); err != nil {
			t.Errorf("%s: %v", c.Name, err)
		}
	}
	for _, c := range v.Roster.Invalid {
		if _, err := ValidateRoster(c.Roster); err == nil {
			t.Errorf("%s: accepted", c.Name)
		}
	}
	accepts := []bool{}
	for _, c := range v.Roster.Acceptance {
		r, err := DecodeRoster(c.Roster)
		if err != nil {
			t.Fatal(err)
		}
		got := AcceptanceProblem(r, c.PinnedPrimary, c.HeldVersion) == nil
		if got != c.Accept {
			t.Errorf("%s: accept %v", c.Name, got)
		}
		accepts = append(accepts, c.Accept)
	}
	if len(accepts) != 4 {
		t.Error("expected four acceptance cases")
	}
}

func TestClientVectorsRegisterAndResign(t *testing.T) {
	v := loadClientVectors(t)
	for _, r := range v.Register {
		origin, err := originOf(r.URL)
		if err != nil || origin != r.Origin {
			t.Errorf("origin of %s: %q %v, want %q", r.URL, origin, err, r.Origin)
		}
		m := registerSigningBytes(r.Network, r.Node, ub(t, r.Challenge), r.TS, origin)
		eqHex(t, "register bytes", m, r.SignedBytes)
		id := mustIdentity(t, hx(t, r.Seed))
		if b64u(id.Sign(m)) != r.Sig || id.ID() != r.Node {
			t.Error("register signature differs")
		}
		if !verifyEd25519(id.edPub, m, ub(t, r.Sig)) {
			t.Error("register signature does not verify")
		}
	}
	rs := v.Resign
	id := mustIdentity(t, hx(t, rs.Seed))
	eqHex(t, "resign bytes", resignSigningBytes(rs.Network, rs.Node, rs.TS), rs.SignedBytes)
	got := signResignation(id, rs.Network, rs.TS)
	if got.Sig != rs.Sig {
		t.Error("resign signature differs")
	}
	if !verifyResignation(got, rs.Network, id.edPub) {
		t.Error("resignation does not verify")
	}
	bad := got
	bad.TS++
	if verifyResignation(bad, rs.Network, id.edPub) {
		t.Error("a changed resignation verifies")
	}
}

func TestClientVectorsPairingLink(t *testing.T) {
	v := loadClientVectors(t)
	l := v.Pairing.Link
	link, err := BuildPairingLink(PairingLink{Network: l.Network, Code: l.Code, CodeID: l.CodeIDB64u, Relay: l.Relay})
	if err != nil || link != l.Link {
		t.Errorf("link %q %v", link, err)
	}
	p, err := ParsePairingLink(l.Link)
	if err != nil || p != (PairingLink{Network: l.Network, Code: l.Code, CodeID: l.CodeIDB64u, Relay: l.Relay}) {
		t.Errorf("parsed %+v %v", p, err)
	}
	for _, c := range v.Pairing.CodeNormalisation {
		if got, err := NormalizeCode(c.Input); err != nil || got != c.Code {
			t.Errorf("normalize %q: %q %v", c.Input, got, err)
		}
	}
}

func checkSpake(t *testing.T, name string, v rfcVector, aad []byte) {
	t.Helper()
	var x, y [32]byte
	copy(x[:], hx(t, v.X))
	copy(y[:], hx(t, v.Y))
	var w [32]byte
	copy(w[:], hx(t, v.W))
	a, err := newSpake2(true, w, &x, []byte(v.A), []byte(v.B), aad)
	if err != nil {
		t.Fatal(err)
	}
	b, err := newSpake2(false, w, &y, []byte(v.A), []byte(v.B), aad)
	if err != nil {
		t.Fatal(err)
	}
	eqHex(t, name+" pA", a.share, v.PA)
	eqHex(t, name+" pB", b.share, v.PB)
	ka, err := a.finish(b.share)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := b.finish(a.share)
	if err != nil {
		t.Fatal(err)
	}
	cA, cB := v.CA, v.CB
	if cA == "" {
		cA, cB = v.Aconf, v.Bconf
	}
	for _, k := range []*spake2Keys{ka, kb} {
		eqHex(t, name+" K", k.K, v.K)
		eqHex(t, name+" TT", k.TT, v.TT)
		eqHex(t, name+" hash", k.Hash, v.HashTT)
		eqHex(t, name+" Ke", k.Ke, v.Ke)
		eqHex(t, name+" Ka", k.Ka, v.Ka)
		eqHex(t, name+" KcA", k.KcA, v.KcA)
		eqHex(t, name+" KcB", k.KcB, v.KcB)
		eqHex(t, name+" cA", k.CA, cA)
		eqHex(t, name+" cB", k.CB, cB)
	}
	if !ka.verifyConfirmation(kb.ours) || !kb.verifyConfirmation(ka.ours) {
		t.Errorf("%s: confirmations do not verify", name)
	}
}

func TestRFC9382Vectors(t *testing.T) {
	var file struct{ Vectors []rfcVector }
	loadJSON(t, "client/test/vectors/rfc9382.json", &file)
	if len(file.Vectors) != 4 {
		t.Fatalf("%d RFC 9382 vectors", len(file.Vectors))
	}
	for i, v := range file.Vectors {
		checkSpake(t, "rfc9382 #"+string(rune('0'+i)), v, nil)
	}
	cv := loadClientVectors(t)
	if len(cv.Spake2.RFC9382) != 4 {
		t.Fatal("client.json carries four RFC 9382 vectors")
	}
	for i, v := range cv.Spake2.RFC9382 {
		checkSpake(t, "client.json rfc9382 #"+string(rune('0'+i)), v, nil)
	}
}

func TestClientVectorsSpake2Profile(t *testing.T) {
	v := loadClientVectors(t)
	p := v.Spake2.Profile
	code, err := NormalizeCode(p.CodeInput)
	if err != nil || code != p.Code {
		t.Fatalf("code %q %v", code, err)
	}
	if d, _ := FormatCode(code); d != p.Display {
		t.Errorf("display %q", d)
	}
	if b64u(hx(t, p.CodeID)) != p.CodeIDB64u || p.IDA != spake2IDA || p.IDB != spake2IDB {
		t.Error("profile constants differ")
	}
	w, err := deriveW(code)
	if err != nil {
		t.Fatal(err)
	}
	eqHex(t, "w", w[:], p.W)
	x, _ := scalarFromRandom(hx(t, p.XRandom))
	y, _ := scalarFromRandom(hx(t, p.YRandom))
	eqHex(t, "x", x[:], p.X)
	eqHex(t, "y", y[:], p.Y)
	checkSpake(t, "profile", rfcVector{A: p.IDA, B: p.IDB, W: p.W, X: p.X, Y: p.Y, PA: p.PA, PB: p.PB, K: p.K, TT: p.TT,
		HashTT: p.HashTT, Ke: p.Ke, Ka: p.Ka, KcA: p.KcA, KcB: p.KcB, CA: p.CA, CB: p.CB}, hx(t, p.CodeID))

	// The whole exchange, with the vector's randomness, reproduces P1..P6 byte for byte.
	codeID := hx(t, p.CodeID)
	nc, err := newNewcomerExchange(code, codeID, hx(t, p.XRandom))
	if err != nil {
		t.Fatal(err)
	}
	pr, err := newPrimaryExchange(code, codeID, hx(t, p.YRandom))
	if err != nil {
		t.Fatal(err)
	}
	eqHex(t, "P1", nc.p1(), p.PA)
	p2, err := pr.onP1(nc.p1())
	if err != nil {
		t.Fatal(err)
	}
	eqHex(t, "P2", p2, p.PB)
	p3, err := nc.onP2(p2)
	if err != nil {
		t.Fatal(err)
	}
	eqHex(t, "P3", p3, p.CA)
	if ok, err := pr.onP3(p3); !ok || err != nil {
		t.Fatalf("cA refused: %v", err)
	}
	p4, _ := pr.p4()
	eqHex(t, "P4", p4, p.CB)
	keys, err := pairKeys(nc.keys)
	if err != nil {
		t.Fatal(err)
	}
	eqHex(t, "okm", append(append([]byte{}, keys.toPrimary...), keys.toNewcomer...), p.Okm)
	newcomer := mustIdentity(t, hx(t, p.NewcomerSeed))
	p5, err := nc.onP4(p4, newcomerKeys{ed25519: newcomer.edPub, x25519: newcomer.xPub[:]})
	if err != nil {
		t.Fatal(err)
	}
	eqHex(t, "P5", p5, p.P5)
	got5, err := pr.onP5(p5)
	if err != nil || !bytes.Equal(got5.ed25519, newcomer.edPub) || !bytes.Equal(got5.x25519, newcomer.xPub[:]) {
		t.Fatalf("P5 opened to %+v %v", got5, err)
	}
	var p6Body struct{ Roster json.RawMessage }
	if err := json.Unmarshal([]byte(p.P6Plaintext), &p6Body); err != nil {
		t.Fatal(err)
	}
	roster, err := DecodeRoster(p6Body.Roster)
	if err != nil {
		t.Fatal(err)
	}
	p6, err := pr.p6(roster)
	if err != nil {
		t.Fatal(err)
	}
	eqHex(t, "P6 (the roster written as the TypeScript client writes it)", p6, p.P6)
	got6, err := nc.onP6(p6)
	if err != nil {
		t.Fatal(err)
	}
	res, err := checkPairedRoster(got6, roster.Network, newcomer)
	if err != nil || res.PinnedPrimary != roster.Primary.Ed25519 {
		t.Fatalf("paired roster: %v", err)
	}
}

type fixedReader struct{ b []byte }

func (f *fixedReader) Read(p []byte) (int, error) {
	n := copy(p, f.b)
	f.b = f.b[n:]
	return n, nil
}

func TestClientVectorsNoise(t *testing.T) {
	v := loadClientVectors(t)
	n := v.Noise
	if n.Protocol != "Noise_IK_25519_ChaChaPoly_SHA256" {
		t.Fatal(n.Protocol)
	}
	eqHex(t, "prologue", sessionPrologue(n.Network), n.Prologue)
	ini := mustIdentity(t, hx(t, n.Initiator.Seed))
	res := mustIdentity(t, hx(t, n.Responder.Seed))
	eqHex(t, "initiator static", ini.xPriv[:], n.Initiator.StaticPrivate)
	eqHex(t, "responder static", res.xPriv[:], n.Responder.StaticPrivate)
	hsI, err := newHandshake(ini, true, n.Network, res.X25519Public(), &fixedReader{hx(t, n.Initiator.EphemeralPrivate)})
	if err != nil {
		t.Fatal(err)
	}
	hsR, err := newHandshake(res, false, n.Network, nil, &fixedReader{hx(t, n.Responder.EphemeralPrivate)})
	if err != nil {
		t.Fatal(err)
	}
	// Message 1's payload is the roster version and the stamp, 16 bytes; message 2's the
	// version alone.
	if p := hx(t, n.Message1.Payload); len(p) != initPayloadLen || len(hx(t, n.Message2.Payload)) != 8 {
		t.Fatalf("payload lengths %d and %d", len(p), len(hx(t, n.Message2.Payload)))
	}
	m1, _, _, err := hsI.WriteMessage(nil, hx(t, n.Message1.Payload))
	if err != nil {
		t.Fatal(err)
	}
	eqHex(t, "message 1", m1, n.Message1.Noise)
	rid, _ := nodeIDToBytes(res.ID())
	iid, _ := nodeIDToBytes(ini.ID())
	f1, _ := encodeFrame(frameHandshakeInit, rid, handshakeInitBody(n.Initiator.Index, m1))
	eqHex(t, "message 1 frame sent", f1, n.Message1.FrameSent)
	d1, _ := encodeFrame(frameHandshakeInit, iid, handshakeInitBody(n.Initiator.Index, m1))
	eqHex(t, "message 1 frame delivered", d1, n.Message1.FrameDelivered)
	got, _, _, err := hsR.ReadMessage(nil, m1)
	if err != nil || !bytes.Equal(got, hx(t, n.Message1.Payload)) || !bytes.Equal(hsR.PeerStatic(), ini.X25519Public()) {
		t.Fatalf("responder reads message 1: %v", err)
	}
	m2, rToI, rFromI, err := hsR.WriteMessage(nil, hx(t, n.Message2.Payload))
	if err != nil {
		t.Fatal(err)
	}
	eqHex(t, "message 2", m2, n.Message2.Noise)
	f2, _ := encodeFrame(frameHandshakeResp, iid, handshakeRespBody(n.Responder.Index, n.Initiator.Index, m2))
	eqHex(t, "message 2 frame sent", f2, n.Message2.FrameSent)
	d2, _ := encodeFrame(frameHandshakeResp, rid, handshakeRespBody(n.Responder.Index, n.Initiator.Index, m2))
	eqHex(t, "message 2 frame delivered", d2, n.Message2.FrameDelivered)
	got2, iSend, iRecv, err := hsI.ReadMessage(nil, m2)
	if err != nil || !bytes.Equal(got2, hx(t, n.Message2.Payload)) {
		t.Fatal(err)
	}
	eqHex(t, "handshake hash", hsI.ChannelBinding(), n.HandshakeHash)
	eqHex(t, "handshake hash (responder)", hsR.ChannelBinding(), n.HandshakeHash)
	// flynn/noise splits into initiator->responder then responder->initiator.
	_ = rToI
	for _, tr := range n.Transport {
		send, recv, peer, index := iSend, rToI, rid, n.Responder.Index
		if tr.Direction == "responder->initiator" {
			send, recv, peer, index = rFromI, iRecv, iid, n.Initiator.Index
		}
		if send.Nonce() != uint64(tr.Nonce) {
			t.Fatalf("nonce %d", send.Nonce())
		}
		ct, err := send.Encrypt(nil, nil, hx(t, tr.Plaintext))
		if err != nil {
			t.Fatal(err)
		}
		eqHex(t, tr.Direction+" ciphertext", ct, tr.Ciphertext)
		f, _ := encodeFrame(frameData, peer, dataBody(index, ct))
		eqHex(t, tr.Direction+" frame", f, tr.FrameSent)
		pt, err := recv.Decrypt(nil, nil, ct)
		if err != nil || !bytes.Equal(pt, hx(t, tr.Plaintext)) {
			t.Errorf("%s does not decrypt", tr.Direction)
		}
	}
}

func TestClientVectorsFramesAndSessionMessages(t *testing.T) {
	v := loadClientVectors(t)
	for _, f := range v.Frames {
		var peer [16]byte
		copy(peer[:], hx(t, f.Peer))
		enc, err := encodeFrame(byte(f.Type), peer, hx(t, f.Body))
		if err != nil {
			t.Fatal(err)
		}
		eqHex(t, "frame "+f.Name, enc, f.Frame)
		d, err := decodeFrame(hx(t, f.Frame))
		if err != nil || int(d.typ) != f.Type || hex.EncodeToString(d.peer[:]) != f.Peer || hex.EncodeToString(d.body) != f.Body {
			t.Errorf("decode %s: %+v %v", f.Name, d, err)
		}
	}
	for _, m := range v.SessionMessages {
		d, err := decodeSessionMessage(hx(t, m.Encoding))
		if err != nil {
			t.Fatalf("%s: %v", m.Name, err)
		}
		eqHex(t, m.Name, encodeSessionMessage(d), m.Encoding)
		switch m.Name {
		case "message, last fragment":
			if d.more || string(d.bytes) != "hi" {
				t.Error(m.Name)
			}
		case "message, more fragments follow":
			if !d.more || !bytes.Equal(d.bytes, []byte{0, 0xff}) {
				t.Error(m.Name)
			}
		case "message, empty":
			if d.more || len(d.bytes) != 0 {
				t.Error(m.Name)
			}
		case "credit 1 MiB":
			if d.typ != sessCredit || d.credit != 1<<20 {
				t.Error(m.Name)
			}
		case "roster-request":
			if d.typ != sessRosterRequest {
				t.Error(m.Name)
			}
		case "roster":
			// A roster travels as its JCS encoding.
			r, err := ValidateRoster(d.bytes)
			if err != nil {
				t.Fatal(err)
			}
			if j, _ := r.JCS(); !bytes.Equal(j, d.bytes) {
				t.Error("roster message is not the roster's JCS")
			}
		case "resign":
			res, ok := parseResignation(d.bytes)
			if !ok || res.Node != v.Resign.Node || res.TS != v.Resign.TS || res.Sig != v.Resign.Sig {
				t.Error(m.Name)
			}
			again, _ := json.Marshal(res)
			if !bytes.Equal(again, d.bytes) {
				t.Errorf("resign body: %s", again)
			}
		default:
			t.Errorf("unexpected session message vector %q", m.Name)
		}
	}
}

type relayVectors struct {
	Keys []struct {
		Seed, Ed25519Seed, Ed25519, X25519Private, X25519, NodeID, NodeIDRaw string
	}
	Rosters []struct {
		Description                  string
		Roster                       json.RawMessage
		JCS, SigningInput, Signature string
		Valid                        bool
	}
	Registrations []struct {
		Description, Network, Node, Ed25519, Challenge, Origin, Message, Sig string
		TS                                                                   int64
	}
	Frames      []struct{ Description, Sent, Delivered string }
	RosterTexts []struct {
		Description, Text string
		Valid             bool
	}
	Ed25519 []struct {
		Description, Pub, Msg, Sig string
		Valid                      bool
	}
}

func TestRelayVectors(t *testing.T) {
	var v relayVectors
	loadJSON(t, "spec/vectors/relay.json", &v)
	if len(v.Keys) != 4 || len(v.Rosters) != 13 || len(v.Registrations) != 2 || len(v.Frames) != 3 {
		t.Fatal("relay.json did not load as expected")
	}
	keyByID := map[string]*Identity{}
	for _, k := range v.Keys {
		id := mustIdentity(t, ub(t, k.Seed))
		if b64u(id.edPriv.Seed()) != k.Ed25519Seed || b64u(id.edPub) != k.Ed25519 || b64u(id.xPriv[:]) != k.X25519Private ||
			b64u(id.xPub[:]) != k.X25519 || id.ID() != k.NodeID {
			t.Errorf("keys for seed %s differ", k.Seed)
		}
		raw, _ := nodeIDToBytes(id.ID())
		eqHex(t, "raw id", raw[:], k.NodeIDRaw)
		keyByID[id.ID()] = id
	}
	for _, c := range v.Rosters {
		r, err := DecodeRoster(c.Roster)
		valid := err == nil && r.Problem() == nil
		if valid != c.Valid {
			t.Errorf("%s: valid %v, want %v (%v)", c.Description, valid, c.Valid, err)
		}
		if err != nil || c.JCS == "" {
			continue
		}
		in, _ := r.SigningBytes()
		if b64u(in) != c.SigningInput || b64u(in[len(rosterLabel):]) != c.JCS {
			t.Errorf("%s: signing input differs", c.Description)
		}
		if r.Signature != c.Signature {
			t.Errorf("%s: signature field differs", c.Description)
		}
		// The relay's file stores the roster in JCS form: ours is the same text.
		if j, err := r.JCS(); err != nil || !bytes.Equal(j, mustCanon(t, c.Roster)) {
			t.Errorf("%s: JCS of the roster is not the stored text", c.Description)
		}
	}
	for _, g := range v.Registrations {
		m := registerSigningBytes(g.Network, g.Node, ub(t, g.Challenge), g.TS, g.Origin)
		if b64u(m) != g.Message {
			t.Errorf("%s: message differs", g.Description)
		}
		if !verifyEd25519(ub(t, g.Ed25519), m, ub(t, g.Sig)) {
			t.Errorf("%s: signature does not verify", g.Description)
		}
		if id := keyByID[g.Node]; id == nil || b64u(id.Sign(m)) != g.Sig {
			t.Errorf("%s: re-signing differs", g.Description)
		}
	}
	// Rosters as text: validity turns on the bytes themselves (repeated names, 12.0 and 1.2e1,
	// escaped lone surrogates).
	if len(v.RosterTexts) < 10 {
		t.Fatalf("%d rosterTexts", len(v.RosterTexts))
	}
	for _, c := range v.RosterTexts {
		_, err := ValidateRoster([]byte(c.Text))
		if (err == nil) != c.Valid {
			t.Errorf("rosterTexts %q: valid %v, want %v (%v)", c.Description, err == nil, c.Valid, err)
		}
	}
	// Ed25519 verification, strict and the same everywhere (section 1).
	if len(v.Ed25519) != 24 {
		t.Fatalf("%d ed25519 vectors", len(v.Ed25519))
	}
	for _, c := range v.Ed25519 {
		if got := verifyEd25519(ub(t, c.Pub), ub(t, c.Msg), ub(t, c.Sig)); got != c.Valid {
			t.Errorf("ed25519 %q: verify %v, want %v", c.Description, got, c.Valid)
		}
	}
	for _, f := range v.Frames {
		for _, h := range []string{f.Sent, f.Delivered} {
			d, err := decodeFrame(hx(t, h))
			if err != nil {
				t.Fatalf("%s: %v", f.Description, err)
			}
			again, _ := encodeFrame(d.typ, d.peer, d.body)
			eqHex(t, f.Description, again, h)
		}
		// What a member sends of type 8 arrives as type 3 with the same body, so a receiver
		// handles it as data.
		sent, _ := decodeFrame(hx(t, f.Sent))
		got, _ := decodeFrame(hx(t, f.Delivered))
		if sent.typ == frameControl && (got.typ != frameData || !bytes.Equal(sent.body, got.body)) {
			t.Errorf("%s: control is not delivered as data", f.Description)
		}
	}
}

func TestCacophonyNoiseVectors(t *testing.T) {
	var file struct {
		Vectors []struct {
			ProtocolName     string `json:"protocol_name"`
			InitPrologue     string `json:"init_prologue"`
			InitEphemeral    string `json:"init_ephemeral"`
			InitStatic       string `json:"init_static"`
			InitRemoteStatic string `json:"init_remote_static"`
			RespPrologue     string `json:"resp_prologue"`
			RespEphemeral    string `json:"resp_ephemeral"`
			RespStatic       string `json:"resp_static"`
			RespRemoteStatic string `json:"resp_remote_static"`
			HandshakeHash    string `json:"handshake_hash"`
			Messages         []struct{ Payload, Ciphertext string }
		}
	}
	loadJSON(t, "client/test/vectors/noise-cacophony.json", &file)
	patterns := map[string]noise.HandshakePattern{
		"IK": noise.HandshakeIK, "KK": noise.HandshakeKK, "XX": noise.HandshakeXX, "NN": noise.HandshakeNN,
	}
	seen := map[string]bool{}
	for _, v := range file.Vectors {
		name := strings.Split(v.ProtocolName, "_")[1]
		seen[name] = true
		pattern := patterns[name]
		key := func(h string) noise.DHKey {
			if h == "" {
				return noise.DHKey{}
			}
			k, err := noiseSuite.GenerateKeypair(&fixedReader{hx(t, h)})
			if err != nil {
				t.Fatal(err)
			}
			return k
		}
		opt := func(h string) []byte {
			if h == "" {
				return nil
			}
			return hx(t, h)
		}
		mk := func(initiator bool) *noise.HandshakeState {
			c := noise.Config{CipherSuite: noiseSuite, Pattern: pattern, Initiator: initiator}
			if initiator {
				c.Prologue, c.StaticKeypair, c.PeerStatic = hx(t, v.InitPrologue), key(v.InitStatic), opt(v.InitRemoteStatic)
				c.Random = &fixedReader{hx(t, v.InitEphemeral)}
			} else {
				c.Prologue, c.StaticKeypair, c.PeerStatic = hx(t, v.RespPrologue), key(v.RespStatic), opt(v.RespRemoteStatic)
				c.Random = &fixedReader{hx(t, v.RespEphemeral)}
			}
			hs, err := noise.NewHandshakeState(c)
			if err != nil {
				t.Fatal(err)
			}
			return hs
		}
		init, resp := mk(true), mk(false)
		var iSend, iRecv, rSend, rRecv *noise.CipherState
		hsCount := len(pattern.Messages)
		for i, m := range v.Messages {
			payload := hx(t, m.Payload)
			initiatorSends := i%2 == 0
			if i < hsCount {
				w, r := init, resp
				if !initiatorSends {
					w, r = resp, init
				}
				out, c1, c2, err := w.WriteMessage(nil, payload)
				if err != nil {
					t.Fatal(err)
				}
				eqHex(t, v.ProtocolName+" handshake message", out, m.Ciphertext)
				got, d1, d2, err := r.ReadMessage(nil, out)
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatalf("%s: read: %v", v.ProtocolName, err)
				}
				if c1 != nil {
					if initiatorSends {
						iSend, iRecv, rRecv, rSend = c1, c2, d1, d2
					} else {
						rRecv, rSend, iSend, iRecv = c1, c2, d1, d2
					}
				}
				continue
			}
			s, r := iSend, rRecv
			if !initiatorSends {
				s, r = rSend, iRecv
			}
			ct, err := s.Encrypt(nil, nil, payload)
			if err != nil {
				t.Fatal(err)
			}
			eqHex(t, v.ProtocolName+" transport", ct, m.Ciphertext)
			if pt, err := r.Decrypt(nil, nil, ct); err != nil || !bytes.Equal(pt, payload) {
				t.Errorf("%s: transport does not decrypt", v.ProtocolName)
			}
		}
		eqHex(t, v.ProtocolName+" hash (initiator)", init.ChannelBinding(), v.HandshakeHash)
		eqHex(t, v.ProtocolName+" hash (responder)", resp.ChannelBinding(), v.HandshakeHash)
	}
	if len(seen) != 4 {
		t.Errorf("patterns covered: %v", seen)
	}
}

// The relay's file names its Ed25519 public keys; strict verification is the same as Go's
// for every canonical key, so the vector signatures verify both ways.
func TestVectorsVerifyWithStdlib(t *testing.T) {
	var v relayVectors
	loadJSON(t, "spec/vectors/relay.json", &v)
	for _, g := range v.Registrations {
		m := registerSigningBytes(g.Network, g.Node, ub(t, g.Challenge), g.TS, g.Origin)
		if !ed25519.Verify(ub(t, g.Ed25519), m, ub(t, g.Sig)) {
			t.Error("stdlib refuses a vector signature")
		}
	}
	_ = sha256.Sum256
}

func mustCanon(t *testing.T, raw []byte) []byte {
	t.Helper()
	c, err := Canonicalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// handshakeStamps: the stamp's encoding, and the ordered steps through a real responder
// (section 7.1): accept S; the same bytes again refused; an older stamp refused; S from a new
// ephemeral refused; S+1 accepted; an 8-byte payload refused as malformed.
func TestClientVectorsHandshakeStamps(t *testing.T) {
	v := loadClientVectors(t)
	h := v.HandshakeStamps
	if len(h.Encoding) == 0 || len(h.Steps) < 11 {
		t.Fatalf("%d encoding cases, %d steps", len(h.Encoding), len(h.Steps))
	}
	for _, c := range h.Encoding {
		if got := nextStampAfter(c.WallNowMs, c.LastStamp); got != c.Stamp {
			t.Errorf("stamp after %d at wall %d: %d, want %d", c.LastStamp, c.WallNowMs, got, c.Stamp)
		}
	}
	ids := map[string]*Identity{}
	for _, k := range v.Keys {
		id := mustIdentity(t, hx(t, k.Seed))
		ids[id.ID()] = id
	}
	ini, res := ids[h.Initiator], ids[h.Responder]
	if ini == nil || res == nil {
		t.Fatal("the steps name keys the file does not hold")
	}
	roster, err := ValidateRoster(v.Roster.Signing.Roster)
	if err != nil || roster.member(ini.ID()) == nil || roster.member(res.ID()) == nil {
		t.Fatalf("the signing roster does not list both: %v", err)
	}
	relay := newFakeRelay(t)
	// The responder starts at responderStartedMs; before each step its clock moves on to that
	// step's responderWallNowMs.
	if h.WindowMs != stampWindowMs {
		t.Fatalf("window %d ms, this implementation's %d", h.WindowMs, stampWindowMs)
	}
	clk := newFakeClock(time.UnixMilli(h.ResponderStartedMs))
	m, err := NewMember(MemberOptions{Identity: res, Roster: roster, clock: clk, dial: relay.dial, liveness: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.WaitConnected(ctx); err != nil {
		t.Fatal(err)
	}
	reads := func() int {
		var n int
		locked(m, func() { n = m.sess.stats.initsRead })
		return n
	}
	from, _ := nodeIDToBytes(ini.ID())
	primary := ids[roster.Network]
	if primary == nil {
		t.Fatal("the file does not hold the primary's key, to sign the roster changes")
	}
	answers := func() int {
		relay.mu.Lock()
		defer relay.mu.Unlock()
		return relay.sentTypes[frameHandshakeResp]
	}
	stored := func() (uint64, bool) {
		var s uint64
		var ok bool
		locked(m, func() { s, ok = m.sess.stamps[ini.ID()] })
		return s, ok
	}
	version := roster.Version
	accepted, inits := 0, 0
	for i, step := range h.Steps {
		if d := step.ResponderWallNowMs - clk.Now().UnixMilli(); d < 0 {
			t.Fatalf("%s: the clock would go back", step.Description)
		} else {
			clk.Advance(time.Duration(d) * time.Millisecond)
		}
		if step.Event != "" {
			// A roster change, through the roster-change path: the primary signs the next
			// version without the initiator, or with it again.
			members := roster.Members
			switch step.Event {
			case "removed":
				members = withoutMember(roster.Members, ini.ID())
			case "readmitted":
			default:
				t.Fatalf("%s: unknown event %q", step.Description, step.Event)
			}
			version++
			u := roster.UnsignedRoster
			u.Version, u.Members = version, members
			next, err := SignRoster(u, primary)
			if err != nil {
				t.Fatal(err)
			}
			var took bool
			locked(m, func() { took = m.offerRoster(next) })
			if !took {
				t.Fatalf("%s: the roster change was not accepted", step.Description)
			}
			if s, ok := stored(); step.Stored != nil && (!ok || s != *step.Stored) {
				t.Errorf("%s: stored %d (%v), want %d", step.Description, s, ok, *step.Stored)
			} else if step.Event == "removed" && ok {
				t.Errorf("%s: a stamp is still stored for an id off the roster", step.Description)
			}
			continue
		}
		// An init step: it must say what to send, or the handshake would wait for randomness.
		if len(step.EphemeralPrivate) != 64 || step.Noise == "" || step.Payload == "" {
			t.Fatalf("%s: a malformed init step (no ephemeral key, payload or noise)", step.Description)
		}
		inits++
		// The initiator's side: these bytes are what it writes with this ephemeral key.
		hs, err := newHandshake(ini, true, roster.Network, res.X25519Public(), &fixedReader{hx(t, step.EphemeralPrivate)})
		if err != nil {
			t.Fatal(err)
		}
		msg1, _, _, err := hs.WriteMessage(nil, hx(t, step.Payload))
		if err != nil {
			t.Fatalf("%s: %v", step.Description, err)
		}
		eqHex(t, step.Description, msg1, step.Noise)
		if step.Stamp != nil && hex.EncodeToString(initPayload(uint64(roster.Version), *step.Stamp)) != step.Payload {
			t.Errorf("%s: payload is not version || stamp", step.Description)
		}
		// The responder's side. The steps test the stamp rule alone: the id's failure budget
		// (which would drop inits after four refusals) starts full for each.
		locked(m, func() {
			if p := m.sess.limits.members[ini.ID()]; p != nil {
				p.fails = bucket{}
			}
		})
		f, _ := encodeFrame(frameHandshakeInit, from, handshakeInitBody(uint32(i)+1, hx(t, step.Noise)))
		relay.inject(res.ID(), f)
		eventually(t, step.Description, func() bool { return reads() == inits })
		// An accepted init is answered with handshake-resp (the relay then says the initiator
		// is unreachable, which ends the session: nobody is behind the vector's keys); a refused
		// one is dropped unanswered.
		if step.Accepted {
			accepted++
		}
		time.Sleep(10 * time.Millisecond)
		eventually(t, step.Description+" answered", func() bool { return answers() >= accepted })
		stamp, _ := stored()
		// What is stored: the stored field where given, else the stamp as it is.
		want := uint64(0)
		if step.Stamp != nil {
			want = *step.Stamp
		}
		if step.Stored != nil {
			want = *step.Stored
		}
		if n := answers(); n != accepted || step.Stored != nil && stamp != want || step.Accepted && stamp != want {
			t.Errorf("%s: %d answered after it, want %d (accepted %v), stamp %d", step.Description, n, accepted, step.Accepted, stamp)
		}
	}
}
