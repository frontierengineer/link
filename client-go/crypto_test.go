package link

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"filippo.io/nistec"
)

func TestReduceModNMatchesBigInt(t *testing.T) {
	n := new(big.Int).SetBytes(p256N)
	cases := [][]byte{nil, {0}, {1}, p256N, append([]byte{0}, p256N...), bytes.Repeat([]byte{0xff}, 48), bytes.Repeat([]byte{0xff}, 40)}
	nMinus1 := new(big.Int).Sub(n, big.NewInt(1)).FillBytes(make([]byte, 32))
	nPlus1 := new(big.Int).Add(n, big.NewInt(1)).FillBytes(make([]byte, 32))
	cases = append(cases, nMinus1, nPlus1)
	for range 2000 {
		b := make([]byte, 1+int(randByte())%48)
		rand.Read(b)
		cases = append(cases, b)
	}
	for _, c := range cases {
		got := reduceModN(c)
		want := new(big.Int).Mod(new(big.Int).SetBytes(c), n).FillBytes(make([]byte, 32))
		if !bytes.Equal(got[:], want) {
			t.Fatalf("reduce %x: got %x want %x", c, got, want)
		}
	}
	for range 200 {
		b := make([]byte, 48)
		rand.Read(b)
		s := reduceModN(b)
		if isZero32(s) {
			continue
		}
		neg := negModN(s)
		sum := new(big.Int).Add(new(big.Int).SetBytes(s[:]), new(big.Int).SetBytes(neg[:]))
		if sum.Cmp(n) != 0 {
			t.Fatalf("n - s wrong for %x", s)
		}
	}
}

func randByte() byte {
	var b [1]byte
	rand.Read(b[:])
	return b[0]
}

func TestSpake2RefusesBadShares(t *testing.T) {
	w, _ := deriveW("ABCD1234")
	a, err := newSpake2(true, w, nil, []byte(spake2IDA), []byte(spake2IDB), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := newSpake2(false, w, nil, []byte(spake2IDA), []byte(spake2IDB), nil)
	notOnCurve := append([]byte{}, b.share...)
	notOnCurve[64] ^= 1
	compressed := mustPointBytes(t, b.share)
	// pB = w*N makes pB - w*N the identity: K would be the identity, which RFC 9382 refuses.
	wN, _ := nistec.NewP256Point().ScalarMult(spake2N, w[:])
	cases := map[string][]byte{
		"empty":             nil,
		"identity encoding": {0},
		"short":             b.share[:64],
		"long":              append(append([]byte{}, b.share...), 0),
		"compressed":        compressed,
		"wrong prefix":      append([]byte{5}, b.share[1:]...),
		"not on the curve":  notOnCurve,
		"x >= p":            append([]byte{4}, bytes.Repeat([]byte{0xff}, 64)...),
		"degenerate":        wN.Bytes(),
	}
	for name, share := range cases {
		if _, err := a.finish(share); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := a.finish(b.share); err != nil {
		t.Fatalf("a valid share refused: %v", err)
	}
	if _, err := newSpake2(true, [32]byte{}, nil, nil, nil, nil); err == nil {
		t.Error("w = 0 accepted")
	}
	var zero [32]byte
	if _, err := newSpake2(true, w, &zero, nil, nil, nil); err == nil {
		t.Error("a zero scalar accepted")
	}
}

func mustPointBytes(t *testing.T, uncompressed []byte) []byte {
	p, err := nistec.NewP256Point().SetBytes(uncompressed)
	if err != nil {
		t.Fatal(err)
	}
	return p.BytesCompressed()
}

func TestPairingExchangeFailsOnWrongCodeOrCodeID(t *testing.T) {
	run := func(codeA, codeB string, idA, idB []byte) error {
		nc, _ := newNewcomerExchange(codeA, idA, nil)
		pr, _ := newPrimaryExchange(codeB, idB, nil)
		p2, err := pr.onP1(nc.p1())
		if err != nil {
			return err
		}
		p3, err := nc.onP2(p2)
		if err != nil {
			return err
		}
		ok, err := pr.onP3(p3)
		if err != nil {
			return err
		}
		if !ok {
			return errPairTest
		}
		p4, _ := pr.p4()
		id, _ := NewIdentity()
		if _, err := nc.onP4(p4, newcomerKeys{ed25519: id.edPub, x25519: id.xPub[:]}); err != nil {
			return err
		}
		return nil
	}
	id1, id2 := []byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte{8, 7, 6, 5, 4, 3, 2, 1}
	if err := run("ABCD1234", "ABCD1234", id1, id1); err != nil {
		t.Fatalf("same code fails: %v", err)
	}
	if err := run("ABCD1234", "ABCD1235", id1, id1); err == nil {
		t.Error("a wrong code passes")
	}
	if err := run("ABCD1234", "ABCD1234", id1, id2); err == nil {
		t.Error("a different code id passes")
	}
	// A forged cB is refused by the newcomer; a P5 that will not open fails the primary.
	nc, _ := newNewcomerExchange("ABCD1234", id1, nil)
	pr, _ := newPrimaryExchange("ABCD1234", id1, nil)
	p2, _ := pr.onP1(nc.p1())
	p3, _ := nc.onP2(p2)
	pr.onP3(p3)
	p4, _ := pr.p4()
	forged := append([]byte{}, p4...)
	forged[0] ^= 1
	id, _ := NewIdentity()
	if _, err := nc.onP4(forged, newcomerKeys{ed25519: id.edPub, x25519: id.xPub[:]}); err == nil {
		t.Error("a forged cB passes")
	}
	p5, err := nc.onP4(p4, newcomerKeys{ed25519: id.edPub, x25519: id.xPub[:]})
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte{}, p5...)
	bad[len(bad)-1] ^= 1
	if _, err := pr.onP5(bad); err == nil {
		t.Error("a tampered P5 opens")
	}
	if _, err := pr.onP5(p5); err != nil {
		t.Errorf("P5 refused after a failed open: %v", err)
	}
	// Out-of-order calls fail.
	nc2, _ := newNewcomerExchange("ABCD1234", id1, nil)
	if _, err := nc2.onP4(p4, newcomerKeys{}); err == nil {
		t.Error("P4 before P2")
	}
	if _, err := nc2.onP6(p4); err == nil {
		t.Error("P6 before P4")
	}
}

type pairTestError struct{}

func (pairTestError) Error() string { return "cA refused" }

var errPairTest = pairTestError{}

// ── Ed25519 strictness ──

// Edwards25519 arithmetic in math/big, for tests only: enough to decode points and multiply
// them by small scalars.
var (
	edP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	edD = func() *big.Int {
		d := new(big.Int).Mul(big.NewInt(-121665), new(big.Int).ModInverse(big.NewInt(121666), edP))
		return d.Mod(d, edP)
	}()
)

type edPoint struct{ x, y *big.Int }

func edAdd(a, b edPoint) edPoint {
	x1y2 := new(big.Int).Mul(a.x, b.y)
	y1x2 := new(big.Int).Mul(a.y, b.x)
	y1y2 := new(big.Int).Mul(a.y, b.y)
	x1x2 := new(big.Int).Mul(a.x, b.x)
	dxy := new(big.Int).Mul(edD, new(big.Int).Mul(x1x2, y1y2))
	dxy.Mod(dxy, edP)
	one := big.NewInt(1)
	xd := new(big.Int).ModInverse(new(big.Int).Mod(new(big.Int).Add(one, dxy), edP), edP)
	yd := new(big.Int).ModInverse(new(big.Int).Mod(new(big.Int).Sub(one, dxy), edP), edP)
	x := new(big.Int).Mul(new(big.Int).Add(x1y2, y1x2), xd)
	y := new(big.Int).Mul(new(big.Int).Add(y1y2, x1x2), yd) // a = -1: y1y2 - a x1x2
	return edPoint{x.Mod(x, edP), y.Mod(y, edP)}
}

func edDecode(t *testing.T, b []byte) (edPoint, bool) {
	t.Helper()
	le := make([]byte, 32)
	for i := range 32 {
		le[i] = b[31-i]
	}
	le[0] &= 0x7f
	y := new(big.Int).SetBytes(le)
	y.Mod(y, edP) // as Go's SetBytes does: non-canonical y is reduced
	sign := b[31] >> 7
	y2 := new(big.Int).Mul(y, y)
	u := new(big.Int).Sub(y2, big.NewInt(1))
	v := new(big.Int).Add(new(big.Int).Mul(edD, y2), big.NewInt(1))
	x2 := new(big.Int).Mul(u, new(big.Int).ModInverse(v.Mod(v, edP), edP))
	x2.Mod(x2, edP)
	x := new(big.Int).ModSqrt(x2, edP)
	if x == nil {
		return edPoint{}, false
	}
	if x.Bit(0) != uint(sign) {
		x.Sub(edP, x)
		x.Mod(x, edP)
	}
	return edPoint{x, y}, true
}

func TestSmallOrderListIsTheEightPoints(t *testing.T) {
	identity := edPoint{big.NewInt(0), big.NewInt(1)}
	for _, enc := range smallOrderPoints {
		for _, sign := range []byte{0, 0x80} {
			b := append([]byte{}, enc...)
			b[31] |= sign
			p, ok := edDecode(t, b)
			if !ok {
				continue // x = 0 has no negative: the sign-bit variant does not decode
			}
			q := p
			for range 3 {
				q = edAdd(q, q)
			}
			if q.x.Sign() != 0 || q.y.Cmp(identity.y) != 0 {
				t.Errorf("%x is not of small order", b)
			}
			if !smallOrderEd25519(b) {
				t.Errorf("%x not recognised", b)
			}
		}
	}
	id, _ := NewIdentity()
	if smallOrderEd25519(id.edPub) {
		t.Error("a real key flagged as small order")
	}
}

func TestCanonicalEd25519(t *testing.T) {
	pFF := func(first, last byte) []byte {
		b := bytes.Repeat([]byte{0xff}, 32)
		b[0], b[31] = first, last
		return b
	}
	canonical := [][]byte{make([]byte, 32), mustHex("0100000000000000000000000000000000000000000000000000000000000000"), pFF(0xec, 0x7f), pFF(0xeb, 0xff)}
	nonCanonical := [][]byte{
		pFF(0xed, 0x7f), pFF(0xee, 0x7f), pFF(0xff, 0x7f), pFF(0xed, 0xff), // y >= p
		mustHex("0100000000000000000000000000000000000000000000000000000000000080"), // y = 1, x = -0
		pFF(0xec, 0xff), // y = p - 1, x = -0
	}
	for _, b := range canonical {
		if !canonicalEd25519(b) {
			t.Errorf("%x refused", b)
		}
	}
	for _, b := range nonCanonical {
		if canonicalEd25519(b) {
			t.Errorf("%x accepted", b)
		}
	}
}

// Go's crypto/ed25519 accepts a public key of small order, in a canonical encoding or not,
// and under such a key anyone can make a signature that verifies: here R is the identity and
// S = 0, which holds whenever [k]A is the identity, that is (A of order 4) when
// k = H(R || A || M) mod L is a multiple of 4. The spec rejects every non-canonical encoding,
// and the TypeScript client rejects small-order keys; verifyEd25519 refuses both.
func TestEd25519WeakKeysRefused(t *testing.T) {
	R := mustHex("0100000000000000000000000000000000000000000000000000000000000000")
	sig := append(append([]byte{}, R...), make([]byte, 32)...)
	L, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	forge := func(A []byte) []byte {
		for i := 0; ; i++ {
			msg := []byte("frontier " + strings.Repeat("x", i))
			h := sha512.Sum512(append(append(append([]byte{}, R...), A...), msg...))
			le := make([]byte, 64)
			for j := range 64 {
				le[j] = h[63-j]
			}
			if k := new(big.Int).Mod(new(big.Int).SetBytes(le), L); k.Bit(0) == 0 && k.Bit(1) == 0 {
				return msg
			}
		}
	}
	for name, A := range map[string][]byte{
		"y = 0, canonical":        make([]byte, 32),
		"y = 0, written as y = p": pFFKey(),
	} {
		msg := forge(A)
		if !ed25519.Verify(A, msg, sig) {
			t.Fatalf("%s: crypto/ed25519 refuses the forgery; this test shows nothing", name)
		}
		if verifyEd25519(A, msg, sig) {
			t.Errorf("%s: a forged signature under a weak key accepted", name)
		}
		t.Logf("%s: crypto/ed25519 accepts key %s; verifyEd25519 refuses it", name, hex.EncodeToString(A))
	}
}

func pFFKey() []byte {
	b := bytes.Repeat([]byte{0xff}, 32)
	b[0], b[31] = 0xed, 0x7f // y = p, i.e. y = 0
	return b
}

func TestEd25519NonCanonicalSignatureRefused(t *testing.T) {
	id, _ := NewIdentity()
	msg := []byte("frontier")
	sig := id.Sign(msg)
	if !verifyEd25519(id.edPub, msg, sig) {
		t.Fatal("canonical signature refused")
	}
	// S + L: the same signature in a non-canonical encoding.
	l := [32]byte{0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}
	out := append([]byte{}, sig...)
	carry := 0
	for i := range 32 {
		v := int(out[32+i]) + int(l[i]) + carry
		out[32+i], carry = byte(v), v>>8
	}
	if verifyEd25519(id.edPub, msg, out) {
		t.Fatal("non-canonical S accepted")
	}
	if verifyEd25519(id.edPub[:31], msg, sig) || verifyEd25519(id.edPub, msg, sig[:63]) {
		t.Fatal("wrong lengths accepted")
	}
}

// R, like A, must be canonical and not of small order. A signature whose R is the identity
// is easy to make with the private key (S = k·a mod L), and crypto/ed25519 accepts it.
func TestEd25519SmallOrderRRefused(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 32)
	priv := ed25519.NewKeyFromSeed(seed)
	A := priv.Public().(ed25519.PublicKey)
	h := sha512.Sum512(seed)
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	a := new(big.Int).SetBytes(reverse(h[:32]))
	L, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	R := mustHex("0100000000000000000000000000000000000000000000000000000000000000") // the identity
	msg := []byte("frontier")
	kh := sha512.Sum512(append(append(append([]byte{}, R...), A...), msg...))
	k := new(big.Int).Mod(new(big.Int).SetBytes(reverse(kh[:])), L)
	S := new(big.Int).Mod(new(big.Int).Mul(k, a), L)
	sig := append(append([]byte{}, R...), reverse(S.FillBytes(make([]byte, 32)))...)
	if !ed25519.Verify(A, msg, sig) {
		t.Fatal("crypto/ed25519 refuses the small-order R; this test shows nothing")
	}
	if verifyEd25519(A, msg, sig) {
		t.Fatal("a signature with a small-order R accepted")
	}
	// The same R written non-canonically (x = 0 with the sign bit): refused by both.
	nc := append([]byte{}, sig...)
	nc[31] |= 0x80
	if verifyEd25519(A, msg, nc) {
		t.Fatal("a non-canonical R accepted")
	}
	// An honest signature still verifies.
	if !verifyEd25519(A, msg, ed25519.Sign(priv, msg)) {
		t.Fatal("an honest signature refused")
	}
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}
