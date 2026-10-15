package vectors

import (
	"crypto/ed25519"
	"fmt"
	"math/big"

	"github.com/frontierengineer/link/relay/internal/link"
)

// ed25519Vectors are signatures that section 1's verification must accept or refuse, each
// built so that one rule decides it where it can: an honest signature, then for each rule a
// signature whose equation holds over the decoded points (so a verifier without that rule
// accepts it), and the cases where the cofactored and cofactorless equations disagree.
func ed25519Vectors(ka, kb *link.Keys) []ed25519Vector {
	a := edSecret(ka.Ed25519Seed)
	A := edBase.mul(a)
	aEnc := A.encode()
	if string(aEnc) != string(ka.Ed25519Public) {
		panic("vectors: edwards arithmetic disagrees with crypto/ed25519")
	}
	var out []ed25519Vector
	add := func(desc string, pub, msg, sig []byte, valid bool) {
		out = append(out, ed25519Vector{Description: desc, Pub: b64(pub), Msg: b64(msg), Sig: b64(sig), Valid: valid})
	}
	// expect checks what the two equations say of a case, so each vector means what it says.
	expect := func(pub, msg, sig []byte, cofactorless, cofactored bool) {
		cl, cf := edEquations(pub, msg, sig)
		if cl != cofactorless || cf != cofactored {
			panic(fmt.Sprintf("vectors: equations %v/%v, want %v/%v", cl, cf, cofactorless, cofactored))
		}
	}
	// msgWhere finds a message whose challenge over (R, A) meets pred.
	msgWhere := func(r, pub []byte, pred func(k *big.Int) bool) ([]byte, *big.Int) {
		for i := 0; ; i++ {
			m := []byte(fmt.Sprintf("frontier-link/1/vector %d", i))
			if k := edChallenge(r, pub, m); pred(k) {
				return m, k
			}
		}
	}
	divisible := func(n int64) func(*big.Int) bool {
		return func(k *big.Int) bool { return new(big.Int).Mod(k, big.NewInt(n)).Sign() == 0 }
	}
	notDivisible := func(n int64) func(*big.Int) bool {
		return func(k *big.Int) bool { return new(big.Int).Mod(k, big.NewInt(n)).Sign() != 0 }
	}
	sig := func(r []byte, s *big.Int) []byte { return append(append([]byte(nil), r...), edScalarBytes(s)...) }
	mod := func(v *big.Int) *big.Int { return v.Mod(v, edL) }

	// Honest signatures.
	m0 := []byte("frontier-link/1/roster{\"vector\":1}")
	add("an honest signature", aEnc, m0, ed25519.Sign(ka.Ed25519, m0), true)
	m1 := []byte("frontier-link/1/register, another key")
	add("an honest signature by another key", kb.Ed25519Public, m1, ed25519.Sign(kb.Ed25519, m1), true)

	// The eight points of small order as A: R = [r]B, S = r, and a message whose challenge is a
	// multiple of 8, so [k]A is the identity and the equation holds.
	r := big.NewInt(0x1234567)
	R := edBase.mul(r).encode()
	names := []string{"the identity", "the point of order 2", "a point of order 4", "the other point of order 4",
		"a point of order 8", "its negation", "another point of order 8", "its negation"}
	small := smallOrderEncodings()
	for i, t := range small {
		m, _ := msgWhere(R, t, divisible(8))
		s := sig(R, r)
		expect(t, m, s, true, true)
		add("small-order A: "+names[i], t, m, s, false)
	}
	// The same points written otherwise: y + p (possible where y < 19), and x = 0 with the
	// sign bit set.
	for _, c := range []struct {
		name string
		enc  []byte
	}{
		{"the identity written y = p + 1", edEncodeY(new(big.Int).Add(edP, big.NewInt(1)), 0)},
		{"the identity with the sign bit set (x = 0)", edEncodeY(big.NewInt(1), 1)},
		{"the point of order 2 with the sign bit set (x = 0)", edEncodeY(new(big.Int).Sub(edP, big.NewInt(1)), 1)},
		{"a point of order 4 written y = p", edEncodeY(edP, 0)},
		{"the other point of order 4 written y = p", edEncodeY(edP, 1)},
	} {
		m, _ := msgWhere(R, c.enc, divisible(8))
		s := sig(R, r)
		expect(c.enc, m, s, true, true)
		add("non-canonical small-order A: "+c.name, c.enc, m, s, false)
	}

	// A non-canonical encoding of a point of large order (y < 19, written y + p). Without its
	// secret no signature verifies; it is refused for the encoding first.
	found := false
	for y := int64(2); y < 19 && !found; y++ {
		enc := edEncodeY(new(big.Int).Add(edP, big.NewInt(y)), 0)
		p, ok := edDecode(enc)
		if !ok || link.IsSmallOrder(p.encode()) {
			continue
		}
		m := []byte("frontier-link/1/non-canonical key")
		add(fmt.Sprintf("non-canonical A: the point with y = %d written y = p + %d", y, y), enc, m, sig(R, r), false)
		found = true
	}
	if !found {
		panic("vectors: no point of large order with y < 19")
	}

	// R non-canonical: the identity written y = p + 1, with S = k·a, so that over the decoded
	// points [S]B = R + [k]A.
	{
		rEnc := edEncodeY(new(big.Int).Add(edP, big.NewInt(1)), 0)
		k := edChallenge(rEnc, aEnc, m0)
		s := sig(rEnc, mod(new(big.Int).Mul(k, a)))
		expect(aEnc, m0, s, true, true)
		add("non-canonical R: the identity written y = p + 1 (the equation holds over the decoded points)", aEnc, m0, s, false)
	}
	// R of small order. The identity with S = k·a satisfies both equations: crypto/ed25519 alone
	// accepts it. A point of order 8 with S = k·a satisfies only the cofactored one.
	for i, t := range []int{0, 4} {
		rEnc := small[t]
		k := edChallenge(rEnc, aEnc, m0)
		s := sig(rEnc, mod(new(big.Int).Mul(k, a)))
		expect(aEnc, m0, s, i == 0, true)
		add("small-order R: "+names[t]+", S = k·a", aEnc, m0, s, false)
	}

	// S not below L: an honest signature with L added to S.
	{
		good := ed25519.Sign(ka.Ed25519, m0)
		s := new(big.Int).SetBytes(func() []byte {
			be := make([]byte, 32)
			for i := range 32 {
				be[i] = good[63-i]
			}
			return be
		}())
		bad := sig(good[:32], s.Add(s, edL))
		expect(aEnc, m0, bad, true, true)
		add("S + L in place of S (S >= L)", aEnc, m0, bad, false)
	}

	// Mixed order. A' = [a]B + T8 with R = [r]B and S = r + k·a: the cofactorless equation holds
	// only when 8 divides k, the cofactored one always. Both are A' of neither small nor prime
	// order, canonical; the rule accepts the first and refuses the second.
	t8 := edMustDecode(small[4])
	mixedA := edBase.mul(a).add(t8).encode()
	{
		m, k := msgWhere(R, mixedA, divisible(8))
		s := sig(R, mod(new(big.Int).Add(r, new(big.Int).Mul(k, a))))
		expect(mixedA, m, s, true, true)
		add("mixed-order A = [a]B + T8, k a multiple of 8: both equations hold", mixedA, m, s, true)
	}
	{
		m, k := msgWhere(R, mixedA, notDivisible(8))
		s := sig(R, mod(new(big.Int).Add(r, new(big.Int).Mul(k, a))))
		expect(mixedA, m, s, false, true)
		add("mixed-order A = [a]B + T8, k not a multiple of 8: only the cofactored equation holds", mixedA, m, s, false)
	}
	// R = [r]B + T8 with S = r + k·a: only the cofactored equation holds.
	{
		mixedR := edBase.mul(r).add(t8).encode()
		k := edChallenge(mixedR, aEnc, m0)
		s := sig(mixedR, mod(new(big.Int).Add(r, new(big.Int).Mul(k, a))))
		expect(aEnc, m0, s, false, true)
		add("mixed-order R = [r]B + T8: only the cofactored equation holds", aEnc, m0, s, false)
	}

	// The order-4 forgery: A of order 4, R the identity, S = 0, for a message whose challenge
	// is a multiple of 4. Anyone can make one for any message; a verifier without the
	// small-order rules accepts it.
	{
		rEnc := small[0]
		m, _ := msgWhere(rEnc, small[2], divisible(4))
		s := sig(rEnc, big.NewInt(0))
		expect(small[2], m, s, true, true)
		add("the order-4 forgery: A of order 4, R the identity, S = 0", small[2], m, s, false)
	}
	return out
}

// smallOrderEncodings are the eight points of small order, canonical, checked here against
// their order.
func smallOrderEncodings() [][]byte {
	var out [][]byte
	for _, enc := range smallOrderHex {
		p := edMustDecode(enc)
		if !p.mul(big.NewInt(8)).equal(edIdentity()) || string(p.encode()) != string(enc) || !link.IsSmallOrder(enc) {
			panic("vectors: not a canonical point of small order")
		}
		out = append(out, enc)
	}
	return out
}

var smallOrderHex = func() [][]byte {
	var out [][]byte
	for _, h := range []string{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000080",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	} {
		b := make([]byte, 32)
		for i := range 32 {
			fmt.Sscanf(h[2*i:2*i+2], "%02x", &b[i])
		}
		out = append(out, b)
	}
	return out
}()
