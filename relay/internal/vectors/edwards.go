package vectors

// Just enough edwards25519 arithmetic, on math/big, to build the Ed25519 vectors: points that
// crypto/ed25519 will not make (small and mixed order, non-canonical encodings) and signatures
// over them. Slow and not constant-time; it signs nothing but test vectors.

import (
	"crypto/sha512"
	"math/big"
)

var (
	edP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	// edL is the order of the prime subgroup: 2^252 + 27742317777372353535851937790883648493.
	edL, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	edD    = func() *big.Int {
		d := new(big.Int).Mul(big.NewInt(-121665), new(big.Int).ModInverse(big.NewInt(121666), edP))
		return d.Mod(d, edP)
	}()
	edSqrtM1 = new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(edP, big.NewInt(1)), 2), edP)
)

type edPoint struct{ x, y *big.Int }

func edIdentity() edPoint { return edPoint{big.NewInt(0), big.NewInt(1)} }

func edMod(v *big.Int) *big.Int { return v.Mod(v, edP) }

// add is the complete twisted Edwards addition for a = -1.
func (p edPoint) add(q edPoint) edPoint {
	x1y2 := new(big.Int).Mul(p.x, q.y)
	y1x2 := new(big.Int).Mul(p.y, q.x)
	y1y2 := new(big.Int).Mul(p.y, q.y)
	x1x2 := new(big.Int).Mul(p.x, q.x)
	t := edMod(new(big.Int).Mul(edD, edMod(new(big.Int).Mul(x1x2, y1y2))))
	xn := edMod(new(big.Int).Add(x1y2, y1x2))
	xd := edMod(new(big.Int).Add(big.NewInt(1), t))
	yn := edMod(new(big.Int).Add(y1y2, x1x2))
	yd := edMod(new(big.Int).Sub(big.NewInt(1), t))
	return edPoint{
		edMod(xn.Mul(xn, new(big.Int).ModInverse(xd, edP))),
		edMod(yn.Mul(yn, new(big.Int).ModInverse(yd, edP))),
	}
}

func (p edPoint) neg() edPoint { return edPoint{edMod(new(big.Int).Neg(p.x)), new(big.Int).Set(p.y)} }

func (p edPoint) mul(k *big.Int) edPoint {
	r := edIdentity()
	for i := k.BitLen() - 1; i >= 0; i-- {
		r = r.add(r)
		if k.Bit(i) == 1 {
			r = r.add(p)
		}
	}
	return r
}

func (p edPoint) equal(q edPoint) bool { return p.x.Cmp(q.x) == 0 && p.y.Cmp(q.y) == 0 }

// encode is the canonical encoding: y little-endian, the sign of x in the top bit.
func (p edPoint) encode() []byte {
	return edEncodeY(p.y, p.x.Bit(0))
}

// edEncodeY writes any y below 2^255 (canonical or not) with sign bit s.
func edEncodeY(y *big.Int, s uint) []byte {
	out := make([]byte, 32)
	b := y.Bytes()
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	out[31] |= byte(s << 7)
	return out
}

// edDecode reads an encoding, canonical or not (y is taken mod p); false if no point has it.
func edDecode(enc []byte) (edPoint, bool) {
	le := append([]byte(nil), enc...)
	sign := uint(le[31] >> 7)
	le[31] &= 0x7f
	be := make([]byte, 32)
	for i := range le {
		be[i] = le[31-i]
	}
	y := edMod(new(big.Int).SetBytes(be))
	y2 := edMod(new(big.Int).Mul(y, y))
	u := edMod(new(big.Int).Sub(y2, big.NewInt(1)))
	v := edMod(new(big.Int).Add(new(big.Int).Mul(edD, y2), big.NewInt(1)))
	x2 := edMod(u.Mul(u, new(big.Int).ModInverse(v, edP)))
	x := new(big.Int).Exp(x2, new(big.Int).Rsh(new(big.Int).Add(edP, big.NewInt(3)), 3), edP)
	if edMod(new(big.Int).Mul(x, x)).Cmp(x2) != 0 {
		x = edMod(x.Mul(x, edSqrtM1))
	}
	if edMod(new(big.Int).Mul(x, x)).Cmp(x2) != 0 {
		return edPoint{}, false
	}
	if x.Sign() == 0 && sign == 1 {
		// No canonical point has it, but it reads as x = 0 (what a lax decoder does).
		return edPoint{x, y}, true
	}
	if x.Bit(0) != sign {
		x = edMod(x.Neg(x))
	}
	return edPoint{x, y}, true
}

func edMustDecode(enc []byte) edPoint {
	p, ok := edDecode(enc)
	if !ok {
		panic("vectors: not a point")
	}
	return p
}

var edBase = edMustDecode(func() []byte {
	b := make([]byte, 32)
	b[0] = 0x58
	for i := 1; i < 32; i++ {
		b[i] = 0x66
	}
	return b
}())

// edScalar reads 64 bytes, little-endian, mod L.
func edScalar(h []byte) *big.Int {
	be := make([]byte, len(h))
	for i := range h {
		be[i] = h[len(h)-1-i]
	}
	return new(big.Int).Mod(new(big.Int).SetBytes(be), edL)
}

func edScalarBytes(s *big.Int) []byte {
	out := make([]byte, 32)
	b := s.Bytes()
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}

// edChallenge is k = SHA-512(R || A || M) mod L, over the encodings as given.
func edChallenge(r, a, m []byte) *big.Int {
	h := sha512.New()
	h.Write(r)
	h.Write(a)
	h.Write(m)
	return edScalar(h.Sum(nil))
}

// edSecret is the clamped scalar of an Ed25519 seed (RFC 8032), mod L.
func edSecret(seed []byte) *big.Int {
	h := sha512.Sum512(seed)
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64
	be := make([]byte, 32)
	for i := range 32 {
		be[i] = h[31-i]
	}
	return new(big.Int).Mod(new(big.Int).SetBytes(be), edL)
}

// edCofactorless and edCofactored are the two equations, over decoded points (no encoding or
// small-order checks): [S]B = R + [k]A, and [8][S]B = [8]R + [8][k]A.
func edEquations(pub, msg, sig []byte) (cofactorless, cofactored bool) {
	a, ok1 := edDecode(pub)
	r, ok2 := edDecode(sig[:32])
	s := new(big.Int).SetBytes(func() []byte {
		be := make([]byte, 32)
		for i := range 32 {
			be[i] = sig[63-i]
		}
		return be
	}())
	if !ok1 || !ok2 {
		return false, false
	}
	k := edChallenge(sig[:32], pub, msg)
	lhs := edBase.mul(s)
	rhs := r.add(a.mul(k))
	eight := big.NewInt(8)
	return lhs.equal(rhs), lhs.mul(eight).equal(rhs.mul(eight))
}
