package link

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"math/big"
)

// Ed25519 verification as section 1 fixes it, identical in every implementation:
//   - A (the public key) and R are canonical encodings: y < p, and x = 0 never with the sign
//     bit set;
//   - neither A nor R is one of the eight points of small order;
//   - S < L;
//   - the equation is cofactorless: [S]B = R + [k]A, with k = SHA-512(R || A || M) mod L.
//
// crypto/ed25519 already checks S < L and the cofactorless equation, and compares R by its
// encoding; the checks on the encodings of A and R come first, here.

// fieldP is 2^255 - 19.
var fieldP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

// smallOrder holds the canonical encodings of the eight points of small order: the identity,
// the point of order 2, the two of order 4 and the four of order 8. A canonical encoding of
// any other point is not among them.
var smallOrder = func() [][]byte {
	var out [][]byte
	for _, h := range []string{
		"0100000000000000000000000000000000000000000000000000000000000000", // identity
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 2: y = -1
		"0000000000000000000000000000000000000000000000000000000000000000", // order 4: y = 0
		"0000000000000000000000000000000000000000000000000000000000000080", // order 4, -x
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", // order 8, -x
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", // order 8, -x
	} {
		b, err := hex.DecodeString(h)
		if err != nil {
			panic(err)
		}
		out = append(out, b)
	}
	return out
}()

// canonicalPoint reports whether p, 32 bytes, encodes y < p, and does not set the sign bit for
// a point whose x is 0 (y = 1 or y = p - 1). Whether a point with that y exists is the
// verifier's to decide; this checks only that the encoding is the one encoding of its point.
func canonicalPoint(p []byte) bool {
	if len(p) != 32 {
		return false
	}
	le := bytes.Clone(p)
	sign := le[31] >> 7
	le[31] &= 0x7f
	for i, j := 0, len(le)-1; i < j; i, j = i+1, j-1 {
		le[i], le[j] = le[j], le[i]
	}
	y := new(big.Int).SetBytes(le)
	if y.Cmp(fieldP) >= 0 {
		return false
	}
	if sign == 1 && (y.Cmp(big.NewInt(1)) == 0 || y.Cmp(new(big.Int).Sub(fieldP, big.NewInt(1))) == 0) {
		return false
	}
	return true
}

// IsSmallOrder reports whether p is the canonical encoding of a point of small order.
func IsSmallOrder(p []byte) bool {
	for _, s := range smallOrder {
		if bytes.Equal(p, s) {
			return true
		}
	}
	return false
}

// VerifyEd25519 is the protocol's one Ed25519 verification (section 1). Every signature the
// relay checks goes through it.
func VerifyEd25519(pub, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	r := sig[:32]
	if !canonicalPoint(pub) || !canonicalPoint(r) || IsSmallOrder(pub) || IsSmallOrder(r) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}
