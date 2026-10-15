package link

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/bits"

	"filippo.io/nistec"
)

// SPAKE2 over P-256, RFC 9382 ciphersuite P256-SHA256-HKDF-HMAC, with this protocol's
// parameters (section 5.3). A is the newcomer and uses M; B is the primary and uses N. The
// group arithmetic is filippo.io/nistec (the standard library's own constant-time P-256);
// scalars are reduced here in constant time.

const (
	spake2IDA = "frontier-link/1/newcomer"
	spake2IDB = "frontier-link/1/primary"
)

// p256N is the order n of the P-256 group, big-endian, and the same as little-endian limbs.
var (
	p256N      = mustHex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
	p256NLimbs = limbs(p256N)
	// RFC 9382 section 6, compressed SEC1.
	spake2M = mustPoint("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f")
	spake2N = mustPoint("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49")
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func mustPoint(s string) *nistec.P256Point {
	p, err := nistec.NewP256Point().SetBytes(mustHex(s))
	if err != nil {
		panic(err)
	}
	return p
}

func limbs(b []byte) [4]uint64 {
	var l [4]uint64
	for i := range 4 {
		l[i] = binary.BigEndian.Uint64(b[24-8*i : 32-8*i])
	}
	return l
}

func limbBytes(l [4]uint64) [32]byte {
	var b [32]byte
	for i := range 4 {
		binary.BigEndian.PutUint64(b[24-8*i:32-8*i], l[i])
	}
	return b
}

// reduceModN returns b (big-endian, any length) mod n in constant time: one bit at a time,
// r = 2r + bit, then r - n kept whenever 2r + bit overflowed 256 bits or did not borrow.
func reduceModN(b []byte) [32]byte {
	var r [4]uint64
	for _, x := range b {
		for i := 7; i >= 0; i-- {
			c := uint64(x>>uint(i)) & 1
			for j := range 4 {
				r[j], c = r[j]<<1|c, r[j]>>63
			}
			var d [4]uint64
			var borrow uint64
			for j := range 4 {
				d[j], borrow = bits.Sub64(r[j], p256NLimbs[j], borrow)
			}
			mask := -(c | (borrow ^ 1))
			for j := range 4 {
				r[j] = r[j]&^mask | d[j]&mask
			}
		}
	}
	return limbBytes(r)
}

// negModN is n - s for 0 < s < n, in constant time.
func negModN(s [32]byte) [32]byte {
	sl := limbs(s[:])
	var out [4]uint64
	var borrow uint64
	for j := range 4 {
		out[j], borrow = bits.Sub64(p256NLimbs[j], sl[j], borrow)
	}
	return limbBytes(out)
}

func isZero32(s [32]byte) bool {
	var z [32]byte
	return subtle.ConstantTimeCompare(s[:], z[:]) == 1
}

// deriveW is w from a canonical pairing code: 40 HKDF bytes, big-endian, mod n. w = 0 is
// refused.
func deriveW(code string) ([32]byte, error) {
	wide, err := hkdf.Key(sha256.New, []byte(code), nil, "frontier-link/1/spake2/w", 40)
	if err != nil {
		return [32]byte{}, err
	}
	w := reduceModN(wide)
	if isZero32(w) {
		return w, errors.New("spake2: w = 0 is refused")
	}
	return w, nil
}

// scalarFromRandom is a secret scalar from 48 random bytes, mod n.
func scalarFromRandom(r []byte) ([32]byte, error) {
	if len(r) != 48 {
		return [32]byte{}, errors.New("spake2: scalar randomness must be 48 bytes")
	}
	return reduceModN(r), nil
}

type spake2Keys struct {
	K        []byte // the shared point, uncompressed SEC1
	TT       []byte
	Hash     []byte // SHA-256(TT)
	Ke, Ka   []byte
	KcA, KcB []byte
	CA, CB   []byte
	ours     []byte // the confirmation this side sends
	theirs   []byte // and the one it expects
}

type spake2 struct {
	roleA    bool
	w, xy    [32]byte
	idA, idB []byte
	aad      []byte
	share    []byte // pA or pB, uncompressed SEC1
}

// newSpake2 starts one side. scalar fixes x or y (vectors and tests); nil draws it from
// 48 random bytes, again until it is not zero.
func newSpake2(roleA bool, w [32]byte, scalar *[32]byte, idA, idB, aad []byte) (*spake2, error) {
	w = reduceModN(w[:])
	if isZero32(w) {
		return nil, errors.New("spake2: w = 0 is refused")
	}
	s := &spake2{roleA: roleA, w: w, idA: idA, idB: idB, aad: aad}
	if scalar != nil {
		s.xy = reduceModN(scalar[:])
		if isZero32(s.xy) {
			return nil, errors.New("spake2: secret scalar is 0")
		}
	} else {
		for {
			r := make([]byte, 48)
			if _, err := rand.Read(r); err != nil {
				return nil, err
			}
			if s.xy, _ = scalarFromRandom(r); !isZero32(s.xy) {
				break
			}
		}
	}
	blind := spake2N
	if roleA {
		blind = spake2M
	}
	wb, err := nistec.NewP256Point().ScalarMult(blind, w[:])
	if err != nil {
		return nil, err
	}
	xg, err := nistec.NewP256Point().ScalarBaseMult(s.xy[:])
	if err != nil {
		return nil, err
	}
	s.share = nistec.NewP256Point().Add(wb, xg).Bytes()
	if len(s.share) != 65 {
		return nil, errors.New("spake2: degenerate share")
	}
	return s, nil
}

// finish takes the peer's share. The share must be an uncompressed SEC1 point on the curve
// (P-256 has cofactor 1, so every such point is in the prime-order group, and an encoding
// cannot name the identity), and K must not be the identity (RFC 9382 section 7).
func (s *spake2) finish(peerShare []byte) (*spake2Keys, error) {
	if len(peerShare) != 65 || peerShare[0] != 4 {
		return nil, errors.New("spake2: peer share is not a valid uncompressed P-256 point")
	}
	peer, err := nistec.NewP256Point().SetBytes(peerShare)
	if err != nil {
		return nil, errors.New("spake2: peer share is not a valid uncompressed P-256 point")
	}
	// K = h*x*(pB - w*N) for A, h*y*(pA - w*M) for B; h = 1 on P-256. -w*N is (n - w)*N.
	unblind := spake2M
	if s.roleA {
		unblind = spake2N
	}
	negW := negModN(s.w)
	wu, err := nistec.NewP256Point().ScalarMult(unblind, negW[:])
	if err != nil {
		return nil, err
	}
	t := nistec.NewP256Point().Add(peer, wu)
	if len(t.Bytes()) != 65 {
		return nil, errors.New("spake2: degenerate shared point")
	}
	kp, err := nistec.NewP256Point().ScalarMult(t, s.xy[:])
	if err != nil {
		return nil, err
	}
	K := kp.Bytes()
	if len(K) != 65 {
		return nil, errors.New("spake2: degenerate shared point")
	}
	pA, pB := s.share, peerShare
	if !s.roleA {
		pA, pB = peerShare, s.share
	}
	var tt []byte
	for _, part := range [][]byte{s.idA, s.idB, pA, pB, K, s.w[:]} {
		tt = binary.LittleEndian.AppendUint64(tt, uint64(len(part)))
		tt = append(tt, part...)
	}
	sum := sha256.Sum256(tt)
	k := &spake2Keys{K: K, TT: tt, Hash: sum[:], Ke: sum[:16:16], Ka: sum[16:32:32]}
	kc, err := hkdf.Key(sha256.New, k.Ka, nil, "ConfirmationKeys"+string(s.aad), 32)
	if err != nil {
		return nil, err
	}
	k.KcA, k.KcB = kc[:16:16], kc[16:]
	k.CA, k.CB = hmacSHA256(k.KcA, tt), hmacSHA256(k.KcB, tt)
	if s.roleA {
		k.ours, k.theirs = k.CA, k.CB
	} else {
		k.ours, k.theirs = k.CB, k.CA
	}
	return k, nil
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// verifyConfirmation checks the peer's confirmation MAC in constant time.
func (k *spake2Keys) verifyConfirmation(received []byte) bool {
	return hmac.Equal(received, k.theirs)
}
