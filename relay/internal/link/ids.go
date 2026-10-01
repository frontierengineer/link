// Package link holds the parts of the Link protocol (spec/protocol.md) that the relay verifies:
// key and id derivation, canonical JSON, rosters and the registration signature.
package link

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"strings"
)

// IDLen is the length of a raw node id, the bytes before b32.
const IDLen = 16

// ID is a raw node id.
type ID [IDLen]byte

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// B64u is base64url without padding, strict about trailing bits.
var B64u = base64.RawURLEncoding.Strict()

// String is the 26-character b32 form of the id.
func (id ID) String() string { return strings.ToLower(b32.EncodeToString(id[:])) }

// IDFromKey derives a node id: the first 16 bytes of SHA-256 of the Ed25519 public key.
func IDFromKey(pub ed25519.PublicKey) ID {
	h := sha256.Sum256(pub)
	var id ID
	copy(id[:], h[:IDLen])
	return id
}

// ParseID decodes the canonical 26-character lowercase b32 form.
func ParseID(s string) (ID, bool) {
	var id ID
	if len(s) != 26 || strings.ToLower(s) != s {
		return id, false
	}
	b, err := b32.DecodeString(strings.ToUpper(s))
	if err != nil || len(b) != IDLen {
		return id, false
	}
	copy(id[:], b)
	if id.String() != s {
		return id, false // non-zero trailing bits
	}
	return id, true
}

// DecodeKey decodes a b64u value that must be exactly n raw bytes.
func DecodeKey(s string, n int) ([]byte, bool) {
	b, err := B64u.DecodeString(s)
	if err != nil || len(b) != n {
		return nil, false
	}
	return b, true
}

// Keys is a node's key material derived from its seed (section 2).
type Keys struct {
	Ed25519Seed   []byte
	Ed25519       ed25519.PrivateKey
	Ed25519Public ed25519.PublicKey
	X25519Private []byte // clamped
	X25519Public  []byte
	ID            ID
}

// DeriveKeys derives the Ed25519 and X25519 keys and the node id from a 32-byte seed.
func DeriveKeys(seed []byte) (*Keys, error) {
	edSeed, err := hkdf.Key(sha256.New, seed, nil, "frontier-link/1/ed25519", 32)
	if err != nil {
		return nil, err
	}
	xPriv, err := hkdf.Key(sha256.New, seed, nil, "frontier-link/1/x25519", 32)
	if err != nil {
		return nil, err
	}
	xPriv[0] &= 248
	xPriv[31] &= 127
	xPriv[31] |= 64
	xk, err := ecdh.X25519().NewPrivateKey(xPriv)
	if err != nil {
		return nil, err
	}
	priv := ed25519.NewKeyFromSeed(edSeed)
	pub := priv.Public().(ed25519.PublicKey)
	return &Keys{
		Ed25519Seed:   edSeed,
		Ed25519:       priv,
		Ed25519Public: pub,
		X25519Private: xPriv,
		X25519Public:  xk.PublicKey().Bytes(),
		ID:            IDFromKey(pub),
	}, nil
}

func appendLenStr(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

// RegisterMessage is the byte string a node signs to register (section 4.1):
// lenStr("frontier-link/1/register") || lenStr(network) || lenStr(node) || challenge ||
// u64be(ts) || lenStr(origin).
func RegisterMessage(network, node string, challenge []byte, ts uint64, origin string) []byte {
	b := make([]byte, 0, 4+24+4+len(network)+4+len(node)+len(challenge)+8+4+len(origin))
	b = appendLenStr(b, "frontier-link/1/register")
	b = appendLenStr(b, network)
	b = appendLenStr(b, node)
	b = append(b, challenge...)
	b = binary.BigEndian.AppendUint64(b, ts)
	return appendLenStr(b, origin)
}

// NonCanonical returns sig with L added to its S half: the same signature in a non-canonical
// encoding, which strict verification must refuse. For tests and vectors.
func NonCanonical(sig []byte) []byte {
	// L = 2^252 + 27742317777372353535851937790883648493, little-endian.
	l := [32]byte{0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}
	out := bytes.Clone(sig)
	carry := 0
	for i := range 32 {
		v := int(out[32+i]) + int(l[i]) + carry
		out[32+i], carry = byte(v), v>>8
	}
	return out
}
