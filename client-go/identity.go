package link

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
)

// Keys and ids (section 2). One 32-byte seed yields the node's Ed25519 identity and its
// X25519 session key; the node id is a hash of the Ed25519 public key.

// Identity is a node's key material. Persist Seed; everything else derives from it.
type Identity struct {
	seed   [32]byte
	id     string
	edPriv ed25519.PrivateKey
	edPub  ed25519.PublicKey
	xPriv  [32]byte // clamped
	xPub   [32]byte
}

// IdentityFromSeed derives an identity from a 32-byte seed.
func IdentityFromSeed(seed []byte) (*Identity, error) {
	if len(seed) != 32 {
		return nil, invalidError("seed must be 32 bytes")
	}
	edSeed, err := hkdf.Key(sha256.New, seed, nil, "frontier-link/1/ed25519", 32)
	if err != nil {
		return nil, err
	}
	xPriv, err := hkdf.Key(sha256.New, seed, nil, "frontier-link/1/x25519", 32)
	if err != nil {
		return nil, err
	}
	clampX25519(xPriv)
	xk, err := ecdh.X25519().NewPrivateKey(xPriv)
	if err != nil {
		return nil, err
	}
	id := &Identity{edPriv: ed25519.NewKeyFromSeed(edSeed)}
	copy(id.seed[:], seed)
	id.edPub = id.edPriv.Public().(ed25519.PublicKey)
	copy(id.xPriv[:], xPriv)
	copy(id.xPub[:], xk.PublicKey().Bytes())
	id.id = NodeIDFromEd25519(id.edPub)
	return id, nil
}

// NewIdentity makes an identity from a fresh random seed.
func NewIdentity() (*Identity, error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return IdentityFromSeed(seed)
}

func clampX25519(k []byte) {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
}

// Seed returns a copy of the 32 secret bytes. It never leaves the node.
func (i *Identity) Seed() []byte { return bytes.Clone(i.seed[:]) }

// ID is the node id: 26 lowercase base32 characters.
func (i *Identity) ID() string { return i.id }

// Ed25519Public returns a copy of the Ed25519 public key.
func (i *Identity) Ed25519Public() ed25519.PublicKey { return bytes.Clone(i.edPub) }

// X25519Public returns a copy of the X25519 public key.
func (i *Identity) X25519Public() []byte { return bytes.Clone(i.xPub[:]) }

// Sign is an Ed25519 signature over message.
func (i *Identity) Sign(message []byte) []byte { return ed25519.Sign(i.edPriv, message) }

// NodeIDFromEd25519 is b32(SHA-256(ed25519Public)[0..16]).
func NodeIDFromEd25519(pub []byte) string {
	sum := sha256.Sum256(pub)
	return b32(sum[:16])
}

// IsNodeID reports whether s is a canonical node id: 26 lowercase base32 characters whose
// trailing bits are zero.
func IsNodeID(s string) bool {
	_, err := nodeIDToBytes(s)
	return err == nil
}

// nodeIDToBytes is the raw 16 bytes a frame's peer field carries.
func nodeIDToBytes(s string) ([16]byte, error) {
	var out [16]byte
	if len(s) != 26 {
		return out, fmt.Errorf("not a node id: %q", s)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return out, fmt.Errorf("not a node id: %q", s)
		}
	}
	b, err := b32Enc.DecodeString(strings.ToUpper(s))
	if err != nil || len(b) != 16 {
		return out, fmt.Errorf("not a node id: %q", s)
	}
	copy(out[:], b)
	if b32(out[:]) != s {
		return out, errors.New("non-canonical node id") // non-zero trailing bits
	}
	return out, nil
}

func nodeIDFromBytes(b []byte) string { return b32(b) }
