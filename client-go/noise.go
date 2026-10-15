package link

import (
	"io"

	"github.com/flynn/noise"
)

// Sessions use Noise_IK_25519_ChaChaPoly_SHA256, revision 34 (section 7.1), from
// github.com/flynn/noise. Its X25519 is golang.org/x/crypto/curve25519, which fails a
// handshake whose DH output is all zero (a low-order peer key).

var noiseSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

func sessionPrologue(network string) []byte {
	return []byte("frontier-link/1/session" + network)
}

func (i *Identity) noiseKey() noise.DHKey {
	return noise.DHKey{Private: append([]byte(nil), i.xPriv[:]...), Public: append([]byte(nil), i.xPub[:]...)}
}

// newHandshake starts an IK handshake. rs is the responder's static key (initiator only).
// rng supplies the ephemeral key; nil is crypto/rand, a fixed reader is for vectors.
func newHandshake(id *Identity, initiator bool, network string, rs []byte, rng io.Reader) (*noise.HandshakeState, error) {
	return noise.NewHandshakeState(noise.Config{
		CipherSuite:   noiseSuite,
		Pattern:       noise.HandshakeIK,
		Initiator:     initiator,
		Prologue:      sessionPrologue(network),
		StaticKeypair: id.noiseKey(),
		PeerStatic:    rs,
		Random:        rng,
	})
}
