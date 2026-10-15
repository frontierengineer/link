package link

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"

	"golang.org/x/crypto/chacha20poly1305"
)

// The pairing exchange of section 5.3 as two transport-agnostic state machines. The relay
// plumbing around them lives in newcomer.go and primary.go.

type pairTransportKeys struct {
	toPrimary  []byte // newcomer -> primary
	toNewcomer []byte // primary -> newcomer
}

func pairKeys(k *spake2Keys) (pairTransportKeys, error) {
	okm, err := hkdf.Key(sha256.New, k.Ke, k.Hash, "frontier-link/1/pair-transport", 64)
	if err != nil {
		return pairTransportKeys{}, err
	}
	return pairTransportKeys{toPrimary: okm[:32:32], toNewcomer: okm[32:]}, nil
}

// sealer is ChaCha20-Poly1305 with nonce = 4 zero bytes || u64le(counter), a counter per
// direction from 0, and empty associated data.
type sealer struct {
	send, recv   cipher.AEAD
	sendN, recvN uint64
}

func newSealer(sendKey, recvKey []byte) (*sealer, error) {
	s, err := chacha20poly1305.New(sendKey)
	if err != nil {
		return nil, err
	}
	r, err := chacha20poly1305.New(recvKey)
	if err != nil {
		return nil, err
	}
	return &sealer{send: s, recv: r}, nil
}

func counterNonce(n uint64) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.LittleEndian.PutUint64(nonce[4:], n)
	return nonce
}

func (s *sealer) seal(plaintext []byte) ([]byte, error) {
	if s.sendN == math.MaxUint64 {
		return nil, errors.New("pairing: nonce exhausted")
	}
	ct := s.send.Seal(nil, counterNonce(s.sendN), plaintext, nil)
	s.sendN++
	return ct, nil
}

// open fails when the tag does not verify; the counter advances only on success.
func (s *sealer) open(ciphertext []byte) ([]byte, error) {
	if s.recvN == math.MaxUint64 {
		return nil, errors.New("pairing: nonce exhausted")
	}
	pt, err := s.recv.Open(nil, counterNonce(s.recvN), ciphertext, nil)
	if err != nil {
		return nil, errors.New("pairing: a sealed message did not open")
	}
	s.recvN++
	return pt, nil
}

type newcomerKeys struct {
	ed25519 []byte
	x25519  []byte
}

type p5Body struct {
	Ed25519 string `json:"ed25519"`
	X25519  string `json:"x25519"`
}

// newcomerExchange is A, the newcomer: P1, P3, P5 out; P2, P4, P6 in.
type newcomerExchange struct {
	spake     *spake2
	keys      *spake2Keys
	sealer    *sealer
	confirmed bool
}

// newNewcomerExchange takes a canonical code; random48 fixes x for vectors.
func newNewcomerExchange(code string, codeID []byte, random48 []byte) (*newcomerExchange, error) {
	return newExchange(true, code, codeID, random48, func(s *spake2) *newcomerExchange { return &newcomerExchange{spake: s} })
}

func newExchange[T any](roleA bool, code string, codeID, random48 []byte, wrap func(*spake2) T) (T, error) {
	var zero T
	w, err := deriveW(code)
	if err != nil {
		return zero, err
	}
	var scalar *[32]byte
	if random48 != nil {
		x, err := scalarFromRandom(random48)
		if err != nil {
			return zero, err
		}
		scalar = &x
	}
	s, err := newSpake2(roleA, w, scalar, []byte(spake2IDA), []byte(spake2IDB), codeID)
	if err != nil {
		return zero, err
	}
	return wrap(s), nil
}

// p1 is pA.
func (e *newcomerExchange) p1() []byte { return e.spake.share }

// onP2 takes pB and returns P3, cA.
func (e *newcomerExchange) onP2(pB []byte) ([]byte, error) {
	if e.keys != nil {
		return nil, errors.New("pairing: P2 already received")
	}
	k, err := e.spake.finish(pB)
	if err != nil {
		return nil, err
	}
	e.keys = k
	return k.ours, nil
}

// onP4 checks cB and returns P5, sealed with this node's public keys.
func (e *newcomerExchange) onP4(cB []byte, mine newcomerKeys) ([]byte, error) {
	if e.keys == nil {
		return nil, errors.New("pairing: P4 before P2")
	}
	if !e.keys.verifyConfirmation(cB) {
		return nil, errors.New("pairing: the primary did not prove the code")
	}
	e.confirmed = true
	t, err := pairKeys(e.keys)
	if err != nil {
		return nil, err
	}
	if e.sealer, err = newSealer(t.toPrimary, t.toNewcomer); err != nil {
		return nil, err
	}
	body, err := json.Marshal(p5Body{Ed25519: b64u(mine.ed25519), X25519: b64u(mine.x25519)})
	if err != nil {
		return nil, err
	}
	return e.sealer.seal(body)
}

// onP6 opens P6 and returns the roster it carries, not yet validated.
func (e *newcomerExchange) onP6(sealed []byte) (*Roster, error) {
	if e.sealer == nil || !e.confirmed {
		return nil, errors.New("pairing: P6 before P4")
	}
	pt, err := e.sealer.open(sealed)
	if err != nil {
		return nil, err
	}
	tree, err := parseJSON(pt)
	if err != nil {
		return nil, err
	}
	obj, ok := tree.(map[string]any)
	if !ok || obj["roster"] == nil {
		return nil, errors.New("pairing: P6 carries no roster")
	}
	r, err := rosterFromTree(obj["roster"])
	if err != nil {
		return nil, errors.New("pairing: the primary sent an invalid roster: " + err.Error())
	}
	return r, nil
}

// primaryExchange is B, the primary: P2, P4, P6 out; P1, P3, P5 in.
type primaryExchange struct {
	spake  *spake2
	keys   *spake2Keys
	sealer *sealer
}

func newPrimaryExchange(code string, codeID []byte, random48 []byte) (*primaryExchange, error) {
	return newExchange(false, code, codeID, random48, func(s *spake2) *primaryExchange { return &primaryExchange{spake: s} })
}

// onP1 takes pA and returns P2, pB.
func (e *primaryExchange) onP1(pA []byte) ([]byte, error) {
	if e.keys != nil {
		return nil, errors.New("pairing: P1 already received")
	}
	k, err := e.spake.finish(pA)
	if err != nil {
		return nil, err
	}
	e.keys = k
	return e.spake.share, nil
}

// onP3 reports whether cA verifies; then p4 may be sent.
func (e *primaryExchange) onP3(cA []byte) (bool, error) {
	if e.keys == nil {
		return false, errors.New("pairing: P3 before P1")
	}
	if !e.keys.verifyConfirmation(cA) {
		return false, nil
	}
	t, err := pairKeys(e.keys)
	if err != nil {
		return false, err
	}
	if e.sealer, err = newSealer(t.toNewcomer, t.toPrimary); err != nil {
		return false, err
	}
	return true, nil
}

func (e *primaryExchange) p4() ([]byte, error) {
	if e.keys == nil || e.sealer == nil {
		return nil, errors.New("pairing: P4 before cA verified")
	}
	return e.keys.ours, nil
}

// onP5 opens the newcomer's keys.
func (e *primaryExchange) onP5(sealed []byte) (newcomerKeys, error) {
	if e.sealer == nil {
		return newcomerKeys{}, errors.New("pairing: P5 before cA verified")
	}
	pt, err := e.sealer.open(sealed)
	if err != nil {
		return newcomerKeys{}, err
	}
	tree, err := parseJSON(pt)
	if err != nil {
		return newcomerKeys{}, err
	}
	obj, ok := tree.(map[string]any)
	if !ok {
		return newcomerKeys{}, errors.New("pairing: P5 is not an object")
	}
	ed, _ := obj["ed25519"].(string)
	x, _ := obj["x25519"].(string)
	var k newcomerKeys
	if k.ed25519, err = fromB64uLen(ed, 32, "P5 ed25519"); err != nil {
		return newcomerKeys{}, err
	}
	if k.x25519, err = fromB64uLen(x, 32, "P5 x25519"); err != nil {
		return newcomerKeys{}, err
	}
	return k, nil
}

// p6 seals {"roster": roster}.
func (e *primaryExchange) p6(r *Roster) ([]byte, error) {
	if e.sealer == nil {
		return nil, errors.New("pairing: P6 before cA verified")
	}
	// Written by hand: json.Marshal would escape <, > and & in the roster's strings, which
	// JSON.stringify does not.
	rj, err := r.MarshalJSON()
	if err != nil {
		return nil, err
	}
	return e.sealer.seal(append(append([]byte(`{"roster":`), rj...), '}'))
}
