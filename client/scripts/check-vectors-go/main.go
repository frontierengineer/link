// Independent cross-check of spec/vectors/client.json with Go's standard
// library and flynn/noise: keys, ids, signatures, pairing transport, Noise IK.
// Run from this directory: go run . [path to client.json]
package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/flynn/noise"
	"golang.org/x/crypto/chacha20poly1305"
)

func h(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func b64(s string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

var fails = 0

func check(ok bool, what string) {
	if !ok {
		fails++
		fmt.Println("FAIL", what)
	} else {
		fmt.Println("ok  ", what)
	}
}

func lenStr(s string) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(len(s)))
	return append(b, s...)
}

type fixedRand struct{ b []byte }

func (f *fixedRand) Read(p []byte) (int, error) { n := copy(p, f.b); f.b = f.b[n:]; return n, nil }

func main() {
	path := "../../../spec/vectors/client.json"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var v map[string]any
	json.Unmarshal(raw, &v)
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding)

	for _, k := range v["keys"].([]any) {
		k := k.(map[string]any)
		seed := h(k["seed"].(string))
		edSeed, _ := hkdf.Key(sha256.New, seed, nil, "frontier-link/1/ed25519", 32)
		check(hex.EncodeToString(edSeed) == k["ed25519Seed"], "ed25519 seed")
		pub := ed25519.NewKeyFromSeed(edSeed).Public().(ed25519.PublicKey)
		check(hex.EncodeToString(pub) == k["ed25519Public"], "ed25519 public")
		x, _ := hkdf.Key(sha256.New, seed, nil, "frontier-link/1/x25519", 32)
		x[0] &= 248
		x[31] &= 127
		x[31] |= 64
		check(hex.EncodeToString(x) == k["x25519Private"], "x25519 private clamped")
		xp, _ := ecdh.X25519().NewPrivateKey(x)
		check(hex.EncodeToString(xp.PublicKey().Bytes()) == k["x25519Public"], "x25519 public")
		sum := sha256.Sum256(pub)
		check(strings.ToLower(b32.EncodeToString(sum[:16])) == k["nodeId"], "node id")
	}

	ro := v["roster"].(map[string]any)["signing"].(map[string]any)
	roster := ro["roster"].(map[string]any)
	signed := h(ro["signedBytes"].(string))
	check(bytes.Equal(signed, append([]byte("frontier-link/1/roster"), []byte(ro["jcs"].(string))...)), "roster signed bytes = label || jcs")
	pk := b64(roster["primary"].(map[string]any)["ed25519"].(string))
	check(ed25519.Verify(pk, signed, b64(ro["signature"].(string))), "roster signature")

	for _, r := range v["register"].([]any) {
		r := r.(map[string]any)
		ts := make([]byte, 8)
		binary.BigEndian.PutUint64(ts, uint64(r["ts"].(float64)))
		var m []byte
		m = append(m, lenStr("frontier-link/1/register")...)
		m = append(m, lenStr(r["network"].(string))...)
		m = append(m, lenStr(r["node"].(string))...)
		m = append(m, b64(r["challenge"].(string))...)
		m = append(m, ts...)
		m = append(m, lenStr(r["origin"].(string))...)
		check(hex.EncodeToString(m) == r["signedBytes"], "register bytes "+r["origin"].(string))
		edSeed, _ := hkdf.Key(sha256.New, h(r["seed"].(string)), nil, "frontier-link/1/ed25519", 32)
		key := ed25519.NewKeyFromSeed(edSeed)
		check(base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, m)) == r["sig"], "register sig")
	}

	rs := v["resign"].(map[string]any)
	{
		ts := make([]byte, 8)
		binary.BigEndian.PutUint64(ts, uint64(rs["ts"].(float64)))
		m := append(append(append(lenStr("frontier-link/1/resign"), lenStr(rs["network"].(string))...), lenStr(rs["node"].(string))...), ts...)
		check(hex.EncodeToString(m) == rs["signedBytes"], "resign bytes")
		edSeed, _ := hkdf.Key(sha256.New, h(rs["seed"].(string)), nil, "frontier-link/1/ed25519", 32)
		check(base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(edSeed), m)) == rs["sig"], "resign sig")
	}

	// SPAKE2 profile: derived values that do not need P-256 arithmetic.
	p := v["spake2"].(map[string]any)["profile"].(map[string]any)
	tt := h(p["TT"].(string))
	hash := sha256.Sum256(tt)
	check(hex.EncodeToString(hash[:]) == p["hashTT"], "spake2 hash(TT)")
	kc, _ := hkdf.Key(sha256.New, hash[16:], nil, "ConfirmationKeys"+string(h(p["codeId"].(string))), 32)
	check(hex.EncodeToString(kc) == p["KcA"].(string)+p["KcB"].(string), "spake2 KcA||KcB")
	okm, _ := hkdf.Key(sha256.New, hash[:16], hash[:], "frontier-link/1/pair-transport", 64)
	check(hex.EncodeToString(okm) == p["okm"], "pair transport okm")
	aead, _ := chacha20poly1305.New(okm[:32])
	pt, err := aead.Open(nil, make([]byte, 12), h(p["p5"].(string)), nil)
	check(err == nil && string(pt) == p["p5Plaintext"], "P5 opens with okm[0..32], nonce 0")
	aead2, _ := chacha20poly1305.New(okm[32:])
	pt2, err := aead2.Open(nil, make([]byte, 12), h(p["p6"].(string)), nil)
	check(err == nil && string(pt2) == p["p6Plaintext"], "P6 opens with okm[32..64], nonce 0")

	// Noise IK with flynn/noise.
	n := v["noise"].(map[string]any)
	ini := n["initiator"].(map[string]any)
	res := n["responder"].(map[string]any)
	kp := func(priv []byte) noise.DHKey {
		k, _ := noise.DH25519.GenerateKeypair(&fixedRand{append([]byte{}, priv...)})
		return k
	}
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	iS := kp(h(ini["staticPrivate"].(string)))
	rS := kp(h(res["staticPrivate"].(string)))
	hsI, _ := noise.NewHandshakeState(noise.Config{CipherSuite: cs, Pattern: noise.HandshakeIK, Initiator: true,
		Prologue: h(n["prologue"].(string)), StaticKeypair: iS, PeerStatic: rS.Public,
		Random: &fixedRand{h(ini["ephemeralPrivate"].(string))}})
	hsR, _ := noise.NewHandshakeState(noise.Config{CipherSuite: cs, Pattern: noise.HandshakeIK, Initiator: false,
		Prologue: h(n["prologue"].(string)), StaticKeypair: rS,
		Random: &fixedRand{h(res["ephemeralPrivate"].(string))}})
	check(bytes.Equal(h(n["prologue"].(string)), []byte("frontier-link/1/session"+n["network"].(string))), "prologue")
	m1 := n["message1"].(map[string]any)
	out1, _, _, _ := hsI.WriteMessage(nil, h(m1["payload"].(string)))
	check(hex.EncodeToString(out1) == m1["noise"], "IK message 1")
	if _, _, _, err := hsR.ReadMessage(nil, out1); err != nil {
		check(false, "IK responder reads message 1")
	}
	m2 := n["message2"].(map[string]any)
	out2, rc1, rc2, _ := hsR.WriteMessage(nil, h(m2["payload"].(string)))
	check(hex.EncodeToString(out2) == m2["noise"], "IK message 2")
	_, ic1, ic2, err := hsI.ReadMessage(nil, out2)
	check(err == nil, "IK initiator reads message 2")
	check(hex.EncodeToString(hsI.ChannelBinding()) == n["handshakeHash"], "IK handshake hash")
	tr := n["transport"].([]any)
	t0 := tr[0].(map[string]any)
	c0, _ := ic1.Encrypt(nil, nil, h(t0["plaintext"].(string)))
	check(hex.EncodeToString(c0) == t0["ciphertext"], "transport 0 (initiator->responder)")
	d0, err := rc1.Decrypt(nil, nil, c0)
	check(err == nil && hex.EncodeToString(d0) == t0["plaintext"], "transport 0 decrypts")
	t1 := tr[1].(map[string]any)
	c1, _ := rc2.Encrypt(nil, nil, h(t1["plaintext"].(string)))
	check(hex.EncodeToString(c1) == t1["ciphertext"], "transport 1 (responder->initiator)")
	_, err = ic2.Decrypt(nil, nil, c1)
	check(err == nil, "transport 1 decrypts")

	// Frames: version 1, type, 16-byte peer, body.
	for _, f := range v["frames"].([]any) {
		f := f.(map[string]any)
		want := append([]byte{1, byte(f["type"].(float64))}, h(f["peer"].(string))...)
		want = append(want, h(f["body"].(string))...)
		check(hex.EncodeToString(want) == f["frame"], "frame "+f["name"].(string))
	}

	if fails > 0 {
		fmt.Println(fails, "failures")
		os.Exit(1)
	}
	fmt.Println("all checks passed")
}
