package link

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// The signed statements besides the roster: registration (section 4.1) and resignation
// (section 7.3), and the Ed25519 verification every signature goes through.

// verifyEd25519 is section 1's verification, strict and the same in every implementation:
// A and R canonical encodings (y < p, and not x = 0 with the sign bit set), neither one of
// the eight points of small order, S < L, and the cofactorless equation [S]B = R + [k]A.
// Go's crypto/ed25519 gives the last two, and refuses a non-canonical R (it compares R's
// encoding with that of the point it computes), but it accepts a non-canonical or
// small-order A, and a small-order R whenever the equation holds; those are checked here.
func verifyEd25519(pub, message, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	r := sig[:32]
	if !canonicalEd25519(pub) || smallOrderEd25519(pub) || !canonicalEd25519(r) || smallOrderEd25519(r) {
		return false
	}
	return ed25519.Verify(pub, message, sig)
}

// canonicalEd25519 reports whether a 32-byte point encoding is canonical (RFC 8032 section
// 5.1.3): y < p, and not x = 0 with the sign bit set. It does not check that the point is on
// the curve; ed25519.Verify does.
func canonicalEd25519(b []byte) bool {
	// y >= p = 2^255 - 19: the low 255 bits are 0x7fff...ffed or more, which means bytes
	// 1..30 are 0xff, byte 31 is 0x7f (sign bit aside) and byte 0 is 0xed or more.
	high := true
	for _, x := range b[1:31] {
		high = high && x == 0xff
	}
	if high && b[31]&0x7f == 0x7f && b[0] >= 0xed {
		return false
	}
	// x = 0 occurs for y = 1 and y = p - 1; with the sign bit set those encodings are not
	// canonical.
	if b[31]&0x80 != 0 {
		rest := b[31] & 0x7f
		zeros := true
		for _, x := range b[1:31] {
			zeros = zeros && x == 0
		}
		if zeros && rest == 0 && b[0] == 1 {
			return false // y = 1
		}
		if high && rest == 0x7f && b[0] == 0xec {
			return false // y = p - 1
		}
	}
	return true
}

// originOf is the lowercased host[:port] of a dialled URL, with the port omitted when it is
// 80 or 443 whatever the scheme (section 4.1), as the relay compares it.
func originOf(raw string) (string, error) {
	u, err := normalizeRelayURL(raw)
	if err != nil {
		return "", err
	}
	host := u.Host
	if p := u.Port(); p == "80" || p == "443" {
		host = strings.TrimSuffix(host, ":"+p)
	}
	return host, nil
}

// normalizeRelayURL parses a relay URL as a browser would before dialling it: the scheme and
// host lowercased, the port written in decimal without leading zeros, and the scheme's own
// default port dropped. The Host header the relay sees is then the host the signature
// names. Hosts must be ASCII (an internationalised name is given in its xn-- form).
func normalizeRelayURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("relay URL: %w", err)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	switch u.Scheme {
	case "ws", "wss", "http", "https":
	default:
		return nil, fmt.Errorf("unsupported relay URL scheme: %s:", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return nil, errors.New("relay URL has no host")
	}
	for i := 0; i < len(host); i++ {
		if host[i] >= 0x80 {
			return nil, errors.New("relay URL host must be ASCII (use its xn-- form)")
		}
	}
	host = strings.ToLower(host)
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if p := u.Port(); p != "" {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("relay URL port: %w", err)
		}
		def := map[string]uint64{"ws": 80, "http": 80, "wss": 443, "https": 443}[u.Scheme]
		if n != def {
			host += ":" + strconv.FormatUint(n, 10)
		}
	}
	u.Host = host
	return u, nil
}

// registerSigningBytes is lenStr("frontier-link/1/register") || lenStr(network) ||
// lenStr(node) || challenge || u64be(ts) || lenStr(origin).
func registerSigningBytes(network, node string, challenge []byte, ts int64, origin string) []byte {
	b := appendLenStr(nil, "frontier-link/1/register")
	b = appendLenStr(b, network)
	b = appendLenStr(b, node)
	b = append(b, challenge...)
	b = binary.BigEndian.AppendUint64(b, uint64(ts))
	return appendLenStr(b, origin)
}

// resignSigningBytes is lenStr("frontier-link/1/resign") || lenStr(network) || lenStr(node)
// || u64be(ts).
func resignSigningBytes(network, node string, ts int64) []byte {
	b := appendLenStr(nil, "frontier-link/1/resign")
	b = appendLenStr(b, network)
	b = appendLenStr(b, node)
	return binary.BigEndian.AppendUint64(b, uint64(ts))
}

// resignation is the body of a resign session message.
type resignation struct {
	Node string `json:"node"`
	TS   int64  `json:"ts"`
	Sig  string `json:"sig"`
}

func signResignation(id *Identity, network string, ts int64) resignation {
	return resignation{Node: id.ID(), TS: ts, Sig: b64u(id.Sign(resignSigningBytes(network, id.ID(), ts)))}
}

// parseResignation reads a resign message's JSON: an object whose node is a string, ts a
// non-negative safe integer and sig a string.
func parseResignation(data []byte) (resignation, bool) {
	tree, err := parseJSON(data)
	if err != nil {
		return resignation{}, false
	}
	obj, ok := tree.(map[string]any)
	if !ok {
		return resignation{}, false
	}
	var r resignation
	if r.Node, ok = obj["node"].(string); !ok {
		return resignation{}, false
	}
	if r.TS, ok = safeInteger(obj["ts"]); !ok || r.TS < 0 {
		return resignation{}, false
	}
	if r.Sig, ok = obj["sig"].(string); !ok {
		return resignation{}, false
	}
	return r, true
}

func verifyResignation(r resignation, network string, ed25519Pub []byte) bool {
	sig, err := fromB64uLen(r.Sig, 64, "sig")
	if err != nil {
		return false
	}
	return verifyEd25519(ed25519Pub, resignSigningBytes(network, r.Node, r.TS), sig)
}
