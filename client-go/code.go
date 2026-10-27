package link

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Pairing codes, code ids and pairing links (section 5.1).

const (
	crockford    = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	codeLength   = 8
	codeIDLength = 8
)

// GenerateCode returns a fresh code in its canonical form: 8 Crockford characters, no hyphen.
func GenerateCode() string {
	b := make([]byte, codeLength)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	// 256 is a multiple of 32, so b & 31 is uniform.
	for i := range b {
		b[i] = crockford[b[i]&31]
	}
	return string(b)
}

// NormalizeCode is the canonical code for user input: hyphens and whitespace dropped,
// upper-cased, I and L read as 1, O as 0. It fails when the result is not 8 Crockford
// characters.
func NormalizeCode(input string) (string, error) {
	var b strings.Builder
	for _, r := range input {
		if r == '-' || unicode.IsSpace(r) {
			continue
		}
		switch r = unicode.ToUpper(r); r {
		case 'I', 'L':
			r = '1'
		case 'O':
			r = '0'
		}
		b.WriteRune(r)
	}
	code := b.String()
	if len(code) != codeLength || strings.Trim(code, crockford) != "" {
		return "", errors.New("a pairing code is 8 characters from 0-9 and A-Z without I, L, O, U")
	}
	return code, nil
}

// FormatCode is the display form, XXXX-XXXX.
func FormatCode(code string) (string, error) {
	c, err := NormalizeCode(code)
	if err != nil {
		return "", err
	}
	return c[:4] + "-" + c[4:], nil
}

// PairingLink is what a pairing code gives a newcomer (section 5.1): the pairing parameters,
// whatever wraps them (a frontier://pair link, an https URL's fragment).
type PairingLink struct {
	Network string
	Code    string // canonical, no hyphen
	CodeID  string // b64u of the 8-byte code id
	Relay   string
}

// pairingParams writes the pairing parameters, v=1&n=<network>&c=<code>&i=<code id>&r=<relay>,
// each value percent-encoded as ECMAScript's encodeURIComponent does.
func pairingParams(p PairingLink) (string, error) {
	if !IsNodeID(p.Network) {
		return "", errors.New("network is not a node id")
	}
	if _, err := fromB64uLen(p.CodeID, codeIDLength, "code id"); err != nil {
		return "", err
	}
	code, err := NormalizeCode(p.Code)
	if err != nil {
		return "", err
	}
	return "v=1&n=" + encodeURIComponent(p.Network) + "&c=" + encodeURIComponent(code) + "&i=" + encodeURIComponent(p.CodeID) + "&r=" + encodeURIComponent(p.Relay), nil
}

// readPairingParams reads pairing parameters; what names them in errors, and badVersion, when
// not empty, is the error for a missing or unknown version.
func readPairingParams(s, what, badVersion string) (PairingLink, error) {
	params := map[string]string{}
	for _, part := range strings.Split(s, "&") {
		if part == "" {
			continue
		}
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			return PairingLink{}, fmt.Errorf("%s parameter without a value: %s", what, part)
		}
		if _, dup := params[key]; dup {
			return PairingLink{}, fmt.Errorf("%s repeats %s", what, key)
		}
		v, err := url.PathUnescape(value) // decodeURIComponent: %XX only, '+' stays '+'
		if err != nil || !utf8.ValidString(v) {
			return PairingLink{}, fmt.Errorf("%s: malformed percent-encoding in %s", what, key)
		}
		params[key] = v
	}
	switch v := params["v"]; {
	case v == "" && badVersion != "":
		return PairingLink{}, errors.New(badVersion)
	case v == "":
		return PairingLink{}, fmt.Errorf("%s: missing v", what)
	case v != "1" && badVersion != "":
		return PairingLink{}, errors.New(badVersion)
	case v != "1":
		return PairingLink{}, fmt.Errorf("%s: unknown version %s", what, v)
	}
	p := PairingLink{Network: params["n"], CodeID: params["i"], Relay: params["r"]}
	if p.Network == "" {
		return PairingLink{}, fmt.Errorf("%s: missing n (the network id)", what)
	}
	if !IsNodeID(p.Network) {
		return PairingLink{}, fmt.Errorf("%s: bad network id", what)
	}
	if params["c"] == "" {
		return PairingLink{}, fmt.Errorf("%s: missing c (the code)", what)
	}
	if p.CodeID == "" {
		return PairingLink{}, fmt.Errorf("%s: missing i (the code id)", what)
	}
	if _, err := fromB64uLen(p.CodeID, codeIDLength, what+" code id"); err != nil {
		return PairingLink{}, err
	}
	if p.Relay == "" {
		return PairingLink{}, fmt.Errorf("%s: missing r (the relay)", what)
	}
	u, err := url.Parse(p.Relay)
	if err != nil {
		return PairingLink{}, fmt.Errorf("%s: %w", what, err)
	}
	if s := strings.ToLower(u.Scheme); s != "ws" && s != "wss" {
		return PairingLink{}, fmt.Errorf("%s: relay must be a ws:// or wss:// URL", what)
	}
	code, err := NormalizeCode(params["c"])
	if err != nil {
		return PairingLink{}, err
	}
	p.Code = code
	return p, nil
}

// BuildPairingParams writes the pairing parameters alone (section 5.1):
// v=1&n=<network>&c=<code>&i=<code id>&r=<relay>, each value percent-encoded. Link defines these,
// not a scheme: an application wraps them as it likes, in a link's query or an https URL's
// fragment. It fails invalid for a network that is not a node id, a code id not of 8 bytes, a
// code that is not one, or a relay that is not a ws:// or wss:// URL (IsRelayURL).
func BuildPairingParams(p PairingLink) (string, error) {
	if !IsRelayURL(p.Relay) {
		return "", invalidError("pairing parameters: relay must be a ws:// or wss:// URL")
	}
	s, err := pairingParams(p)
	if err != nil {
		return "", invalidError("pairing parameters: " + err.Error())
	}
	return s, nil
}

// ParsePairingParams reads pairing parameters (section 5.1) as BuildPairingParams writes them,
// in any order; parameters it does not know are ignored, and the code may be in its displayed
// form. It fails invalid on a missing parameter, an unknown version, a repeated parameter, or a
// value that is not what its parameter holds.
func ParsePairingParams(params string) (PairingLink, error) {
	p, err := readPairingParams(params, "pairing parameters", "")
	if err != nil {
		return PairingLink{}, invalidError(err.Error())
	}
	if !IsRelayURL(p.Relay) {
		return PairingLink{}, invalidError("pairing parameters: relay must be a ws:// or wss:// URL")
	}
	return p, nil
}

// BuildPairingLink writes frontier://pair? followed by the pairing parameters: one wrapping of
// them (section 5.1).
func BuildPairingLink(p PairingLink) (string, error) {
	s, err := pairingParams(p)
	if err != nil {
		return "", err
	}
	return "frontier://pair?" + s, nil
}

// ParsePairingLink reads a frontier://pair? link: the pairing parameters in that wrapping. The
// code may be in its displayed form.
func ParsePairingLink(link string) (PairingLink, error) {
	const prefix = "frontier://pair?"
	if !strings.HasPrefix(link, prefix) {
		return PairingLink{}, errors.New("not a frontier://pair link")
	}
	return readPairingParams(link[len(prefix):], "pairing link", "unsupported pairing link version")
}

// encodeURIComponent is ECMAScript's: every byte of the UTF-8 encoding is percent-encoded
// except A-Z a-z 0-9 - _ . ! ~ * ' ( ).
func encodeURIComponent(s string) string {
	const upper = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte("-_.!~*'()", c) >= 0 {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(upper[c>>4])
			b.WriteByte(upper[c&15])
		}
	}
	return b.String()
}
