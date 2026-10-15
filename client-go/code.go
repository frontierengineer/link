package link

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"
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

// PairingLink is what a frontier://pair link carries.
type PairingLink struct {
	Network string
	Code    string // canonical, no hyphen
	CodeID  string // b64u of the 8-byte code id
	Relay   string
}

// BuildPairingLink writes frontier://pair?v=1&n=<network>&c=<code>&i=<code id>&r=<relay>.
func BuildPairingLink(p PairingLink) (string, error) {
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
	return "frontier://pair?v=1&n=" + p.Network + "&c=" + code + "&i=" + p.CodeID + "&r=" + encodeURIComponent(p.Relay), nil
}

// ParsePairingLink reads a pairing link. The code may be in its displayed form.
func ParsePairingLink(link string) (PairingLink, error) {
	const prefix = "frontier://pair?"
	if !strings.HasPrefix(link, prefix) {
		return PairingLink{}, errors.New("not a frontier://pair link")
	}
	params := map[string]string{}
	for _, part := range strings.Split(link[len(prefix):], "&") {
		if part == "" {
			continue
		}
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			return PairingLink{}, fmt.Errorf("pairing link parameter without a value: %s", part)
		}
		if _, dup := params[key]; dup {
			return PairingLink{}, fmt.Errorf("pairing link repeats %s", key)
		}
		v, err := url.PathUnescape(value) // decodeURIComponent: %XX only, '+' stays '+'
		if err != nil {
			return PairingLink{}, fmt.Errorf("pairing link: %w", err)
		}
		params[key] = v
	}
	if params["v"] != "1" {
		return PairingLink{}, errors.New("unsupported pairing link version")
	}
	p := PairingLink{Network: params["n"], CodeID: params["i"], Relay: params["r"]}
	if !IsNodeID(p.Network) {
		return PairingLink{}, errors.New("pairing link: bad network id")
	}
	if params["c"] == "" {
		return PairingLink{}, errors.New("pairing link: missing code")
	}
	if p.CodeID == "" {
		return PairingLink{}, errors.New("pairing link: missing code id")
	}
	if _, err := fromB64uLen(p.CodeID, codeIDLength, "pairing link code id"); err != nil {
		return PairingLink{}, err
	}
	if p.Relay == "" {
		return PairingLink{}, errors.New("pairing link: missing relay")
	}
	u, err := url.Parse(p.Relay)
	if err != nil {
		return PairingLink{}, fmt.Errorf("pairing link: %w", err)
	}
	if s := strings.ToLower(u.Scheme); s != "ws" && s != "wss" {
		return PairingLink{}, errors.New("pairing link: relay must be a ws:// or wss:// URL")
	}
	code, err := NormalizeCode(params["c"])
	if err != nil {
		return PairingLink{}, err
	}
	p.Code = code
	return p, nil
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
