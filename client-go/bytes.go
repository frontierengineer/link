// Package link is the Go client for Link, protocol version 1 (spec/protocol.md): keys and
// ids, signed rosters, pairing with a short code (SPAKE2), and end-to-end encrypted sessions
// (Noise IK) over one outbound WebSocket to a relay that only routes.
package link

import (
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// The encodings the spec's notation names: lenStr, u32be, u64be, b64u (base64url, no
// padding) and b32 (RFC 4648 base32, lowercase, no padding). Decoders are strict: they reject
// padding, foreign characters (line breaks included, which encoding/base64 would otherwise
// skip) and non-canonical trailing bits, so one value has exactly one text form.

var (
	b64uEnc = base64.RawURLEncoding.Strict()
	b32Enc  = base32.StdEncoding.WithPadding(base32.NoPadding)
)

func b64u(b []byte) string { return b64uEnc.EncodeToString(b) }

func fromB64u(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, errors.New("invalid base64url character")
	}
	return b64uEnc.DecodeString(s)
}

// fromB64uLen decodes b64u and requires an exact byte length.
func fromB64uLen(s string, n int, what string) ([]byte, error) {
	b, err := fromB64u(s)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	if len(b) != n {
		return nil, fmt.Errorf("%s: expected %d bytes", what, n)
	}
	return b, nil
}

func b32(b []byte) string { return strings.ToLower(b32Enc.EncodeToString(b)) }

func appendLenStr(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

func u32be(x uint32) []byte { return binary.BigEndian.AppendUint32(nil, x) }

func u64be(x uint64) []byte { return binary.BigEndian.AppendUint64(nil, x) }

// equalBytes compares in constant time (for equal lengths).
func equalBytes(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }
