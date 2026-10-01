package link

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ParseJSON decodes one JSON value into a tree of map[string]any, []any, string, json.Number,
// bool and nil. Unlike encoding/json it refuses duplicate object keys, invalid UTF-8 and
// trailing data, which a value about to be canonicalised and signed must not have.
func ParseJSON(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("json: invalid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("json: trailing data")
	}
	return v, nil
}

func parseValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			m := map[string]any{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k := kt.(string)
				if _, dup := m[k]; dup {
					return nil, fmt.Errorf("json: duplicate key %q", k)
				}
				if m[k], err = parseValue(dec); err != nil {
					return nil, err
				}
			}
			_, err := dec.Token()
			return m, err
		case '[':
			a := []any{}
			for dec.More() {
				v, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			_, err := dec.Token()
			return a, err
		}
		return nil, fmt.Errorf("json: unexpected %v", t)
	default:
		return t, nil
	}
}

// Canonicalize serialises a value as RFC 8785 (JCS) prescribes: object members sorted by the
// UTF-16 code units of their names, no whitespace, strings escaped as ECMAScript's
// JSON.stringify does, numbers as ECMAScript's Number.prototype.toString.
func Canonicalize(v any) ([]byte, error) {
	var b []byte
	return appendJCS(b, v)
}

func appendJCS(b []byte, v any) ([]byte, error) {
	var err error
	switch t := v.(type) {
	case nil:
		return append(b, "null"...), nil
	case bool:
		return strconv.AppendBool(b, t), nil
	case string:
		return appendJCSString(b, t)
	case json.Number:
		f, err := strconv.ParseFloat(string(t), 64)
		if err != nil {
			return nil, fmt.Errorf("jcs: number %q: %w", t, err)
		}
		return appendJCSNumber(b, f)
	case float64:
		return appendJCSNumber(b, t)
	case int:
		return appendJCSNumber(b, float64(t))
	case int64:
		return appendJCSNumber(b, float64(t))
	case []any:
		b = append(b, '[')
		for i, e := range t {
			if i > 0 {
				b = append(b, ',')
			}
			if b, err = appendJCS(b, e); err != nil {
				return nil, err
			}
		}
		return append(b, ']'), nil
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		slices.SortFunc(keys, compareUTF16)
		b = append(b, '{')
		for i, k := range keys {
			if i > 0 {
				b = append(b, ',')
			}
			if b, err = appendJCSString(b, k); err != nil {
				return nil, err
			}
			b = append(b, ':')
			if b, err = appendJCS(b, t[k]); err != nil {
				return nil, err
			}
		}
		return append(b, '}'), nil
	}
	return nil, fmt.Errorf("jcs: unsupported type %T", v)
}

func compareUTF16(a, b string) int {
	return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b)))
}

func appendJCSString(b []byte, s string) ([]byte, error) {
	if !utf8.ValidString(s) {
		return nil, errors.New("jcs: invalid UTF-8 in string")
	}
	const hex = "0123456789abcdef"
	b = append(b, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"', '\\':
			b = append(b, '\\', c)
		case '\b':
			b = append(b, '\\', 'b')
		case '\t':
			b = append(b, '\\', 't')
		case '\n':
			b = append(b, '\\', 'n')
		case '\f':
			b = append(b, '\\', 'f')
		case '\r':
			b = append(b, '\\', 'r')
		default:
			if c < 0x20 {
				b = append(b, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xf])
			} else {
				b = append(b, c)
			}
		}
	}
	return append(b, '"'), nil
}

// appendJCSNumber formats f as ECMAScript's Number::toString (ECMA-262 7.1.12.1), which is
// what JCS requires. Go's shortest round-trip digits are the same digits ECMAScript picks.
func appendJCSNumber(b []byte, f float64) ([]byte, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return nil, errors.New("jcs: NaN and Infinity are not JSON")
	}
	if f == 0 {
		return append(b, '0'), nil // also -0
	}
	if f < 0 {
		b = append(b, '-')
		f = -f
	}
	// "d.ddddde±x": digits and decimal exponent.
	e := strconv.FormatFloat(f, 'e', -1, 64)
	mant, expStr, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	exp, _ := strconv.Atoi(expStr)
	k, n := len(digits), exp+1
	switch {
	case k <= n && n <= 21:
		b = append(b, digits...)
		for range n - k {
			b = append(b, '0')
		}
	case 0 < n && n <= 21:
		b = append(b, digits[:n]...)
		b = append(b, '.')
		b = append(b, digits[n:]...)
	case -6 < n && n <= 0:
		b = append(b, '0', '.')
		for range -n {
			b = append(b, '0')
		}
		b = append(b, digits...)
	default:
		b = append(b, digits[0])
		if k > 1 {
			b = append(b, '.')
			b = append(b, digits[1:]...)
		}
		b = append(b, 'e')
		if n-1 >= 0 {
			b = append(b, '+')
		}
		b = strconv.AppendInt(b, int64(n-1), 10)
	}
	return b, nil
}
