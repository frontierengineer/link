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

// MaxJSONDepth is the most arrays and objects open at once in any protocol JSON document
// (section 1); a roster needs three.
const MaxJSONDepth = 32

// ParseJSON decodes one JSON value into a tree of map[string]any, []any, string, json.Number,
// bool and nil. Unlike encoding/json it refuses duplicate object keys, invalid UTF-8, an
// escaped lone surrogate, a number out of range, nesting beyond MaxJSONDepth and trailing data, which a value about to be canonicalised and signed
// must not have: JCS input is I-JSON (RFC 7493), and every JSON document of the protocol is.
func ParseJSON(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("json: invalid UTF-8")
	}
	if err := checkSurrogateEscapes(data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := parseValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("json: trailing data")
	}
	return v, nil
}

// checkSurrogateEscapes refuses a \u escape of a surrogate that is not one half of a pair,
// which encoding/json would quietly turn into U+FFFD. Valid UTF-8 cannot hold a surrogate, so
// only escapes need looking at. Malformed escapes are left for the decoder to refuse.
func checkSurrogateEscapes(data []byte) error {
	lone := errors.New("json: escaped lone surrogate")
	inString := false
	for i := 0; i < len(data); i++ {
		switch c := data[i]; {
		case !inString:
			inString = c == '"'
		case c == '"':
			inString = false
		case c == '\\':
			r, ok := escapedUnit(data, i)
			if !ok {
				i++ // a two-character escape, or a malformed one
				continue
			}
			i += 5
			switch {
			case utf16.IsSurrogate(rune(r)) && r < 0xdc00:
				low, ok := escapedUnit(data, i+1)
				if !ok || low < 0xdc00 || low > 0xdfff {
					return lone
				}
				i += 6
			case utf16.IsSurrogate(rune(r)):
				return lone
			}
		}
	}
	return nil
}

// escapedUnit reads the \uXXXX escape at data[i], if there is one.
func escapedUnit(data []byte, i int) (uint16, bool) {
	if i+6 > len(data) || data[i] != '\\' || data[i+1] != 'u' {
		return 0, false
	}
	n, err := strconv.ParseUint(string(data[i+2:i+6]), 16, 16)
	return uint16(n), err == nil
}

// parseValue reads one value inside `open` arrays and objects.
func parseValue(dec *json.Decoder, open int) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		if open >= MaxJSONDepth {
			return nil, errors.New("json: nested too deeply")
		}
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
				if m[k], err = parseValue(dec, open+1); err != nil {
					return nil, err
				}
			}
			_, err := dec.Token()
			return m, err
		case '[':
			a := []any{}
			for dec.More() {
				v, err := parseValue(dec, open+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			_, err := dec.Token()
			return a, err
		}
		return nil, fmt.Errorf("json: unexpected %v", t)
	case json.Number:
		// Every number is finite as a double (section 1): 1e309 is not.
		if f, err := strconv.ParseFloat(string(t), 64); err != nil || math.IsInf(f, 0) {
			return nil, fmt.Errorf("json: number %s out of range", t)
		}
		return t, nil
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
