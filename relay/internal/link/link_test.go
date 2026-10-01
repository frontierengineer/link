package link

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"math"
	"testing"
)

// The examples of RFC 8785 sections 3.2.2 and 3.2.3.
func TestCanonicalizeRFC8785Examples(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{
  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
  "literals": [null, true, false]
}`, `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`},
		{`{
  "\u20ac": "Euro Sign",
  "\r": "Carriage Return",
  "\ufb33": "Hebrew Letter Dalet With Dagesh",
  "1": "One",
  "\ud83d\ude00": "Emoji: Grinning Face",
  "\u0080": "Control",
  "\u00f6": "Latin Small Letter O With Diaeresis"
}`, "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\"😀\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}"},
	}
	for _, c := range cases {
		v, err := ParseJSON([]byte(c.in))
		if err != nil {
			t.Fatal(err)
		}
		got, err := Canonicalize(v)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != c.want {
			t.Errorf("got  %s\nwant %s", got, c.want)
		}
	}
}

// The number samples of RFC 8785 appendix B.
func TestCanonicalNumbersRFC8785AppendixB(t *testing.T) {
	cases := map[uint64]string{
		0x0000000000000000: "0",
		0x8000000000000000: "0",
		0x0000000000000001: "5e-324",
		0x8000000000000001: "-5e-324",
		0x7fefffffffffffff: "1.7976931348623157e+308",
		0xffefffffffffffff: "-1.7976931348623157e+308",
		0x4340000000000000: "9007199254740992",
		0xc340000000000000: "-9007199254740992",
		0x4430000000000000: "295147905179352830000",
		0x44b52d02c7e14af5: "9.999999999999997e+22",
		0x44b52d02c7e14af6: "1e+23",
		0x44b52d02c7e14af7: "1.0000000000000001e+23",
		0x444b1ae4d6e2ef4e: "999999999999999700000",
		0x444b1ae4d6e2ef4f: "999999999999999900000",
		0x444b1ae4d6e2ef50: "1e+21",
		0x3eb0c6f7a0b5ed8c: "9.999999999999997e-7",
		0x3eb0c6f7a0b5ed8d: "0.000001",
		0x41b3de4355555553: "333333333.3333332",
		0x41b3de4355555554: "333333333.33333325",
		0x41b3de4355555555: "333333333.3333333",
		0x41b3de4355555556: "333333333.3333334",
		0x41b3de4355555557: "333333333.33333343",
		0xbecbf647612f3696: "-0.0000033333333333333333",
		0x43143ff3c1cb0959: "1424953923781206.2",
	}
	for bits, want := range cases {
		got, err := appendJCSNumber(nil, math.Float64frombits(bits))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("%016x: got %s want %s", bits, got, want)
		}
	}
	if _, err := appendJCSNumber(nil, math.NaN()); err == nil {
		t.Error("NaN accepted")
	}
}

func TestParseJSONRefusesDuplicatesAndTrailingData(t *testing.T) {
	for _, in := range []string{`{"a":1,"a":2}`, `{"a":1} {}`, "{\"a\":\"\xff\"}", `{"a":`} {
		if _, err := ParseJSON([]byte(in)); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

func TestIDs(t *testing.T) {
	k, err := DeriveKeys(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s := k.ID.String()
	if len(s) != 26 {
		t.Fatalf("id %q is not 26 characters", s)
	}
	back, ok := ParseID(s)
	if !ok || back != k.ID {
		t.Fatal("id does not round-trip")
	}
	for _, bad := range []string{"", s[:25], s + "a", "A" + s[1:], s[:25] + "1"} {
		if _, ok := ParseID(bad); ok {
			t.Errorf("ParseID accepted %q", bad)
		}
	}
}

func testRoster(t *testing.T, mutate func(map[string]any)) []byte {
	t.Helper()
	p, _ := DeriveKeys(bytes.Repeat([]byte{1}, 32))
	w, _ := DeriveKeys(bytes.Repeat([]byte{2}, 32))
	members := []any{}
	for _, m := range []struct {
		k    *Keys
		kind string
	}{{p, KindPrimary}, {w, KindWorker}} {
		members = append(members, map[string]any{
			"id": m.k.ID.String(), "ed25519": B64u.EncodeToString(m.k.Ed25519Public),
			"x25519": B64u.EncodeToString(m.k.X25519Public), "kind": m.kind,
		})
	}
	if members[0].(map[string]any)["id"].(string) > members[1].(map[string]any)["id"].(string) {
		members[0], members[1] = members[1], members[0]
	}
	r := map[string]any{
		"network": p.ID.String(), "version": 3, "issuedAt": int64(1790000000000),
		"relay": "wss://relay.example/v1", "primary": map[string]any{"ed25519": B64u.EncodeToString(p.Ed25519Public)},
		"members": members,
	}
	if mutate != nil {
		mutate(r)
	}
	if err := SignRoster(r, p.Ed25519); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(r)
	return raw
}

func TestRosterValidity(t *testing.T) {
	if _, err := ParseRoster(testRoster(t, nil)); err != nil {
		t.Fatalf("valid roster refused: %v", err)
	}
	// Whitespace and member order in the JSON text do not matter: the signature is over JCS.
	var loose map[string]any
	_ = json.Unmarshal(testRoster(t, nil), &loose)
	pretty, _ := json.MarshalIndent(loose, "", "   ")
	if _, err := ParseRoster(pretty); err != nil {
		t.Fatalf("reformatted roster refused: %v", err)
	}
	other, _ := DeriveKeys(bytes.Repeat([]byte{9}, 32))
	bad := map[string]func(map[string]any){
		"version zero":     func(r map[string]any) { r["version"] = 0 },
		"fractional":       func(r map[string]any) { r["version"] = 1.5 },
		"unsorted members": func(r map[string]any) { m := r["members"].([]any); m[0], m[1] = m[1], m[0] },
		"two primaries": func(r map[string]any) {
			for _, m := range r["members"].([]any) {
				m.(map[string]any)["kind"] = KindPrimary
			}
		},
		"unknown kind": func(r map[string]any) { r["members"].([]any)[0].(map[string]any)["kind"] = "boss" },
		"id not derived": func(r map[string]any) {
			r["members"].([]any)[0].(map[string]any)["ed25519"] = B64u.EncodeToString(other.Ed25519Public)
		},
		"network not primary": func(r map[string]any) {
			r["network"] = other.ID.String()
		},
	}
	for name, mutate := range bad {
		if _, err := ParseRoster(testRoster(t, mutate)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A change after signing breaks the signature.
	var r map[string]any
	_ = json.Unmarshal(testRoster(t, nil), &r)
	r["version"] = 4
	raw, _ := json.Marshal(r)
	if _, err := ParseRoster(raw); err == nil {
		t.Error("tampered roster accepted")
	}
}

func TestRegisterMessage(t *testing.T) {
	ch := bytes.Repeat([]byte{0xaa}, 32)
	m := RegisterMessage("n", "node", ch, 0x0102030405060708, "h:1")
	want := []byte{0, 0, 0, 24}
	want = append(want, "frontier-link/1/register"...)
	want = append(want, 0, 0, 0, 1, 'n', 0, 0, 0, 4, 'n', 'o', 'd', 'e')
	want = append(want, ch...)
	want = append(want, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 3, 'h', ':', '1')
	if !bytes.Equal(m, want) {
		t.Fatalf("got %x\nwant %x", m, want)
	}
	k, _ := DeriveKeys(bytes.Repeat([]byte{3}, 32))
	if !ed25519.Verify(k.Ed25519Public, m, ed25519.Sign(k.Ed25519, m)) {
		t.Fatal("signature does not verify")
	}
}

// Verification is strict RFC 8032 (crypto/ed25519): a signature whose S is not reduced
// modulo the group order is refused even though S - L would verify.
func TestNonCanonicalSignatureRefused(t *testing.T) {
	k, _ := DeriveKeys(bytes.Repeat([]byte{3}, 32))
	msg := []byte("frontier")
	sig := ed25519.Sign(k.Ed25519, msg)
	if !ed25519.Verify(k.Ed25519Public, msg, sig) {
		t.Fatal("canonical signature refused")
	}
	if ed25519.Verify(k.Ed25519Public, msg, NonCanonical(sig)) {
		t.Fatal("non-canonical signature accepted")
	}
}
