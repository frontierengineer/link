package link

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
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
		got, err := Canonicalize([]byte(c.in))
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
		0x0000000000000000: "0", 0x8000000000000000: "0", 0x0000000000000001: "5e-324", 0x8000000000000001: "-5e-324",
		0x7fefffffffffffff: "1.7976931348623157e+308", 0xffefffffffffffff: "-1.7976931348623157e+308",
		0x4340000000000000: "9007199254740992", 0xc340000000000000: "-9007199254740992",
		0x4430000000000000: "295147905179352830000", 0x44b52d02c7e14af5: "9.999999999999997e+22",
		0x44b52d02c7e14af6: "1e+23", 0x44b52d02c7e14af7: "1.0000000000000001e+23",
		0x444b1ae4d6e2ef4e: "999999999999999700000", 0x444b1ae4d6e2ef4f: "999999999999999900000",
		0x444b1ae4d6e2ef50: "1e+21", 0x3eb0c6f7a0b5ed8c: "9.999999999999997e-7", 0x3eb0c6f7a0b5ed8d: "0.000001",
		0x41b3de4355555553: "333333333.3333332", 0x41b3de4355555554: "333333333.33333325",
		0x41b3de4355555555: "333333333.3333333", 0x41b3de4355555556: "333333333.3333334",
		0x41b3de4355555557: "333333333.33333343", 0xbecbf647612f3696: "-0.0000033333333333333333",
		0x43143ff3c1cb0959: "1424953923781206.2",
	}
	for bits, want := range cases {
		got, err := appendJCSNumber(nil, math.Float64frombits(bits))
		if err != nil || string(got) != want {
			t.Errorf("%016x: got %s want %s (%v)", bits, got, want, err)
		}
	}
	if _, err := appendJCSNumber(nil, math.NaN()); err == nil {
		t.Error("NaN accepted")
	}
}

func TestParseJSONIsStrict(t *testing.T) {
	bad := []string{
		`{"a":1,"a":2}`, `{"a":1} {}`, "{\"a\":\"\xff\"}", `{"a":`,
		`{"a":"\ud800"}`, `{"a":"\udc00"}`, `{"a":"\ud800x"}`, `{"a":"\ud800\u0041"}`, `["\ud83d"]`,
		strings.Repeat("[", 33) + strings.Repeat("]", 33),
	}
	for _, in := range bad {
		if _, err := parseJSON([]byte(in)); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
	good := []string{strings.Repeat("[", 32) + strings.Repeat("]", 32), `{"a":"\ud83d\ude00"}`, `{"a":"\\ud800"}`, `["\u0041\\"]`, `{"k":"\"\\ud800"}`}
	for _, in := range good {
		if _, err := parseJSON([]byte(in)); err != nil {
			t.Errorf("refused %q: %v", in, err)
		}
	}
}

func TestSafeInteger(t *testing.T) {
	ok := map[string]int64{"12": 12, "0": 0, "9007199254740991": 1<<53 - 1}
	for in, want := range ok {
		if got, good := safeInteger(json.Number(in)); !good || got != want {
			t.Errorf("%s: %d %v", in, got, good)
		}
	}
	for _, in := range []string{"1.5", "12.0", "1.2e1", "1.79e12", "1E2", "-0", "-7", "+7", "9007199254740992", "1e400", "x", ""} {
		if _, good := safeInteger(json.Number(in)); good {
			t.Errorf("%s accepted", in)
		}
	}
	if _, good := safeInteger("12"); good {
		t.Error("a string accepted as a number")
	}
}

func TestIDsAndBase64(t *testing.T) {
	id, _ := IdentityFromSeed(bytes.Repeat([]byte{7}, 32))
	s := id.ID()
	if len(s) != 26 || !IsNodeID(s) {
		t.Fatalf("id %q", s)
	}
	for _, bad := range []string{"", s[:25], s + "a", "A" + s[1:], s[:25] + "1", s[:25] + "b"} {
		if IsNodeID(bad) {
			t.Errorf("IsNodeID(%q)", bad)
		}
	}
	for _, bad := range []string{"AAAA\nAAA", "AA==", "A", "AB", "+/", "AAA\r"} {
		if _, err := fromB64u(bad); err == nil {
			t.Errorf("fromB64u(%q) accepted", bad)
		}
	}
	if _, err := fromB64uLen(b64u(make([]byte, 31)), 32, "k"); err == nil {
		t.Error("wrong length accepted")
	}
	if _, err := IdentityFromSeed(make([]byte, 31)); err == nil {
		t.Error("31-byte seed accepted")
	}
}

func TestCodesAndLinks(t *testing.T) {
	for range 100 {
		c := GenerateCode()
		if n, err := NormalizeCode(c); err != nil || n != c {
			t.Fatalf("generated %q", c)
		}
	}
	for _, bad := range []string{"", "ABCD-123", "ABCD-12345", "ABCD-123U", "ABCD 12!4"} {
		if _, err := NormalizeCode(bad); err == nil {
			t.Errorf("NormalizeCode(%q)", bad)
		}
	}
	if f, _ := FormatCode("abcd1234"); f != "ABCD-1234" {
		t.Error(f)
	}
	net, _ := NewIdentity()
	ok := PairingLink{Network: net.ID(), Code: "ABCD1234", CodeID: "AQIDBAUGBwg", Relay: "wss://relay.example:8443/v1?x=(a b)"}
	link, err := BuildPairingLink(ok)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(link, "r=wss%3A%2F%2Frelay.example%3A8443%2Fv1%3Fx%3D(a%20b)") {
		t.Errorf("relay not encoded as encodeURIComponent does: %s", link)
	}
	back, err := ParsePairingLink(link)
	if err != nil || back != ok {
		t.Fatalf("round trip %+v %v", back, err)
	}
	disp := strings.Replace(link, "c=ABCD1234", "c=ABCD-1234", 1)
	if back, err := ParsePairingLink(disp); err != nil || back.Code != "ABCD1234" {
		t.Errorf("displayed code: %v", err)
	}
	for _, bad := range []string{
		"https://pair?v=1", strings.Replace(link, "v=1", "v=2", 1), strings.Replace(link, "&i=", "&i=AA&i=", 1),
		strings.Replace(link, "i=AQIDBAUGBwg", "i=AQID", 1), strings.Replace(link, "r=wss", "r=https", 1),
		strings.Replace(link, "&r=", "&rx", 1), link + "&r=x", strings.Replace(link, "n="+net.ID(), "n=x", 1),
		strings.Replace(link, "%3A", "%zz", 1),
	} {
		if _, err := ParsePairingLink(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestOrigins(t *testing.T) {
	cases := map[string]string{
		"wss://EU.FrontierEngineer.link/v1":     "eu.frontierengineer.link",
		"wss://eu.frontierengineer.link:443/v1": "eu.frontierengineer.link",
		"ws://127.0.0.1:443/v1":                 "127.0.0.1",
		"ws://127.0.0.1:80/v1":                  "127.0.0.1",
		"wss://host:80/v1":                      "host",
		"ws://127.0.0.1:8080/v1":                "127.0.0.1:8080",
		"ws://127.0.0.1:08080/v1":               "127.0.0.1:8080",
		"WS://[::1]:443/v1":                     "[::1]",
		"ws://[::1]:9000/v1":                    "[::1]:9000",
	}
	for in, want := range cases {
		if got, err := originOf(in); err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"ftp://host/v1", "wss://relé.example/v1", "wss:///v1", "ws://host:99999/v1"} {
		if _, err := originOf(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestRosterRules(t *testing.T) {
	p, _ := NewIdentity()
	w, _ := NewIdentity()
	r, err := CreateNetwork(p, "wss://relay.example/v1", time.UnixMilli(1790000000000))
	if err != nil {
		t.Fatal(err)
	}
	u := r.UnsignedRoster
	u.Version = 2
	u.Members = append(u.Members, MemberFromIdentity(w, KindWorker))
	r2, err := SignRoster(u, p)
	if err != nil {
		t.Fatal(err)
	}
	if AcceptanceProblem(r2, r.Primary.Ed25519, 1) != nil || AcceptanceProblem(r2, r.Primary.Ed25519, 2) == nil {
		t.Error("acceptance")
	}
	// Unknown members survive a round trip and stay covered by the signature.
	raw, _ := json.Marshal(r2)
	var tree map[string]any
	json.Unmarshal(raw, &tree)
	tree["future"] = map[string]any{"z": 1, "a": []any{true}}
	tree["members"].([]any)[0].(map[string]any)["note"] = "x"
	tree["primary"].(map[string]any)["hint"] = "y"
	delete(tree, "signature")
	text, _ := json.Marshal(tree)
	canon, _ := Canonicalize(text)
	tree["signature"] = b64u(p.Sign(append([]byte(rosterLabel), canon...)))
	text, _ = json.Marshal(tree)
	ext, err := ValidateRoster(text)
	if err != nil {
		t.Fatalf("a roster with members this version does not define: %v", err)
	}
	again, _ := json.Marshal(ext)
	if _, err := ValidateRoster(again); err != nil {
		t.Fatalf("re-marshalled: %v", err)
	}
	tree["future"] = "changed"
	text, _ = json.Marshal(tree)
	if _, err := ValidateRoster(text); err == nil {
		t.Error("a change to an unknown member kept the signature valid")
	}
	// Shapes that are not rosters.
	for _, bad := range []string{`[]`, `{}`, `{"network":1}`, `{"network":"x","version":"1"}`} {
		if _, err := ValidateRoster([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	// The size limit: exactly 65000 bytes is valid, one more is not.
	sized := func(n int) *Roster {
		u := r.UnsignedRoster
		u.Relay = ""
		base, _ := (&Roster{UnsignedRoster: u, Signature: strings.Repeat("A", 86)}).Size()
		u.Relay = strings.Repeat("x", n-base)
		got, err := SignRoster(u, p)
		if err != nil {
			return nil
		}
		return got
	}
	if r := sized(MaxRosterBytes); r == nil {
		t.Error("a roster of exactly 65000 bytes refused")
	} else if s, _ := r.Size(); s != MaxRosterBytes {
		t.Errorf("built %d bytes", s)
	}
	if r := sized(MaxRosterBytes + 1); r != nil {
		t.Error("a roster one byte over accepted")
	}
}

func TestFramesAndSessionMessagesAreStrict(t *testing.T) {
	var peer [16]byte
	if _, err := encodeFrame(frameData, peer, make([]byte, maxFrame-frameHeader+1)); err == nil {
		t.Error("frame over 1 MiB encoded")
	}
	for _, bad := range [][]byte{nil, make([]byte, 17), append([]byte{2}, make([]byte, 17)...), make([]byte, maxFrame+1)} {
		if _, err := decodeFrame(bad); err == nil {
			t.Errorf("decoded %d bytes", len(bad))
		}
	}
	for _, bad := range [][]byte{nil, {1}, {2, 0, 0, 0}, {2, 0, 0, 0, 0, 0}, {3, 0}, {6}, {4, 0xff}, {5, 0xc3, 0x28}} {
		if _, err := decodeSessionMessage(bad); err == nil {
			t.Errorf("decoded %x", bad)
		}
	}
	if _, _, err := parseHandshakeInit([]byte{1, 2, 3}); err == nil {
		t.Error("short init")
	}
	if _, _, _, err := parseHandshakeResp(make([]byte, 7)); err == nil {
		t.Error("short resp")
	}
	if _, _, err := parseData([]byte{1}); err == nil {
		t.Error("short data")
	}
}

func TestIntegerFieldsAreLiterals(t *testing.T) {
	for _, body := range []string{
		`{"node":"x","ts":1790000000000.0,"sig":"s"}`, `{"node":"x","ts":1.79e12,"sig":"s"}`,
	} {
		if _, ok := parseResignation([]byte(body)); ok {
			t.Errorf("resignation %s accepted", body)
		}
	}
	if _, ok := parseResignation([]byte(`{"node":"x","ts":1790000000000,"sig":"s"}`)); !ok {
		t.Error("a resignation with an integer ts refused")
	}
}

// Names match exactly, case included (section 1): encoding/json would match "BytesHour".
func TestUsageNamesMatchExactly(t *testing.T) {
	tree, _ := parseJSON([]byte(`{"BytesHour":5,"bytesHour":7,"Connections":9,"limits":{"RateBps":1},"slowed":true}`))
	r, ok := usageFromTree(tree)
	if !ok || r.Network.BytesHour != 7 || r.Network.Connections != 0 || r.Network.Limits.RateBps != 0 || !r.Network.Slowed {
		t.Fatalf("%+v %v", r, ok)
	}
	if _, ok := usageFromTree(map[string]any{"slowed": "yes"}); ok {
		t.Error("a wrong type accepted")
	}
}
