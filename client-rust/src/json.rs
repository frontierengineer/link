//! JSON values as the protocol uses them, and the JSON Canonicalization Scheme (RFC 8785).
//!
//! Parsing is strict, because a parsed value may be canonicalised and its signature checked:
//! the input must be one JSON value (RFC 8259) with nothing after it, strings must be valid
//! Unicode (a lone surrogate escape is refused), object keys must not repeat (JCS input is
//! I-JSON, RFC 7493), and nesting is limited to 32 levels. Every number is held as an IEEE-754
//! double, correctly rounded, which is what ECMAScript's `JSON.parse` makes of it.
//!
//! - Numbers serialise as ECMAScript's `Number::toString` (RFC 8785 section 3.2.2.3).
//! - Strings serialise as ECMAScript's `JSON.stringify` does (section 3.2.2.2).
//! - Canonical object members are sorted by the UTF-16 code units of their names
//!   (section 3.2.3), recursively; arrays keep their order.

use std::collections::HashSet;
use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

/// A JSON value. Objects keep their members in the order they were written.
#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    /// The value, and whether it was written as an integer literal (no fraction, no exponent)
    /// or made from an integer. Only an integer literal counts as an integer (spec section 1).
    Number(f64, bool),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

/// Why a text is not acceptable JSON, or a value cannot be canonicalised.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonError(pub String);

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for JsonError {}

impl Json {
    /// Parses one JSON value, strictly (see the module documentation).
    pub fn parse(text: &str) -> Result<Json, JsonError> {
        if nesting(text) > MAX_DEPTH {
            return Err(JsonError(format!("json: nested deeper than {MAX_DEPTH} levels")));
        }
        serde_json::from_str::<Json>(text).map_err(|e| JsonError(format!("json: {e}")))
    }

    /// Parses UTF-8 bytes as one JSON value; invalid UTF-8 is refused.
    pub fn parse_bytes(bytes: &[u8]) -> Result<Json, JsonError> {
        let text = std::str::from_utf8(bytes).map_err(|_| JsonError("json: invalid UTF-8".into()))?;
        Json::parse(text)
    }

    /// An object from `(name, value)` pairs, in that order.
    pub fn object<K: Into<String>>(members: impl IntoIterator<Item = (K, Json)>) -> Json {
        Json::Object(members.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }

    /// A number that is not an integer literal.
    pub fn float(f: f64) -> Json {
        Json::Number(f, false)
    }

    pub fn str(s: impl Into<String>) -> Json {
        Json::String(s.into())
    }

    /// A number from an integer; exact up to 2^53.
    pub fn int(n: u64) -> Json {
        Json::Number(n as f64, true)
    }

    /// The member `key` of an object.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Number(n, _) => Some(*n),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&[(String, Json)]> {
        match self {
            Json::Object(m) => Some(m),
            _ => None,
        }
    }

    /// The value as an integer `0 ..= 2^53 - 1`, written as an integer literal: `12`, not `12.0`
    /// or `1.2e1` (spec section 1).
    pub fn as_safe_uint(&self) -> Option<u64> {
        match self {
            Json::Number(n, true) if (0.0..=MAX_SAFE_INTEGER).contains(n) => Some(*n as u64),
            _ => None,
        }
    }

    /// Compact JSON with members in their own order. Fails only on a non-finite number.
    pub fn to_json_string(&self) -> Result<String, JsonError> {
        let mut out = String::new();
        write_value(&mut out, self, false)?;
        Ok(out)
    }

    /// RFC 8785 canonical JSON. Fails only on a non-finite number.
    pub fn canonicalize(&self) -> Result<String, JsonError> {
        let mut out = String::new();
        write_value(&mut out, self, true)?;
        Ok(out)
    }
}

/// The deepest nesting of arrays and objects a document may have.
pub const MAX_DEPTH: usize = 32;

/// The deepest nesting of `[` and `{` in `text`, outside strings. Only an upper bound matters:
/// on malformed text the parser refuses it anyway.
fn nesting(text: &str) -> usize {
    let (mut depth, mut max, mut in_string, mut escaped) = (0usize, 0usize, false, false);
    for b in text.bytes() {
        if in_string {
            match b {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth += 1;
                max = max.max(depth);
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    max
}

/// 2^53 - 1.
pub const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

fn write_value(out: &mut String, v: &Json, canonical: bool) -> Result<(), JsonError> {
    match v {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Number(n, _) => write_number(out, *n)?,
        Json::String(s) => write_string(out, s),
        Json::Array(a) => {
            out.push('[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, e, canonical)?;
            }
            out.push(']');
        }
        Json::Object(m) => {
            let mut members: Vec<&(String, Json)> = m.iter().collect();
            if canonical {
                members.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            }
            out.push('{');
            for (i, (k, e)) in members.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, k);
                out.push(':');
                write_value(out, e, canonical)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// A string as ECMAScript's `JSON.stringify` writes it.
fn write_string(out: &mut String, s: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                let b = c as u32;
                out.push_str("\\u00");
                out.push(char::from(HEX[(b >> 4) as usize]));
                out.push(char::from(HEX[(b & 15) as usize]));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A number as ECMAScript's `Number::toString` writes it (ECMA-262, Number::toString).
fn write_number(out: &mut String, f: f64) -> Result<(), JsonError> {
    if !f.is_finite() {
        return Err(JsonError("jcs: NaN and Infinity are not JSON".into()));
    }
    if f == 0.0 {
        out.push('0'); // also -0
        return Ok(());
    }
    if f < 0.0 {
        out.push('-');
    }
    // Ryu writes the shortest digits that round-trip and, between two such, the nearest, ties
    // to even: the digits ECMAScript picks. (Rust's own `{:e}` breaks ties upwards.)
    let mut buf = ryu::Buffer::new();
    let (digits, n) = ryu_digits(buf.format_finite(f.abs()))?;
    let k = digits.len() as i32;
    if k <= n && n <= 21 {
        out.push_str(&digits);
        for _ in 0..(n - k) {
            out.push('0');
        }
    } else if 0 < n && n <= 21 {
        let (int, frac) = digits.split_at(n as usize);
        out.push_str(int);
        out.push('.');
        out.push_str(frac);
    } else if -6 < n && n <= 0 {
        out.push_str("0.");
        for _ in 0..(-n) {
            out.push('0');
        }
        out.push_str(&digits);
    } else {
        let (first, rest) = digits.split_at(1);
        out.push_str(first);
        if !rest.is_empty() {
            out.push('.');
            out.push_str(rest);
        }
        out.push('e');
        if n > 0 {
            out.push('+');
        }
        out.push_str(&(n - 1).to_string());
    }
    Ok(())
}

/// The significant digits of Ryu's output and the position `n` of the decimal point relative to
/// them (value = 0.d1d2… × 10^n), as ECMAScript's Number::toString names them.
fn ryu_digits(s: &str) -> Result<(String, i32), JsonError> {
    let bad = || JsonError("jcs: number format".into());
    let (mant, exp) = match s.split_once('e') {
        Some((m, e)) => (m, e.parse::<i32>().map_err(|_| bad())?),
        None => (s, 0),
    };
    let point = mant.find('.').unwrap_or(mant.len()) as i32;
    let all: String = mant.chars().filter(|c| *c != '.').collect();
    let lead = all.chars().take_while(|c| *c == '0').count();
    let digits = all[lead..].trim_end_matches('0').to_owned();
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    Ok((digits, point - lead as i32 + exp))
}

impl<'de> Deserialize<'de> for Json {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Json, D::Error> {
        d.deserialize_any(JsonVisitor)
    }
}

struct JsonVisitor;

impl<'de> Visitor<'de> for JsonVisitor {
    type Value = Json;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Json, E> {
        Ok(Json::Bool(v))
    }

    // Integers are converted to the nearest double, as ECMAScript does.
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Json, E> {
        Ok(Json::Number(v as f64, true))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Json, E> {
        Ok(Json::Number(v as f64, true))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Json, E> {
        // serde_json reports a fraction, an exponent, or an integer too large for 64 bits here.
        if v.is_finite() { Ok(Json::Number(v, false)) } else { Err(E::custom("number out of range")) }
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Json, E> {
        Ok(Json::String(v.to_owned()))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Json, E> {
        Ok(Json::String(v))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Json, E> {
        Ok(Json::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Json, E> {
        Ok(Json::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Json, A::Error> {
        let mut out = Vec::new();
        while let Some(v) = seq.next_element::<Json>()? {
            out.push(v);
        }
        Ok(Json::Array(out))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Json, A::Error> {
        let mut out: Vec<(String, Json)> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        while let Some(k) = map.next_key::<String>()? {
            if !seen.insert(k.clone()) {
                return Err(de::Error::custom(format!("duplicate key {k:?}")));
            }
            let v = map.next_value::<Json>()?;
            out.push((k, v));
        }
        Ok(Json::Object(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn num(f: f64) -> String {
        let mut s = String::new();
        write_number(&mut s, f).unwrap();
        s
    }

    #[test]
    fn numbers_serialise_as_ecmascript() {
        // RFC 8785 Appendix B, and the cases the relay's canonicaliser checks.
        let cases: &[(u64, &str)] = &[
            (0x0000000000000000, "0"),
            (0x8000000000000000, "0"),
            (0x0000000000000001, "5e-324"),
            (0x8000000000000001, "-5e-324"),
            (0x7fefffffffffffff, "1.7976931348623157e+308"),
            (0xffefffffffffffff, "-1.7976931348623157e+308"),
            (0x4340000000000000, "9007199254740992"),
            (0xc340000000000000, "-9007199254740992"),
            (0x4430000000000000, "295147905179352830000"),
            (0x44b52d02c7e14af5, "9.999999999999997e+22"),
            (0x44b52d02c7e14af6, "1e+23"),
            (0x44b52d02c7e14af7, "1.0000000000000001e+23"),
            (0x444b1ae4d6e2ef4e, "999999999999999700000"),
            (0x444b1ae4d6e2ef4f, "999999999999999900000"),
            (0x444b1ae4d6e2ef50, "1e+21"),
            (0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"),
            (0x3eb0c6f7a0b5ed8d, "0.000001"),
            (0x41b3de4355555553, "333333333.3333332"),
            (0x41b3de4355555554, "333333333.33333325"),
            (0x41b3de4355555555, "333333333.3333333"),
            (0x41b3de4355555556, "333333333.3333334"),
            (0x41b3de4355555557, "333333333.33333343"),
            (0xbecbf647612f3696, "-0.0000033333333333333333"),
            (0x43143ff3c1cb0959, "1424953923781206.2"),
        ];
        for (bits, want) in cases {
            assert_eq!(num(f64::from_bits(*bits)), *want, "{bits:#x}");
        }
        assert_eq!(num(1790000000000.0), "1790000000000");
        assert_eq!(num(12.0), "12");
        assert_eq!(num(0.5), "0.5");
        assert!(write_number(&mut String::new(), f64::NAN).is_err());
    }

    #[test]
    fn parse_is_strict() {
        assert!(Json::parse(r#"{"a":1,"a":2}"#).is_err(), "duplicate key");
        assert!(Json::parse(r#"{"a":1} x"#).is_err(), "trailing data");
        assert!(Json::parse(r#""\ud800""#).is_err(), "lone surrogate");
        // Numbers must be finite: one that overflows to infinity is refused wherever it is.
        for inf in [
            "1e400",
            "1e309",
            "-1e309",
            "[1, 1e309]",
            r#"{"version":1e309}"#,
            "179769313486231590000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000.0",
        ] {
            assert!(Json::parse(inf).is_err(), "{inf}");
        }
        assert!(Json::parse("1.7976931348623157e308").is_ok(), "the largest finite double");
        assert!(Json::parse(&("[".repeat(200) + &"]".repeat(200))).is_err(), "too deep");
        assert!(Json::parse(&("[".repeat(33) + &"]".repeat(33))).is_err(), "33 levels");
        assert!(Json::parse(&("[".repeat(32) + &"]".repeat(32))).is_ok(), "32 levels");
        assert!(Json::parse(&format!("[\"{}\"]", "[{".repeat(100))).is_ok(), "brackets in a string are text");
        assert!(Json::parse(r#"["\\", [[]]]"#).is_ok(), "an escaped backslash ends no string");
        assert!(Json::parse_bytes(b"\"\xff\"").is_err(), "invalid UTF-8");
        assert_eq!(Json::parse(r#""\ud83d\ude00""#), Ok(Json::str("😀")));
        // Only an integer literal is an integer (spec section 1).
        assert_eq!(Json::parse("12").unwrap().as_safe_uint(), Some(12));
        assert_eq!(Json::parse("12.0").unwrap().as_safe_uint(), None);
        assert_eq!(Json::parse("1.2e1").unwrap().as_safe_uint(), None);
        assert_eq!(Json::parse("1.79e12").unwrap().as_safe_uint(), None);
        // serde_json reports `-0` as a float (it keeps the sign), indistinguishable from `-0.0`,
        // so it is not taken as an integer: a known difference from the spec's grammar, which no
        // implementation writes.
        assert_eq!(Json::parse("-0").unwrap().as_safe_uint(), None);
        assert_eq!(Json::parse("9007199254740991").unwrap().as_safe_uint(), Some(9007199254740991));
        assert_eq!(Json::parse("9007199254740992").unwrap().as_safe_uint(), None);
        assert_eq!(Json::parse("-1").unwrap().as_safe_uint(), None);
        assert_eq!(Json::parse("1.5").unwrap().as_safe_uint(), None);
    }

    #[test]
    fn canonical_form() {
        // RFC 8785 section 3.2.3: sorted by UTF-16 code units, so U+1F600 (a surrogate pair,
        // D83D) sorts before U+FB33 although its UTF-8 encoding sorts after.
        let v =
            Json::parse("{\"\u{fb33}\":1,\"\u{1f600}\":2,\"a\":[true,null,\"\\u001f\\n\"],\"\\u0080\":{}}").unwrap();
        assert_eq!(
            v.canonicalize().unwrap(),
            "{\"a\":[true,null,\"\\u001f\\n\"],\"\u{80}\":{},\"\u{1f600}\":2,\"\u{fb33}\":1}"
        );
        // RFC 8785 section 3.2.2's example.
        let v = Json::parse(
            r#"{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/","literals":[null,true,false]}"#,
        )
        .unwrap();
        assert_eq!(
            v.canonicalize().unwrap(),
            r#"{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}"#
        );
        let v = Json::parse(r#"{"b":1e21,"a":"\u2028/"}"#).unwrap();
        assert_eq!(v.to_json_string().unwrap(), "{\"b\":1e+21,\"a\":\"\u{2028}/\"}");
    }
}
