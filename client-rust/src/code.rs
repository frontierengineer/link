//! Pairing codes, code ids and pairing links (section 5.1).

use url::Url;

use crate::bytes::from_b64u_array;
use crate::crypto::random_array;
use crate::identity::is_node_id;

pub const CROCKFORD: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
pub const CODE_LENGTH: usize = 8;
pub const CODE_ID_LENGTH: usize = 8;

/// A fresh code in its canonical form: 8 Crockford characters, no hyphen.
pub fn generate_code() -> String {
    let alphabet = CROCKFORD.as_bytes();
    // 256 is a multiple of 32, so `byte & 31` is uniform.
    random_array::<CODE_LENGTH>().iter().map(|b| char::from(alphabet[usize::from(b & 31)])).collect()
}

/// The canonical code for user input: hyphens and whitespace dropped, upper-cased, I and L read
/// as 1, O as 0. Fails when the result is not 8 Crockford characters.
pub fn normalize_code(input: &str) -> Result<String, String> {
    let code: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(char::to_uppercase)
        .map(|c| match c {
            'I' | 'L' => '1',
            'O' => '0',
            c => c,
        })
        .collect();
    if code.chars().count() != CODE_LENGTH || !code.chars().all(|c| CROCKFORD.contains(c)) {
        return Err("a pairing code is 8 characters from 0-9 and A-Z without I, L, O, U".into());
    }
    Ok(code)
}

/// `XXXX-XXXX`.
pub fn format_code(code: &str) -> Result<String, String> {
    let c = normalize_code(code)?;
    // Canonical codes are ASCII, so byte offsets are character offsets.
    Ok(format!("{}-{}", &c[..4], &c[4..]))
}

pub fn generate_code_id() -> [u8; CODE_ID_LENGTH] {
    random_array::<CODE_ID_LENGTH>()
}

/// The parts of a `frontier://pair` link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingLink {
    pub network: String,
    /// Canonical code, no hyphen.
    pub code: String,
    /// b64u of the 8-byte code id.
    pub code_id: String,
    pub relay: String,
}

/// `frontier://pair?v=1&n=<network>&c=<code>&i=<code id>&r=<relay, percent-encoded>`.
pub fn build_pairing_link(p: &PairingLink) -> Result<String, String> {
    if !is_node_id(&p.network) {
        return Err("network is not a node id".into());
    }
    from_b64u_array::<CODE_ID_LENGTH>(&p.code_id).ok_or("code id: expected 8 bytes")?;
    Ok(format!(
        "frontier://pair?v=1&n={}&c={}&i={}&r={}",
        p.network,
        normalize_code(&p.code)?,
        p.code_id,
        encode_uri_component(&p.relay)
    ))
}

pub fn parse_pairing_link(link: &str) -> Result<PairingLink, String> {
    let rest = link.strip_prefix("frontier://pair?").ok_or("not a frontier://pair link")?;
    let mut params: Vec<(String, String)> = Vec::new();
    for part in rest.split('&') {
        if part.is_empty() {
            continue;
        }
        let (key, value) =
            part.split_once('=').ok_or_else(|| format!("pairing link parameter without a value: {part}"))?;
        if params.iter().any(|(k, _)| k == key) {
            return Err(format!("pairing link repeats {key}"));
        }
        let value = decode_uri_component(value).ok_or("pairing link: malformed percent-encoding")?;
        params.push((key.to_owned(), value));
    }
    let get = |k: &str| params.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str()).filter(|v| !v.is_empty());
    if get("v") != Some("1") {
        return Err("unsupported pairing link version".into());
    }
    let network = get("n").filter(|n| is_node_id(n)).ok_or("pairing link: bad network id")?;
    let code = get("c").ok_or("pairing link: missing code")?;
    let code_id = get("i").ok_or("pairing link: missing code id")?;
    from_b64u_array::<CODE_ID_LENGTH>(code_id).ok_or("pairing link code id: expected 8 bytes")?;
    let relay = get("r").ok_or("pairing link: missing relay")?;
    let scheme = Url::parse(relay).map_err(|e| format!("pairing link: relay is not a URL: {e}"))?;
    if !matches!(scheme.scheme(), "ws" | "wss") {
        return Err("pairing link: relay must be a ws:// or wss:// URL".into());
    }
    Ok(PairingLink {
        network: network.to_owned(),
        code: normalize_code(code)?,
        code_id: code_id.to_owned(),
        relay: relay.to_owned(),
    })
}

/// ECMAScript's `encodeURIComponent`: everything but `A-Z a-z 0-9 - _ . ! ~ * ' ( )` as
/// `%XX` of its UTF-8 bytes, upper-case hex.
fn encode_uri_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// ECMAScript's `decodeURIComponent`: `%XX` sequences decoded as UTF-8; `None` where it throws.
fn decode_uri_component(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        if c == b'%' {
            let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(c);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes() {
        for _ in 0..50 {
            let c = generate_code();
            assert_eq!(normalize_code(&c).unwrap(), c);
        }
        assert_eq!(format_code("7k2m9qxz").unwrap(), "7K2M-9QXZ");
        assert!(normalize_code("7K2M9QXU").is_err(), "U is not Crockford");
        assert!(normalize_code("7K2M9QX").is_err());
        assert!(normalize_code("7K2M9QXZ0").is_err());
        assert!(normalize_code("7K2M9QXé").is_err());
    }

    #[test]
    fn links() {
        assert!(parse_pairing_link("frontier://pair?v=1&v=1").is_err());
        assert!(parse_pairing_link("https://pair?v=1").is_err());
        let ok = "frontier://pair?v=1&n=ixldtk3yi32p4qs53iko7652ae&c=7K2M-9QXZ&i=AQIDBAUGBwg&r=ws%3A%2F%2F127.0.0.1%3A9%2Fv1";
        let l = parse_pairing_link(ok).unwrap();
        assert_eq!(l.code, "7K2M9QXZ");
        assert_eq!(l.relay, "ws://127.0.0.1:9/v1");
        assert!(parse_pairing_link(&ok.replace("ws%3A", "http%3A")).is_err());
        assert!(parse_pairing_link(&ok.replace("%3A%2F", "%E0%2F")).is_err(), "invalid UTF-8");
        assert!(parse_pairing_link(&ok.replace("%3A%2F", "%3")).is_err());
        assert_eq!(encode_uri_component("a b/é~"), "a%20b%2F%C3%A9~");
    }
}
