//! The two signed statements besides the roster: registration (section 4.1) and resignation
//! (section 7.3).

use url::Url;

use crate::bytes::{b64u, from_b64u_array, len_str, u64be};
use crate::crypto::ed25519_verify;
use crate::identity::Identity;
use crate::json::Json;

/// The lowercased `host[:port]` of a dialled URL, with the port omitted when it is 80 or 443
/// whatever the scheme (section 4.1), as the relay compares it. The URL is parsed as WHATWG
/// URL parsing does, as the TypeScript client's `new URL` does.
pub fn origin_of(url: &str) -> Result<String, String> {
    let u = Url::parse(url).map_err(|e| format!("not a URL: {e}"))?;
    if !matches!(u.scheme(), "ws" | "wss" | "http" | "https") {
        return Err(format!("unsupported relay URL scheme: {}:", u.scheme()));
    }
    let host = u.host_str().ok_or("the relay URL has no host")?;
    let origin = match u.port_or_known_default() {
        Some(80) | Some(443) | None => host.to_owned(),
        Some(p) => format!("{host}:{p}"),
    };
    Ok(origin.to_lowercase())
}

/// `lenStr("frontier-link/1/register") || lenStr(network) || lenStr(node) || challenge ||
/// u64be(ts) || lenStr(origin)`.
pub fn register_signing_bytes(network: &str, node: &str, challenge: &[u8; 32], ts: u64, origin: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(128 + origin.len());
    len_str(&mut out, "frontier-link/1/register");
    len_str(&mut out, network);
    len_str(&mut out, node);
    out.extend_from_slice(challenge);
    out.extend_from_slice(&u64be(ts));
    len_str(&mut out, origin);
    out
}

/// `lenStr("frontier-link/1/resign") || lenStr(network) || lenStr(node) || u64be(ts)`.
pub fn resign_signing_bytes(network: &str, node: &str, ts: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    len_str(&mut out, "frontier-link/1/resign");
    len_str(&mut out, network);
    len_str(&mut out, node);
    out.extend_from_slice(&u64be(ts));
    out
}

/// A member's signed resignation, as the `resign` session message carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resignation {
    pub node: String,
    pub ts: u64,
    pub sig: String,
}

impl Resignation {
    pub fn sign(identity: &Identity, network: &str, ts: u64) -> Resignation {
        let sig = identity.sign(&resign_signing_bytes(network, identity.id(), ts));
        Resignation { node: identity.id().to_owned(), ts, sig: b64u(&sig) }
    }

    /// `{"node":..,"ts":..,"sig":..}`.
    pub fn to_json(&self) -> Json {
        Json::object([("node", Json::str(&self.node)), ("ts", Json::int(self.ts)), ("sig", Json::str(&self.sig))])
    }

    /// From the JSON of a `resign` message: an object with a string `node`, a `ts` that is a
    /// non-negative safe integer and a string `sig`.
    pub fn from_json(v: &Json) -> Option<Resignation> {
        Some(Resignation {
            node: v.get("node")?.as_str()?.to_owned(),
            ts: v.get("ts")?.as_safe_uint()?,
            sig: v.get("sig")?.as_str()?.to_owned(),
        })
    }

    pub fn verify(&self, network: &str, ed25519: &[u8; 32]) -> bool {
        let Some(sig) = from_b64u_array::<64>(&self.sig) else {
            return false;
        };
        ed25519_verify(ed25519, &resign_signing_bytes(network, &self.node, self.ts), &sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_resignation_ts_is_an_integer_literal() {
        let ok = Json::parse(r#"{"node":"n","ts":1790000000000,"sig":"s"}"#).unwrap();
        assert_eq!(Resignation::from_json(&ok).map(|r| r.ts), Some(1_790_000_000_000));
        for bad in [r#"{"node":"n","ts":1.79e12,"sig":"s"}"#, r#"{"node":"n","ts":1790000000000.0,"sig":"s"}"#] {
            assert!(Resignation::from_json(&Json::parse(bad).unwrap()).is_none(), "{bad}");
        }
    }

    #[test]
    fn origins() {
        assert_eq!(origin_of("wss://FrontierEngineer.link/v1").unwrap(), "frontierengineer.link");
        assert_eq!(origin_of("wss://frontierengineer.link:443/v1").unwrap(), "frontierengineer.link");
        assert_eq!(origin_of("ws://127.0.0.1:443/v1").unwrap(), "127.0.0.1");
        assert_eq!(origin_of("wss://h:80/v1").unwrap(), "h");
        assert_eq!(origin_of("ws://127.0.0.1:8080/v1").unwrap(), "127.0.0.1:8080");
        assert_eq!(origin_of("ws://[::1]:9000/v1").unwrap(), "[::1]:9000");
        // A non-ASCII host as WHATWG URL parsing (and so the TypeScript client) writes it.
        assert_eq!(origin_of("wss://Relé.example:443/v1").unwrap(), "xn--rel-dma.example");
        assert_eq!(origin_of("wss://Relé.example:8443/v1").unwrap(), "xn--rel-dma.example:8443");
        assert!(origin_of("ftp://x/").is_err());
        assert!(origin_of("not a url").is_err());
    }
}
