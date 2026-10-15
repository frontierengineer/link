//! The roster (section 3): the signed list of a network's members. Only the primary signs it;
//! every member checks it against the primary key it pinned.
//!
//! A [`Roster`] value is always valid: the only ways to make one validate it. It keeps the JSON
//! it was made from, members it does not know included, since the signature covers all of it.

use std::fmt;

use crate::bytes::{b64u, from_b64u_array};
use crate::crypto::ed25519_verify;
use crate::identity::{Identity, node_id_from_ed25519, node_id_to_bytes};
use crate::json::Json;

/// The most a roster's JCS encoding, signature included, may take (section 3): one session message.
pub const MAX_ROSTER_BYTES: usize = 65000;

const ROSTER_LABEL: &[u8] = b"frontier-link/1/roster";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MemberKind {
    Primary,
    Worker,
    Surface,
    Mcp,
}

impl MemberKind {
    pub fn as_str(self) -> &'static str {
        match self {
            MemberKind::Primary => "primary",
            MemberKind::Worker => "worker",
            MemberKind::Surface => "surface",
            MemberKind::Mcp => "mcp",
        }
    }

    pub fn parse(s: &str) -> Option<MemberKind> {
        match s {
            "primary" => Some(MemberKind::Primary),
            "worker" => Some(MemberKind::Worker),
            "surface" => Some(MemberKind::Surface),
            "mcp" => Some(MemberKind::Mcp),
            _ => None,
        }
    }

    /// The kinds a pairing code may admit: every kind but `primary`.
    pub fn is_pairing_kind(self) -> bool {
        self != MemberKind::Primary
    }
}

impl fmt::Display for MemberKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One roster entry. Its id is always the one its Ed25519 key derives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RosterMember {
    id: String,
    ed25519: [u8; 32],
    x25519: [u8; 32],
    kind: MemberKind,
}

impl RosterMember {
    pub fn new(kind: MemberKind, ed25519: [u8; 32], x25519: [u8; 32]) -> RosterMember {
        RosterMember { id: node_id_from_ed25519(&ed25519), ed25519, x25519, kind }
    }

    pub fn from_identity(identity: &Identity, kind: MemberKind) -> RosterMember {
        RosterMember::new(kind, identity.ed25519_public(), identity.x25519_public())
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn ed25519(&self) -> &[u8; 32] {
        &self.ed25519
    }

    pub fn x25519(&self) -> &[u8; 32] {
        &self.x25519
    }

    pub fn kind(&self) -> MemberKind {
        self.kind
    }

    fn to_json(&self) -> Json {
        Json::object([
            ("id", Json::str(&self.id)),
            ("ed25519", Json::str(b64u(&self.ed25519))),
            ("x25519", Json::str(b64u(&self.x25519))),
            ("kind", Json::str(self.kind.as_str())),
        ])
    }
}

/// A roster before the primary signs it. [`sign_roster`] sorts the members.
#[derive(Clone, Debug)]
pub struct UnsignedRoster {
    pub network: String,
    pub version: u64,
    pub issued_at: u64,
    pub relay: String,
    /// The primary's Ed25519 public key.
    pub primary: [u8; 32],
    pub members: Vec<RosterMember>,
}

/// A valid roster.
#[derive(Clone, Debug, PartialEq)]
pub struct Roster {
    json: Json,
    network: String,
    version: u64,
    issued_at: u64,
    relay: String,
    primary: [u8; 32],
    members: Vec<RosterMember>,
}

impl Roster {
    /// Validates `value` (section 3, "Valid").
    pub fn from_json(value: Json) -> Result<Roster, String> {
        let parsed = check(&value)?;
        Ok(Roster { json: value, ..parsed })
    }

    /// Parses and validates a roster's JSON text.
    pub fn parse(text: &str) -> Result<Roster, String> {
        Roster::from_json(Json::parse(text).map_err(|e| e.to_string())?)
    }

    /// The roster's JSON, signature included, exactly as it was received or signed.
    pub fn json(&self) -> &Json {
        &self.json
    }

    /// The roster's JCS encoding, signature included.
    pub fn to_jcs(&self) -> String {
        // A valid roster's numbers are finite, so canonicalisation cannot fail.
        self.json.canonicalize().unwrap_or_default()
    }

    /// The length of the JCS encoding, signature included.
    pub fn size(&self) -> usize {
        self.to_jcs().len()
    }

    pub fn network(&self) -> &str {
        &self.network
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    /// Unix milliseconds.
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub fn relay(&self) -> &str {
        &self.relay
    }

    /// `primary.ed25519`, raw.
    pub fn primary_key(&self) -> &[u8; 32] {
        &self.primary
    }

    /// `primary.ed25519` as the roster writes it (b64u): what a member pins.
    pub fn primary_ed25519(&self) -> String {
        b64u(&self.primary)
    }

    /// Sorted by id.
    pub fn members(&self) -> &[RosterMember] {
        &self.members
    }

    pub fn member(&self, id: &str) -> Option<&RosterMember> {
        self.members.binary_search_by(|m| m.id.as_str().cmp(id)).ok().and_then(|i| self.members.get(i))
    }
}

/// The bytes the primary signs: the label followed by JCS of the roster without `signature`.
pub fn roster_signing_bytes(value: &Json) -> Result<Vec<u8>, String> {
    let Json::Object(members) = value else {
        return Err("not an object".into());
    };
    let unsigned = Json::Object(members.iter().filter(|(k, _)| k != "signature").cloned().collect());
    let jcs = unsigned.canonicalize().map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(ROSTER_LABEL.len() + jcs.len());
    out.extend_from_slice(ROSTER_LABEL);
    out.extend_from_slice(jcs.as_bytes());
    Ok(out)
}

/// Why `value` is not a valid roster, or `None` when it is (section 3, "Valid").
pub fn roster_problem(value: &Json) -> Option<String> {
    check(value).err()
}

/// Section 3 acceptance: valid, signed by the pinned primary key (b64u), and newer than the
/// version held. Returns the reason for refusal, or `None` to accept.
pub fn acceptance_problem(candidate: &Json, pinned_primary: &str, held_version: u64) -> Option<String> {
    let r = match check(candidate) {
        Ok(r) => r,
        Err(e) => return Some(e),
    };
    if b64u(&r.primary) != pinned_primary {
        return Some("roster is signed by a different primary".into());
    }
    if r.version <= held_version {
        return Some("roster is not newer than the one held".into());
    }
    None
}

fn key_field(v: Option<&Json>, what: &str) -> Result<[u8; 32], String> {
    let s = v.and_then(Json::as_str).ok_or_else(|| format!("{what}: not a string"))?;
    from_b64u_array::<32>(s).ok_or_else(|| format!("{what}: expected 32 bytes"))
}

/// Every rule of section 3, in the order the TypeScript client checks them. The returned
/// roster's `json` is a placeholder the caller replaces.
fn check(value: &Json) -> Result<Roster, String> {
    if value.as_object().is_none() {
        return Err("not an object".into());
    }
    let network = value.get("network").and_then(Json::as_str).filter(|s| node_id_to_bytes(s).is_some());
    let Some(network) = network else {
        return Err("network is not a node id".into());
    };
    let version = value.get("version").and_then(Json::as_safe_uint).filter(|v| *v >= 1);
    let Some(version) = version else {
        return Err("version is not a positive integer".into());
    };
    let Some(issued_at) = value.get("issuedAt").and_then(Json::as_safe_uint) else {
        return Err("issuedAt is not a non-negative integer".into());
    };
    let Some(relay) = value.get("relay").and_then(Json::as_str) else {
        return Err("relay is not a string".into());
    };
    let Some(primary_obj) = value.get("primary").filter(|p| p.as_object().is_some()) else {
        return Err("primary is not an object".into());
    };
    let primary = key_field(primary_obj.get("ed25519"), "primary.ed25519")?;
    if node_id_from_ed25519(&primary) != network {
        return Err("network is not derived from primary.ed25519".into());
    }
    let Some(list) = value.get("members").and_then(Json::as_array) else {
        return Err("members is not an array".into());
    };
    let mut members: Vec<RosterMember> = Vec::with_capacity(list.len());
    let mut primaries = 0;
    for m in list {
        if m.as_object().is_none() {
            return Err("member is not an object".into());
        }
        let Some(id) = m.get("id").and_then(Json::as_str).filter(|s| node_id_to_bytes(s).is_some()) else {
            return Err("member id is not a node id".into());
        };
        if members.last().is_some_and(|prev| prev.id.as_str() >= id) {
            return Err("members are not sorted by id (or repeat)".into());
        }
        let ed = key_field(m.get("ed25519"), "member ed25519")?;
        let x = key_field(m.get("x25519"), "member x25519")?;
        if node_id_from_ed25519(&ed) != id {
            return Err(format!("member {id}: id is not derived from its ed25519"));
        }
        let Some(kind) = m.get("kind").and_then(Json::as_str).and_then(MemberKind::parse) else {
            return Err(format!("member {id}: bad kind"));
        };
        if kind == MemberKind::Primary {
            primaries += 1;
            if ed != primary {
                return Err("primary member key differs from primary.ed25519".into());
            }
            if id != network {
                return Err("primary member id differs from network".into());
            }
        }
        members.push(RosterMember { id: id.to_owned(), ed25519: ed, x25519: x, kind });
    }
    if primaries != 1 {
        return Err("roster must have exactly one primary member".into());
    }
    let size = value.canonicalize().map_err(|e| e.to_string())?.len();
    if size > MAX_ROSTER_BYTES {
        return Err(format!("roster is {size} bytes, over the {MAX_ROSTER_BYTES}-byte limit"));
    }
    let signature = value.get("signature").and_then(Json::as_str).ok_or("signature: not a string")?;
    let signature = from_b64u_array::<64>(signature).ok_or("signature: expected 64 bytes")?;
    let signed = roster_signing_bytes(value)?;
    if !ed25519_verify(&primary, &signed, &signature) {
        return Err("signature does not verify".into());
    }
    Ok(Roster {
        json: Json::Null,
        network: network.to_owned(),
        version,
        issued_at,
        relay: relay.to_owned(),
        primary,
        members,
    })
}

/// The JSON of an unsigned roster, members sorted, in the TypeScript client's member order.
fn unsigned_json(unsigned: &UnsignedRoster) -> Json {
    let mut members = unsigned.members.clone();
    members.sort_by(|a, b| a.id.cmp(&b.id));
    Json::object([
        ("network", Json::str(&unsigned.network)),
        ("version", Json::int(unsigned.version)),
        ("issuedAt", Json::int(unsigned.issued_at)),
        ("relay", Json::str(&unsigned.relay)),
        ("primary", Json::object([("ed25519", Json::str(b64u(&unsigned.primary)))])),
        ("members", Json::Array(members.iter().map(RosterMember::to_json).collect())),
    ])
}

/// The JCS size the roster would have once signed (a signature is always 86 b64u characters).
pub fn signed_size(unsigned: &UnsignedRoster) -> usize {
    let mut j = unsigned_json(unsigned);
    if let Json::Object(m) = &mut j {
        m.push(("signature".into(), Json::str("A".repeat(86))));
    }
    j.canonicalize().map(|s| s.len()).unwrap_or(usize::MAX)
}

/// Sorts the members, then signs. `primary` must be the roster's primary identity; the result
/// must be a valid roster, or this fails with the reason.
pub fn sign_roster(unsigned: &UnsignedRoster, primary: &Identity) -> Result<Roster, String> {
    let mut j = unsigned_json(unsigned);
    let signature = primary.sign(&roster_signing_bytes(&j)?);
    if let Json::Object(m) = &mut j {
        m.push(("signature".into(), Json::str(b64u(&signature))));
    }
    Roster::from_json(j).map_err(|e| format!("sign_roster: {e}"))
}

/// The first roster of a new network: version 1, the primary alone, issued at `now_ms`.
pub fn create_network(identity: &Identity, relay: &str, now_ms: u64) -> Result<Roster, String> {
    sign_roster(
        &UnsignedRoster {
            network: identity.id().to_owned(),
            version: 1,
            issued_at: now_ms,
            relay: relay.to_owned(),
            primary: identity.ed25519_public(),
            members: vec![RosterMember::from_identity(identity, MemberKind::Primary)],
        },
        identity,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_network_signs_validates_and_round_trips() {
        let p = Identity::from_seed(&[1; 32]);
        let r = create_network(&p, "wss://relay.example/v1", 1_790_000_000_000).unwrap();
        assert_eq!(r.network(), p.id());
        assert_eq!(r.version(), 1);
        assert_eq!(r.members().len(), 1);
        let again = Roster::parse(&r.json().to_json_string().unwrap()).unwrap();
        assert_eq!(again, r);
        assert_eq!(acceptance_problem(r.json(), &r.primary_ed25519(), 0), None);
        assert!(acceptance_problem(r.json(), &r.primary_ed25519(), 1).is_some());
        let mut size_probe = UnsignedRoster {
            network: p.id().into(),
            version: 1,
            issued_at: 1_790_000_000_000,
            relay: "wss://relay.example/v1".into(),
            primary: p.ed25519_public(),
            members: vec![RosterMember::from_identity(&p, MemberKind::Primary)],
        };
        assert_eq!(signed_size(&size_probe), r.size());
        size_probe.members.push(RosterMember::from_identity(&Identity::from_seed(&[2; 32]), MemberKind::Worker));
        let two = sign_roster(&size_probe, &p).unwrap();
        assert_eq!(signed_size(&size_probe), two.size());
        assert!(two.member(Identity::from_seed(&[2; 32]).id()).is_some());
    }

    #[test]
    fn extra_members_are_signed_over_and_kept() {
        let p = Identity::from_seed(&[1; 32]);
        let r = create_network(&p, "wss://relay.example/v1", 5).unwrap();
        let Json::Object(mut m) = r.json().clone() else { panic!() };
        m.retain(|(k, _)| k != "signature");
        m.push(("future".into(), Json::Array(vec![Json::float(1.5), Json::Null])));
        let unsigned = Json::Object(m.clone());
        let sig = p.sign(&roster_signing_bytes(&unsigned).unwrap());
        m.push(("signature".into(), Json::str(b64u(&sig))));
        let extended = Roster::from_json(Json::Object(m.clone())).unwrap();
        assert!(extended.to_jcs().contains("\"future\":[1.5,null]"));
        // Changing the unknown member breaks the signature.
        if let Some((_, v)) = m.iter_mut().find(|(k, _)| k == "future") {
            *v = Json::Null;
        }
        assert_eq!(roster_problem(&Json::Object(m)).as_deref(), Some("signature does not verify"));
    }
}
