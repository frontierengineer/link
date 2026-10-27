//! The roster (section 3): the signed list of a network's members. The network key signs it,
//! held by the primary alone (section 3.1); every member checks it against the network key it
//! pinned.
//!
//! A [`Roster`] value is always valid: the only ways to make one validate it. It keeps the JSON
//! it was made from, members it does not know included, since the signature covers all of it.

use crate::bytes::{b64u, from_b64u_array};
use crate::crypto::ed25519_verify;
use crate::errors::LinkError;
use crate::identity::{Identity, NetworkKey, node_id_from_ed25519, node_id_to_bytes};
use crate::json::Json;

/// The most a roster's JCS encoding, signature included, may take (section 3): one session message.
pub const MAX_ROSTER_BYTES: usize = 65000;

const ROSTER_LABEL: &[u8] = b"frontier-link/1/roster";

/// One roster entry. Its id is always the one its Ed25519 key derives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RosterMember {
    id: String,
    ed25519: [u8; 32],
    x25519: [u8; 32],
}

impl RosterMember {
    pub fn new(ed25519: [u8; 32], x25519: [u8; 32]) -> RosterMember {
        RosterMember { id: node_id_from_ed25519(&ed25519), ed25519, x25519 }
    }

    pub fn from_identity(identity: &Identity) -> RosterMember {
        RosterMember::new(identity.ed25519_public(), identity.x25519_public())
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

    fn to_json(&self) -> Json {
        Json::object([
            ("id", Json::str(&self.id)),
            ("ed25519", Json::str(b64u(&self.ed25519))),
            ("x25519", Json::str(b64u(&self.x25519))),
        ])
    }
}

/// A roster before the network key signs it. [`sign_roster`] sorts the members.
#[derive(Clone, Debug)]
pub struct UnsignedRoster {
    pub network: String,
    pub version: u64,
    pub issued_at: u64,
    pub relay: String,
    /// The network key's public half; `network` is derived from it.
    pub network_key: [u8; 32],
    /// The primary's node id: one of `members`.
    pub primary: String,
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
    network_key: [u8; 32],
    primary: String,
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

    /// Whether the network is placed: the roster names a relay (section 3.2). A roster whose
    /// `relay` is `""` is valid, but no member dials it until it is placed.
    pub fn is_placed(&self) -> bool {
        !self.relay.is_empty()
    }

    /// `networkKey`, raw.
    pub fn network_key(&self) -> &[u8; 32] {
        &self.network_key
    }

    /// `networkKey` as the roster writes it (b64u): what a member pins.
    pub fn network_key_b64u(&self) -> String {
        b64u(&self.network_key)
    }

    /// The member `primary` names: the one holding the network seed (section 3.1).
    pub fn primary(&self) -> &RosterMember {
        // A valid roster's `primary` is one of its members.
        self.member(&self.primary).unwrap_or(&self.members[0])
    }

    /// `primary`: the primary's node id.
    pub fn primary_id(&self) -> &str {
        &self.primary
    }

    /// Sorted by id.
    pub fn members(&self) -> &[RosterMember] {
        &self.members
    }

    pub fn member(&self, id: &str) -> Option<&RosterMember> {
        self.members.binary_search_by(|m| m.id.as_str().cmp(id)).ok().and_then(|i| self.members.get(i))
    }
}

/// The bytes the network key signs: the label followed by JCS of the roster without `signature`.
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

/// Section 3 acceptance: valid, signed by the pinned network key (b64u), and newer than the
/// version held. Returns the reason for refusal, or `None` to accept.
pub fn acceptance_problem(candidate: &Json, pinned_network_key: &str, held_version: u64) -> Option<String> {
    let r = match check(candidate) {
        Ok(r) => r,
        Err(e) => return Some(e),
    };
    if b64u(&r.network_key) != pinned_network_key {
        return Some("roster is signed by another network key".into());
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
        return Err("network is not an id".into());
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
    let network_key = key_field(value.get("networkKey"), "networkKey")?;
    if node_id_from_ed25519(&network_key) != network {
        return Err("network is not derived from networkKey".into());
    }
    let Some(list) = value.get("members").and_then(Json::as_array) else {
        return Err("members is not an array".into());
    };
    let mut members: Vec<RosterMember> = Vec::with_capacity(list.len());
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
        // Members a later version adds (any other field) are signed over and otherwise ignored.
        members.push(RosterMember { id: id.to_owned(), ed25519: ed, x25519: x });
    }
    let Some(primary) = value.get("primary").and_then(Json::as_str).filter(|s| node_id_to_bytes(s).is_some()) else {
        return Err("primary is not a node id".into());
    };
    if !members.iter().any(|m| m.id == primary) {
        return Err("primary is not a member".into());
    }
    let size = value.canonicalize().map_err(|e| e.to_string())?.len();
    if size > MAX_ROSTER_BYTES {
        return Err(format!("roster is {size} bytes, over the {MAX_ROSTER_BYTES}-byte limit"));
    }
    let signature = value.get("signature").and_then(Json::as_str).ok_or("signature: not a string")?;
    let signature = from_b64u_array::<64>(signature).ok_or("signature: expected 64 bytes")?;
    let signed = roster_signing_bytes(value)?;
    if !ed25519_verify(&network_key, &signed, &signature) {
        return Err("signature does not verify".into());
    }
    Ok(Roster {
        json: Json::Null,
        network: network.to_owned(),
        version,
        issued_at,
        relay: relay.to_owned(),
        network_key,
        primary: primary.to_owned(),
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
        ("networkKey", Json::str(b64u(&unsigned.network_key))),
        ("primary", Json::str(&unsigned.primary)),
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

/// Sorts the members, then signs with the network key; the result must be a valid roster, or
/// this fails with the reason.
pub fn sign_roster(unsigned: &UnsignedRoster, network_key: &NetworkKey) -> Result<Roster, String> {
    let mut j = unsigned_json(unsigned);
    let signature = network_key.sign(&roster_signing_bytes(&j)?);
    if let Json::Object(m) = &mut j {
        m.push(("signature".into(), Json::str(b64u(&signature))));
    }
    Roster::from_json(j).map_err(|e| format!("sign_roster: {e}"))
}

/// A new network (section 3.1): a network seed minted for it, apart from the node's own, and its
/// first roster, version 1, with `identity` alone as the primary, issued at `now_ms`. Persist the
/// network key's seed as secretly as the node's, and hand it to the primary as
/// `MemberOptions::network_seed`.
pub fn create_network(identity: &Identity, relay: &str, now_ms: u64) -> Result<(Roster, NetworkKey), String> {
    let key = NetworkKey::generate();
    let roster = create_network_with(identity, &key, relay, now_ms)?;
    Ok((roster, key))
}

/// The first roster of the network `key` names: version 1, `identity` alone as the primary.
pub fn create_network_with(identity: &Identity, key: &NetworkKey, relay: &str, now_ms: u64) -> Result<Roster, String> {
    sign_roster(
        &UnsignedRoster {
            network: key.id().to_owned(),
            version: 1,
            issued_at: now_ms,
            relay: relay.to_owned(),
            network_key: key.ed25519_public(),
            primary: identity.id().to_owned(),
            members: vec![RosterMember::from_identity(identity)],
        },
        key,
    )
}

/// What [`create_network_with_options`] takes besides the primary's identity.
#[derive(Clone, Debug, Default)]
pub struct NetworkOptions {
    /// The relay URL the network's members dial, or `""` (the default) for a network not placed
    /// yet (section 3.2): no member dials it until [`place_network`] gives it one.
    pub relay: String,
    /// Listed in version 1 alongside the primary.
    pub members: Vec<RosterMember>,
    /// The roster's `issuedAt`, Unix milliseconds; `None` for the current time.
    pub now_ms: Option<u64>,
    /// The network's seed; `None` mints one.
    pub network_seed: Option<[u8; 32]>,
}

/// A new network (section 3.1), as [`create_network`] makes one, with the relay optional and other
/// members listed in version 1 beside `identity`, the primary. Persist the network key's seed as
/// secretly as the node's, and hand it to the primary as `MemberOptions::network_seed`. Fails
/// `Invalid` for a member listed twice (the primary included) or a timestamp over 2^53 - 1, and
/// `RosterFull` over 65000 bytes.
pub fn create_network_with_options(
    identity: &Identity,
    opts: NetworkOptions,
) -> Result<(Roster, NetworkKey), LinkError> {
    let now_ms = opts.now_ms.unwrap_or_else(crate::unix_ms);
    if now_ms > MAX_SAFE_INTEGER {
        return Err(LinkError::invalid("createNetwork: now must be a non-negative integer of Unix milliseconds"));
    }
    let mut members = vec![RosterMember::from_identity(identity)];
    for m in opts.members {
        if members.iter().any(|x| x.id == m.id) {
            return Err(LinkError::invalid(format!("createNetwork: member {} is listed twice", m.id)));
        }
        members.push(m);
    }
    let key = match opts.network_seed {
        Some(seed) => NetworkKey::from_seed(&seed),
        None => NetworkKey::generate(),
    };
    let unsigned = UnsignedRoster {
        network: key.id().to_owned(),
        version: 1,
        issued_at: now_ms,
        relay: opts.relay,
        network_key: key.ed25519_public(),
        primary: identity.id().to_owned(),
        members,
    };
    let size = signed_size(&unsigned);
    if size > MAX_ROSTER_BYTES {
        return Err(LinkError::roster_full(size));
    }
    let roster = sign_roster(&unsigned, &key).map_err(LinkError::invalid)?;
    Ok((roster, key))
}

const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Whether `s` is a relay URL as placing a network takes it (section 3.2): it begins `ws://` or
/// `wss://`, in lower case, followed at once by a host (the text before the next `/`, `?` or `#`
/// is not empty), and it parses as a URL.
pub fn is_relay_url(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("ws://").or_else(|| s.strip_prefix("wss://")) else {
        return false;
    };
    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    host_end > 0 && url::Url::parse(s).is_ok()
}

/// Places a network (section 3.2): the roster after `roster`, an unplaced one, with `relay` set
/// and nothing else changed (version + 1, `issuedAt` the later of `now_ms`, or the current time,
/// and the roster's), signed with the network key `network_seed` derives. Publish it as any new
/// roster: a primary started on it presents it at registration. Fails `Invalid` when the network
/// is placed already, when `relay` is not a ws:// or wss:// URL ([`is_relay_url`]), or when
/// `network_seed` does not derive the roster's network key.
pub fn place_network(
    roster: &Roster,
    network_seed: &[u8; 32],
    relay: &str,
    now_ms: Option<u64>,
) -> Result<Roster, LinkError> {
    if roster.is_placed() {
        return Err(LinkError::invalid("placeNetwork: the network is placed already"));
    }
    if !is_relay_url(relay) {
        return Err(LinkError::invalid("placeNetwork: relay must be a ws:// or wss:// URL"));
    }
    let key = NetworkKey::from_seed(network_seed);
    if &key.ed25519_public() != roster.network_key() {
        return Err(LinkError::invalid("placeNetwork: the network seed does not derive the roster's network key"));
    }
    let now_ms = now_ms.unwrap_or_else(crate::unix_ms);
    if now_ms > MAX_SAFE_INTEGER {
        return Err(LinkError::invalid("placeNetwork: now must be a non-negative integer of Unix milliseconds"));
    }
    // Everything else as signed, fields the protocol does not define included.
    let Json::Object(fields) = roster.json() else {
        return Err(LinkError::invalid("placeNetwork: the roster is not an object"));
    };
    let mut fields: Vec<(String, Json)> = fields.iter().filter(|(k, _)| k != "signature").cloned().collect();
    for (k, v) in &mut fields {
        match k.as_str() {
            "version" => *v = Json::int(roster.version() + 1),
            "issuedAt" => *v = Json::int(now_ms.max(roster.issued_at())),
            "relay" => *v = Json::str(relay),
            _ => {}
        }
    }
    let mut probe = fields.clone();
    probe.push(("signature".into(), Json::str("A".repeat(86))));
    let size = Json::Object(probe).canonicalize().map_err(|e| LinkError::invalid(e.to_string()))?.len();
    if size > MAX_ROSTER_BYTES {
        return Err(LinkError::roster_full(size));
    }
    let unsigned = Json::Object(fields.clone());
    let signature = key.sign(&roster_signing_bytes(&unsigned).map_err(LinkError::invalid)?);
    fields.push(("signature".into(), Json::str(b64u(&signature))));
    Roster::from_json(Json::Object(fields)).map_err(|e| LinkError::invalid(format!("placeNetwork: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_network_signs_validates_and_round_trips() {
        let p = Identity::from_seed(&[1; 32]);
        let (r, key) = create_network(&p, "wss://relay.example/v1", 1_790_000_000_000).unwrap();
        // The network id comes from the network's own seed, not from the primary's node id.
        assert_eq!(r.network(), key.id());
        assert_ne!(r.network(), p.id());
        assert_eq!(r.network_key(), &key.ed25519_public());
        assert_eq!(r.primary_id(), p.id());
        assert_eq!(r.version(), 1);
        assert_eq!(r.members().len(), 1);
        let again = Roster::parse(&r.json().to_json_string().unwrap()).unwrap();
        assert_eq!(again, r);
        assert_eq!(acceptance_problem(r.json(), &r.network_key_b64u(), 0), None);
        assert!(acceptance_problem(r.json(), &r.network_key_b64u(), 1).is_some());
        let mut size_probe = UnsignedRoster {
            network: key.id().into(),
            version: 1,
            issued_at: 1_790_000_000_000,
            relay: "wss://relay.example/v1".into(),
            network_key: key.ed25519_public(),
            primary: p.id().into(),
            members: vec![RosterMember::from_identity(&p)],
        };
        assert_eq!(signed_size(&size_probe), r.size());
        size_probe.members.push(RosterMember::from_identity(&Identity::from_seed(&[2; 32])));
        let two = sign_roster(&size_probe, &key).unwrap();
        assert_eq!(signed_size(&size_probe), two.size());
        assert!(two.member(Identity::from_seed(&[2; 32]).id()).is_some());
    }

    #[test]
    fn extra_members_are_signed_over_and_kept() {
        let p = Identity::from_seed(&[1; 32]);
        let (r, key) = create_network(&p, "wss://relay.example/v1", 5).unwrap();
        let Json::Object(mut m) = r.json().clone() else { panic!() };
        m.retain(|(k, _)| k != "signature");
        m.push(("future".into(), Json::Array(vec![Json::float(1.5), Json::Null])));
        let unsigned = Json::Object(m.clone());
        let sig = key.sign(&roster_signing_bytes(&unsigned).unwrap());
        m.push(("signature".into(), Json::str(b64u(&sig))));
        let extended = Roster::from_json(Json::Object(m.clone())).unwrap();
        assert!(extended.to_jcs().contains("\"future\":[1.5,null]"));
        // Changing the unknown member breaks the signature.
        if let Some((_, v)) = m.iter_mut().find(|(k, _)| k == "future") {
            *v = Json::Null;
        }
        assert_eq!(roster_problem(&Json::Object(m)).as_deref(), Some("signature does not verify"));
    }

    #[test]
    fn the_network_key_signs_whoever_is_primary_and_a_node_key_never_does() {
        let (p, w) = (Identity::from_seed(&[1; 32]), Identity::from_seed(&[2; 32]));
        let key = NetworkKey::from_seed(&[0x80; 32]);
        let claimed = UnsignedRoster {
            network: key.id().into(),
            version: 2,
            issued_at: 5,
            relay: "wss://relay.example/v1".into(),
            network_key: key.ed25519_public(),
            primary: w.id().into(),
            members: vec![RosterMember::from_identity(&p), RosterMember::from_identity(&w)],
        };
        // Once another node is primary, the primary is not the node that created the network:
        // still valid.
        let r = sign_roster(&claimed, &key).unwrap();
        assert_eq!(r.primary_id(), w.id());
        // Signed by the primary's own node key, it is not.
        let mut j = unsigned_json(&claimed);
        let sig = w.sign(&roster_signing_bytes(&j).unwrap());
        if let Json::Object(m) = &mut j {
            m.push(("signature".into(), Json::str(b64u(&sig))));
        }
        assert_eq!(roster_problem(&j).as_deref(), Some("signature does not verify"));
        // A network seed is not a node seed: the two derive different keys.
        assert_ne!(NetworkKey::from_seed(&[1; 32]).ed25519_public(), p.ed25519_public());
    }

    #[test]
    fn primary_must_name_a_member_and_a_members_unknown_kind_is_ignored() {
        let (p, w) = (Identity::from_seed(&[1; 32]), Identity::from_seed(&[2; 32]));
        let key = NetworkKey::from_seed(&[0x80; 32]);
        type Edit<'a> = &'a dyn Fn(&mut Vec<(String, Json)>);
        let signed = |edit: Edit| {
            let unsigned = UnsignedRoster {
                network: key.id().into(),
                version: 2,
                issued_at: 5,
                relay: "wss://relay.example/v1".into(),
                network_key: key.ed25519_public(),
                primary: p.id().into(),
                members: vec![RosterMember::from_identity(&p)],
            };
            let Json::Object(mut m) = unsigned_json(&unsigned) else { panic!() };
            edit(&mut m);
            let sig = key.sign(&roster_signing_bytes(&Json::Object(m.clone())).unwrap());
            m.push(("signature".into(), Json::str(b64u(&sig))));
            Json::Object(m)
        };
        let set = |k: &'static str, v: Json| {
            move |m: &mut Vec<(String, Json)>| {
                m.retain(|(x, _)| x != k);
                m.push((k.into(), v.clone()));
            }
        };
        assert_eq!(roster_problem(&signed(&|_| {})), None);
        assert_eq!(
            roster_problem(&signed(&set("primary", Json::str(w.id())))).as_deref(),
            Some("primary is not a member")
        );
        assert_eq!(
            roster_problem(&signed(&|m| m.retain(|(k, _)| k != "primary"))).as_deref(),
            Some("primary is not a node id")
        );
        assert_eq!(
            roster_problem(&signed(&set("primary", Json::str("x")))).as_deref(),
            Some("primary is not a node id")
        );
        // A member carrying a field this version does not know (`kind`, say) is signed over and
        // otherwise ignored.
        let with_kind = signed(&|m| {
            if let Some((_, Json::Array(ms))) = m.iter_mut().find(|(k, _)| k == "members")
                && let Some(Json::Object(first)) = ms.first_mut()
            {
                first.push(("kind".into(), Json::str("label")));
            }
        });
        let r = Roster::from_json(with_kind).unwrap();
        assert_eq!(r.primary_id(), p.id());
        assert!(r.to_jcs().contains("\"kind\":\"label\""));
    }
}
