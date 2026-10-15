//! The pairing exchange of section 5.3 as two transport-agnostic state machines. The relay
//! plumbing around them lives in `newcomer.rs` (A) and the node core (B).

use zeroize::Zeroizing;

use crate::bytes::{b64u, from_b64u_array};
use crate::crypto::{hkdf_array, open, seal};
use crate::json::Json;
use crate::spake2::{Keys, Role, SPAKE2_ID_A, SPAKE2_ID_B, Spake2, derive_w, scalar_from_random};

/// The newcomer's keys, as P5 carries them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewcomerKeys {
    pub ed25519: [u8; 32],
    pub x25519: [u8; 32],
}

/// `okm = HKDF(ikm = Ke, salt = hash, info = "frontier-link/1/pair-transport", L = 64)`:
/// newcomer → primary key `okm[0..32]`, primary → newcomer `okm[32..64]`.
pub fn transport_keys(keys: &Keys) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let okm = hkdf_array::<64>(keys.ke.as_ref(), keys.hash.as_ref(), b"frontier-link/1/pair-transport");
    let mut to_primary = Zeroizing::new([0u8; 32]);
    let mut to_newcomer = Zeroizing::new([0u8; 32]);
    to_primary.copy_from_slice(&okm[..32]);
    to_newcomer.copy_from_slice(&okm[32..]);
    (to_primary, to_newcomer)
}

/// ChaCha20-Poly1305 per direction, counters from 0, empty associated data.
struct Sealer {
    send_key: Zeroizing<[u8; 32]>,
    recv_key: Zeroizing<[u8; 32]>,
    send_n: u64,
    recv_n: u64,
}

impl Sealer {
    fn seal(&mut self, value: &Json) -> Result<Vec<u8>, String> {
        let text = Zeroizing::new(value.to_json_string().map_err(|e| e.to_string())?);
        let ct = seal(&self.send_key, self.send_n, &[], text.as_bytes());
        self.send_n += 1;
        Ok(ct)
    }

    fn open(&mut self, ciphertext: &[u8]) -> Result<Json, String> {
        let pt = Zeroizing::new(
            open(&self.recv_key, self.recv_n, &[], ciphertext).ok_or("pairing: a sealed message did not open")?,
        );
        self.recv_n += 1;
        Json::parse_bytes(&pt).map_err(|e| format!("pairing: {e}"))
    }
}

fn spake(role: Role, code: &str, code_id: &[u8; 8], random48: Option<&[u8; 48]>) -> Result<Spake2, String> {
    let w = derive_w(code).ok_or("spake2: w = 0 is refused")?;
    Spake2::new(role, w, SPAKE2_ID_A, SPAKE2_ID_B, code_id, random48.map(scalar_from_random))
}

/// A, the newcomer: P1, P3, P5 out; P2, P4, P6 in.
pub struct NewcomerExchange {
    spake: Spake2,
    keys: Option<Keys>,
    sealer: Option<Sealer>,
}

impl NewcomerExchange {
    /// `code` is canonical; `random48` fixes x, for vectors.
    pub fn new(code: &str, code_id: &[u8; 8], random48: Option<&[u8; 48]>) -> Result<NewcomerExchange, String> {
        Ok(NewcomerExchange { spake: spake(Role::A, code, code_id, random48)?, keys: None, sealer: None })
    }

    /// P1: pA.
    pub fn p1(&self) -> Vec<u8> {
        self.spake.share().to_vec()
    }

    /// P2 in, P3 (cA) out.
    pub fn on_p2(&mut self, p_b: &[u8]) -> Result<Vec<u8>, String> {
        if self.keys.is_some() {
            return Err("pairing: P2 already received".into());
        }
        let keys = self.spake.finish(p_b)?;
        let out = keys.ours().to_vec();
        self.keys = Some(keys);
        Ok(out)
    }

    /// P4 in; returns P5 sealed with our public keys. Fails when cB is wrong.
    pub fn on_p4(&mut self, c_b: &[u8], mine: &NewcomerKeys) -> Result<Vec<u8>, String> {
        let keys = self.keys.as_ref().ok_or("pairing: P4 before P2")?;
        if self.sealer.is_some() {
            return Err("pairing: P4 already received".into());
        }
        if !keys.verify_theirs(c_b) {
            return Err("pairing: the primary did not prove the code".into());
        }
        let (to_primary, to_newcomer) = transport_keys(keys);
        let mut sealer = Sealer { send_key: to_primary, recv_key: to_newcomer, send_n: 0, recv_n: 0 };
        let p5 = sealer.seal(&Json::object([
            ("ed25519", Json::str(b64u(&mine.ed25519))),
            ("x25519", Json::str(b64u(&mine.x25519))),
        ]))?;
        self.sealer = Some(sealer);
        Ok(p5)
    }

    /// P6 in: the roster's JSON, not yet validated.
    pub fn on_p6(&mut self, sealed: &[u8]) -> Result<Json, String> {
        let sealer = self.sealer.as_mut().ok_or("pairing: P6 before P4")?;
        let msg = sealer.open(sealed)?;
        msg.get("roster").cloned().ok_or_else(|| "pairing: P6 carries no roster".into())
    }

    pub fn keys(&self) -> Option<&Keys> {
        self.keys.as_ref()
    }
}

/// B, the primary: P2, P4, P6 out; P1, P3, P5 in.
pub struct PrimaryExchange {
    spake: Spake2,
    keys: Option<Keys>,
    sealer: Option<Sealer>,
}

impl PrimaryExchange {
    pub fn new(code: &str, code_id: &[u8; 8], random48: Option<&[u8; 48]>) -> Result<PrimaryExchange, String> {
        Ok(PrimaryExchange { spake: spake(Role::B, code, code_id, random48)?, keys: None, sealer: None })
    }

    /// P1 in, P2 (pB) out.
    pub fn on_p1(&mut self, p_a: &[u8]) -> Result<Vec<u8>, String> {
        if self.keys.is_some() {
            return Err("pairing: P1 already received".into());
        }
        self.keys = Some(self.spake.finish(p_a)?);
        Ok(self.spake.share().to_vec())
    }

    /// P3 in. `Ok(true)` when cA verifies; then [`PrimaryExchange::p4`] may be sent.
    pub fn on_p3(&mut self, c_a: &[u8]) -> Result<bool, String> {
        let keys = self.keys.as_ref().ok_or("pairing: P3 before P1")?;
        if self.sealer.is_some() {
            return Err("pairing: P3 already received".into());
        }
        if !keys.verify_theirs(c_a) {
            return Ok(false);
        }
        let (to_primary, to_newcomer) = transport_keys(keys);
        self.sealer = Some(Sealer { send_key: to_newcomer, recv_key: to_primary, send_n: 0, recv_n: 0 });
        Ok(true)
    }

    /// P4: cB, only once cA verified.
    pub fn p4(&self) -> Result<Vec<u8>, String> {
        match (&self.keys, &self.sealer) {
            (Some(keys), Some(_)) => Ok(keys.ours().to_vec()),
            _ => Err("pairing: P4 before cA verified".into()),
        }
    }

    /// P5 in: the newcomer's keys.
    pub fn on_p5(&mut self, sealed: &[u8]) -> Result<NewcomerKeys, String> {
        let sealer = self.sealer.as_mut().ok_or("pairing: P5 before cA verified")?;
        let msg = sealer.open(sealed)?;
        if msg.as_object().is_none() {
            return Err("pairing: P5 is not an object".into());
        }
        let key = |name: &str| {
            msg.get(name)
                .and_then(Json::as_str)
                .and_then(from_b64u_array::<32>)
                .ok_or_else(|| format!("P5 {name}: expected 32 bytes"))
        };
        Ok(NewcomerKeys { ed25519: key("ed25519")?, x25519: key("x25519")? })
    }

    /// P6 out: `{"roster": ...}`.
    pub fn p6(&mut self, roster: &Json) -> Result<Vec<u8>, String> {
        let sealer = self.sealer.as_mut().ok_or("pairing: P6 before cA verified")?;
        sealer.seal(&Json::object([("roster", roster.clone())]))
    }

    pub fn keys(&self) -> Option<&Keys> {
        self.keys.as_ref()
    }
}
