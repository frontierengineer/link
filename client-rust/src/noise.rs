//! A Noise Protocol engine (revision 34) for the `25519_ChaChaPoly_SHA256` suite. Sessions use
//! IK (section 7.1); NN, KK and XX exist so the engine can be proven byte for byte against the
//! cacophony vectors on every token branch. Structure and names follow Noise sections 5.1-5.3.
//!
//! Every secret (chaining key, cipher keys, ephemeral and static private keys, DH outputs and
//! HKDF intermediates) lives in a `Zeroizing` container and is wiped when dropped. A DH whose
//! result is all zeros (a low-order peer key) fails the handshake, as in the TypeScript and Go
//! implementations.

use zeroize::Zeroizing;

use crate::crypto::{hmac_sha256, open, random_array, seal, sha256, x25519_dh, x25519_public};

/// A Noise message is at most 65535 bytes (Noise section 3).
pub const MAX_MESSAGE: usize = 65535;
pub const TAG_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Token {
    E,
    S,
    Ee,
    Es,
    Se,
    Ss,
}

/// A handshake pattern: pre-messages, then messages, each `(initiator writes, tokens)`.
pub struct Pattern {
    pub name: &'static str,
    pub pre: &'static [(bool, &'static [Token])],
    pub messages: &'static [(bool, &'static [Token])],
}

use Token::*;

pub const IK: Pattern =
    Pattern { name: "IK", pre: &[(false, &[S])], messages: &[(true, &[E, Es, S, Ss]), (false, &[E, Ee, Se])] };
pub const NN: Pattern = Pattern { name: "NN", pre: &[], messages: &[(true, &[E]), (false, &[E, Ee])] };
pub const KK: Pattern = Pattern {
    name: "KK",
    pre: &[(true, &[S]), (false, &[S])],
    messages: &[(true, &[E, Es, Ss]), (false, &[E, Ee, Se])],
};
pub const XX: Pattern =
    Pattern { name: "XX", pre: &[], messages: &[(true, &[E]), (false, &[E, Ee, S, Es]), (true, &[S, Se])] };

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoiseError(pub &'static str);

impl std::fmt::Display for NoiseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "noise: {}", self.0)
    }
}

impl std::error::Error for NoiseError {}

/// One direction's key and 64-bit counter nonce (Noise section 5.1).
pub struct CipherState {
    k: Option<Zeroizing<[u8; 32]>>,
    n: u64,
}

impl CipherState {
    fn new(k: Option<Zeroizing<[u8; 32]>>) -> CipherState {
        CipherState { k, n: 0 }
    }

    pub fn has_key(&self) -> bool {
        self.k.is_some()
    }

    /// Messages processed so far in this direction.
    pub fn nonce(&self) -> u64 {
        self.n
    }

    /// Encrypts with the next nonce. The nonce 2^64 - 1 is reserved (Noise section 5.1), so a
    /// direction that reached it fails rather than reuse a nonce.
    pub fn encrypt_with_ad(&mut self, ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let Some(k) = &self.k else {
            return Ok(plaintext.to_vec());
        };
        if self.n == u64::MAX {
            return Err(NoiseError("nonce exhausted"));
        }
        let ct = seal(k, self.n, ad, plaintext);
        self.n += 1;
        Ok(ct)
    }

    /// Fails on a bad tag; the counter advances only on success.
    pub fn decrypt_with_ad(&mut self, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let Some(k) = &self.k else {
            return Ok(ciphertext.to_vec());
        };
        if self.n == u64::MAX {
            return Err(NoiseError("nonce exhausted"));
        }
        let pt = open(k, self.n, ad, ciphertext).ok_or(NoiseError("decryption failed"))?;
        self.n += 1;
        Ok(pt)
    }
}

/// Noise's HKDF (section 4.3): two 32-byte outputs keyed by the chaining key.
fn hkdf2(ck: &[u8; 32], ikm: &[u8]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let temp = hmac_sha256(ck, &[ikm]);
    let o1 = hmac_sha256(temp.as_ref(), &[&[1u8]]);
    let o2 = hmac_sha256(temp.as_ref(), &[o1.as_ref(), &[2u8]]);
    (o1, o2)
}

struct SymmetricState {
    ck: Zeroizing<[u8; 32]>,
    h: [u8; 32],
    cs: CipherState,
}

impl SymmetricState {
    fn new(protocol_name: &str) -> SymmetricState {
        let name = protocol_name.as_bytes();
        let h = if name.len() <= 32 {
            let mut h = [0u8; 32];
            h[..name.len()].copy_from_slice(name);
            h
        } else {
            sha256(name)
        };
        SymmetricState { ck: Zeroizing::new(h), h, cs: CipherState::new(None) }
    }

    fn mix_key(&mut self, ikm: &[u8]) {
        let (ck, k) = hkdf2(&self.ck, ikm);
        self.ck = ck;
        self.cs = CipherState::new(Some(k));
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut buf = Vec::with_capacity(32 + data.len());
        buf.extend_from_slice(&self.h);
        buf.extend_from_slice(data);
        self.h = sha256(&buf);
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let ct = self.cs.encrypt_with_ad(&self.h, plaintext)?;
        self.mix_hash(&ct);
        Ok(ct)
    }

    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let pt = self.cs.decrypt_with_ad(&self.h, ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(pt)
    }

    fn split(&self) -> (CipherState, CipherState) {
        let (k1, k2) = hkdf2(&self.ck, &[]);
        (CipherState::new(Some(k1)), CipherState::new(Some(k2)))
    }
}

/// An X25519 key pair; the private half is wiped on drop.
#[derive(Clone)]
pub struct KeyPair {
    private: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl KeyPair {
    pub fn from_private(private: &[u8; 32]) -> KeyPair {
        KeyPair { private: Zeroizing::new(*private), public: x25519_public(private) }
    }

    fn generate() -> KeyPair {
        let private = Zeroizing::new(random_array::<32>());
        KeyPair::from_private(&private)
    }

    pub fn public(&self) -> &[u8; 32] {
        &self.public
    }
}

/// The two transport CipherStates of a finished handshake, from this side's point of view.
pub struct Transport {
    pub send: CipherState,
    pub recv: CipherState,
    pub handshake_hash: [u8; 32],
}

pub struct HandshakeOptions<'a> {
    pub pattern: &'static Pattern,
    pub initiator: bool,
    pub prologue: &'a [u8],
    pub s: Option<KeyPair>,
    pub rs: Option<[u8; 32]>,
    /// Fixes the ephemeral private key; only for vectors and tests.
    pub fixed_ephemeral: Option<[u8; 32]>,
}

pub struct HandshakeState {
    ss: SymmetricState,
    initiator: bool,
    messages: &'static [(bool, &'static [Token])],
    s: Option<KeyPair>,
    e: Option<KeyPair>,
    rs: Option<[u8; 32]>,
    re: Option<[u8; 32]>,
    fixed_ephemeral: Option<Zeroizing<[u8; 32]>>,
    index: usize,
}

impl HandshakeState {
    pub fn new(opts: HandshakeOptions<'_>) -> Result<HandshakeState, NoiseError> {
        let mut ss = SymmetricState::new(&format!("Noise_{}_25519_ChaChaPoly_SHA256", opts.pattern.name));
        ss.mix_hash(opts.prologue);
        let hs_s = opts.s;
        let hs_rs = opts.rs;
        for (initiator_writes, tokens) in opts.pattern.pre {
            let mine = *initiator_writes == opts.initiator;
            for t in *tokens {
                match t {
                    S if mine => ss.mix_hash(hs_s.as_ref().ok_or(NoiseError("missing s"))?.public()),
                    S => ss.mix_hash(hs_rs.as_ref().ok_or(NoiseError("missing rs"))?),
                    _ => return Err(NoiseError("unsupported pre-message token")),
                }
            }
        }
        Ok(HandshakeState {
            ss,
            initiator: opts.initiator,
            messages: opts.pattern.messages,
            s: hs_s,
            e: None,
            rs: hs_rs,
            re: None,
            fixed_ephemeral: opts.fixed_ephemeral.map(Zeroizing::new),
            index: 0,
        })
    }

    /// The peer's static key, once known.
    pub fn remote_static(&self) -> Option<&[u8; 32]> {
        self.rs.as_ref()
    }

    pub fn is_complete(&self) -> bool {
        self.index >= self.messages.len()
    }

    pub fn write_message(&mut self, payload: &[u8]) -> Result<(Vec<u8>, Option<Transport>), NoiseError> {
        let Some((initiator_writes, tokens)) = self.messages.get(self.index) else {
            return Err(NoiseError("handshake already complete"));
        };
        if *initiator_writes != self.initiator {
            return Err(NoiseError("not our turn to write"));
        }
        self.index += 1;
        let mut out = Vec::new();
        for t in *tokens {
            match t {
                E => {
                    let e = match &self.fixed_ephemeral {
                        Some(k) => KeyPair::from_private(k),
                        None => KeyPair::generate(),
                    };
                    out.extend_from_slice(&e.public);
                    self.ss.mix_hash(&e.public);
                    self.e = Some(e);
                }
                S => {
                    let s_pub = *self.s.as_ref().ok_or(NoiseError("missing s"))?.public();
                    let ct = self.ss.encrypt_and_hash(&s_pub)?;
                    out.extend_from_slice(&ct);
                }
                dh => self.mix_dh(*dh)?,
            }
        }
        out.extend_from_slice(&self.ss.encrypt_and_hash(payload)?);
        if out.len() > MAX_MESSAGE {
            return Err(NoiseError("handshake message over 65535 bytes"));
        }
        Ok((out, self.maybe_split()))
    }

    /// Fails on any authentication failure or malformed message.
    pub fn read_message(&mut self, message: &[u8]) -> Result<(Vec<u8>, Option<Transport>), NoiseError> {
        if message.len() > MAX_MESSAGE {
            return Err(NoiseError("handshake message over 65535 bytes"));
        }
        let Some((initiator_writes, tokens)) = self.messages.get(self.index) else {
            return Err(NoiseError("handshake already complete"));
        };
        if *initiator_writes == self.initiator {
            return Err(NoiseError("not our turn to read"));
        }
        self.index += 1;
        let mut rest = message;
        for t in *tokens {
            match t {
                E => {
                    let (re, tail) = take::<32>(rest)?;
                    rest = tail;
                    self.ss.mix_hash(&re);
                    self.re = Some(re);
                }
                S => {
                    let n = if self.ss.cs.has_key() { 32 + TAG_LEN } else { 32 };
                    let (Some(ct), Some(tail)) = (rest.get(..n), rest.get(n..)) else {
                        return Err(NoiseError("truncated handshake message"));
                    };
                    rest = tail;
                    let pt = self.ss.decrypt_and_hash(ct)?;
                    let rs: [u8; 32] = pt.as_slice().try_into().map_err(|_| NoiseError("bad static key"))?;
                    self.rs = Some(rs);
                }
                dh => self.mix_dh(*dh)?,
            }
        }
        let payload = self.ss.decrypt_and_hash(rest)?;
        Ok((payload, self.maybe_split()))
    }

    fn mix_dh(&mut self, t: Token) -> Result<(), NoiseError> {
        let e = || self.e.as_ref().ok_or(NoiseError("missing e"));
        let s = || self.s.as_ref().ok_or(NoiseError("missing s"));
        let re = || self.re.as_ref().ok_or(NoiseError("missing re"));
        let rs = || self.rs.as_ref().ok_or(NoiseError("missing rs"));
        let (private, public): (&[u8; 32], &[u8; 32]) = match (t, self.initiator) {
            (Ee, _) => (&e()?.private, re()?),
            (Es, true) => (&e()?.private, rs()?),
            (Es, false) => (&s()?.private, re()?),
            (Se, true) => (&s()?.private, re()?),
            (Se, false) => (&e()?.private, rs()?),
            (Ss, _) => (&s()?.private, rs()?),
            _ => return Err(NoiseError("unexpected token")),
        };
        let shared = x25519_dh(private, public).ok_or(NoiseError("low-order public key"))?;
        self.ss.mix_key(shared.as_ref());
        Ok(())
    }

    fn maybe_split(&self) -> Option<Transport> {
        if !self.is_complete() {
            return None;
        }
        let (c1, c2) = self.ss.split();
        let handshake_hash = self.ss.h;
        Some(if self.initiator {
            Transport { send: c1, recv: c2, handshake_hash }
        } else {
            Transport { send: c2, recv: c1, handshake_hash }
        })
    }
}

fn take<const N: usize>(b: &[u8]) -> Result<([u8; N], &[u8]), NoiseError> {
    let (Some(head), Some(tail)) = (b.get(..N), b.get(N..)) else {
        return Err(NoiseError("truncated handshake message"));
    };
    let arr: [u8; N] = head.try_into().map_err(|_| NoiseError("truncated handshake message"))?;
    Ok((arr, tail))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(p: &'static Pattern, prologue: &'static [u8]) -> (HandshakeState, HandshakeState) {
        let a = KeyPair::from_private(&[1; 32]);
        let b = KeyPair::from_private(&[2; 32]);
        let b_pub = *b.public();
        let a_pub = *a.public();
        let i = HandshakeState::new(HandshakeOptions {
            pattern: p,
            initiator: true,
            prologue,
            s: Some(a),
            rs: Some(b_pub),
            fixed_ephemeral: None,
        })
        .unwrap();
        let r = HandshakeState::new(HandshakeOptions {
            pattern: p,
            initiator: false,
            prologue,
            s: Some(b),
            rs: if p.name == "KK" { Some(a_pub) } else { None },
            fixed_ephemeral: None,
        })
        .unwrap();
        (i, r)
    }

    #[test]
    fn ik_round_trip_and_tamper() {
        let (mut i, mut r) = pair(&IK, b"p");
        let (m1, _) = i.write_message(b"one").unwrap();
        let mut bad = m1.clone();
        bad[40] ^= 1;
        let (_, mut r2) = pair(&IK, b"p");
        assert!(r2.read_message(&bad).is_err());
        let (p1, t) = r.read_message(&m1).unwrap();
        assert_eq!(p1, b"one");
        assert!(t.is_none());
        let (m2, rt) = r.write_message(b"two").unwrap();
        let (p2, it) = i.read_message(&m2).unwrap();
        assert_eq!(p2, b"two");
        let (mut it, mut rt) = (it.unwrap(), rt.unwrap());
        assert_eq!(it.handshake_hash, rt.handshake_hash);
        let c = it.send.encrypt_with_ad(&[], b"x").unwrap();
        assert_eq!(rt.recv.decrypt_with_ad(&[], &c).unwrap(), b"x");
        assert!(rt.recv.decrypt_with_ad(&[], &c).is_err(), "a replayed frame fails: the nonce moved on");
        assert!(i.write_message(b"").is_err(), "complete");
    }

    #[test]
    fn prologue_mismatch_and_wrong_turn_and_truncation() {
        let (mut i, _) = pair(&IK, b"one");
        let (_, mut r) = pair(&IK, b"two");
        let (m1, _) = i.write_message(&[]).unwrap();
        assert!(r.read_message(&m1).is_err());
        let (mut i, mut r) = pair(&IK, b"p");
        assert!(i.read_message(&[0; 100]).is_err(), "not our turn to read");
        assert!(r.write_message(&[]).is_err(), "not our turn to write");
        let (m1, _) = i.write_message(&[]).unwrap();
        assert!(r.read_message(&m1[..50]).is_err());
        let (_, mut r) = pair(&IK, b"p");
        assert!(r.read_message(&vec![0; MAX_MESSAGE + 1]).is_err());
    }

    #[test]
    fn low_order_ephemeral_fails_the_handshake() {
        let (mut i, mut r) = pair(&IK, b"p");
        let (mut m1, _) = i.write_message(&[]).unwrap();
        m1[..32].fill(0);
        assert_eq!(r.read_message(&m1).err(), Some(NoiseError("low-order public key")));
    }

    #[test]
    fn nonce_exhaustion_refuses_rather_than_reuses() {
        let mut c = CipherState::new(Some(Zeroizing::new([5; 32])));
        c.n = u64::MAX - 1;
        assert!(c.encrypt_with_ad(&[], b"last").is_ok());
        assert!(c.encrypt_with_ad(&[], b"reuse").is_err());
    }
}
