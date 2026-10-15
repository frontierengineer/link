//! SPAKE2 over P-256, RFC 9382 ciphersuite P256-SHA256-HKDF-HMAC, with this protocol's
//! parameters (section 5.3). A is the newcomer and uses M; B is the primary and uses N.
//!
//! RFC 9382's requirements on the receiver are kept: a received share must be a valid
//! uncompressed P-256 point (on the curve; the identity has no 65-byte encoding), and the
//! shared point must not be the identity. P-256 has cofactor 1, so no cofactor clearing.

use p256::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
use p256::elliptic_curve::{Field, Group};
use p256::{AffinePoint, ProjectivePoint, Scalar, Sec1Point};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{ct_eq, fill_random, hkdf_array, hmac_sha256, sha256};

/// RFC 9382 section 6, compressed SEC1.
const M_HEX: &str = "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f";
const N_HEX: &str = "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49";

pub const SPAKE2_ID_A: &[u8] = b"frontier-link/1/newcomer";
pub const SPAKE2_ID_B: &[u8] = b"frontier-link/1/primary";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    A,
    B,
}

fn point_from_hex(hex: &str) -> ProjectivePoint {
    // The two constants are fixed, valid compressed points; this cannot fail.
    let bytes = crate::bytes::from_hex(hex).unwrap_or_default();
    let p = Sec1Point::from_bytes(&bytes).ok().and_then(|ep| AffinePoint::from_sec1_point(&ep).into_option());
    match p {
        Some(p) => ProjectivePoint::from(p),
        None => panic!("SPAKE2 constant M or N failed to decode"),
    }
}

fn m_point() -> ProjectivePoint {
    point_from_hex(M_HEX)
}

fn n_point() -> ProjectivePoint {
    point_from_hex(N_HEX)
}

/// A big-endian byte string modulo the group order n, in constant time (Horner's rule in the
/// scalar field).
pub(crate) fn scalar_mod_n(bytes: &[u8]) -> Scalar {
    let radix = Scalar::from(256u64);
    let mut acc = Scalar::ZERO;
    for &b in bytes {
        acc = acc * radix + Scalar::from(u64::from(b));
    }
    acc
}

fn scalar_to_32(s: &Scalar) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&s.to_bytes());
    out
}

fn is_zero(s: &Scalar) -> bool {
    bool::from(s.is_zero())
}

/// `w` from a normalised pairing code: 40 HKDF bytes, big-endian, mod n. `None` when `w = 0`.
pub fn derive_w(code: &str) -> Option<Scalar> {
    let wide = hkdf_array::<40>(code.as_bytes(), &[], b"frontier-link/1/spake2/w");
    let w = scalar_mod_n(wide.as_ref());
    if is_zero(&w) { None } else { Some(w) }
}

/// A secret scalar from 48 random bytes, mod n.
pub fn scalar_from_random(r: &[u8; 48]) -> Scalar {
    scalar_mod_n(r)
}

/// Everything SPAKE2 derives once the peer's share is in.
pub struct Keys {
    /// The shared point K, uncompressed SEC1.
    pub k: Zeroizing<Vec<u8>>,
    /// The full TT transcript.
    pub tt: Zeroizing<Vec<u8>>,
    /// SHA-256(TT).
    pub hash: Zeroizing<[u8; 32]>,
    pub ke: Zeroizing<[u8; 16]>,
    pub ka: Zeroizing<[u8; 16]>,
    pub kc_a: Zeroizing<[u8; 16]>,
    pub kc_b: Zeroizing<[u8; 16]>,
    pub c_a: Zeroizing<[u8; 32]>,
    pub c_b: Zeroizing<[u8; 32]>,
    role: Role,
}

impl Keys {
    /// The confirmation this side sends.
    pub fn ours(&self) -> &[u8; 32] {
        if self.role == Role::A { &self.c_a } else { &self.c_b }
    }

    /// Constant-time check of the peer's confirmation MAC.
    pub fn verify_theirs(&self, received: &[u8]) -> bool {
        let theirs: &[u8; 32] = if self.role == Role::A { &self.c_b } else { &self.c_a };
        ct_eq(received, theirs)
    }
}

pub struct Spake2 {
    role: Role,
    w: Scalar,
    xy: Scalar,
    id_a: Vec<u8>,
    id_b: Vec<u8>,
    /// Appended to "ConfirmationKeys" in the KcA/KcB info (the code id here).
    aad: Vec<u8>,
    share: [u8; 65],
}

impl Drop for Spake2 {
    fn drop(&mut self) {
        self.w.zeroize();
        self.xy.zeroize();
    }
}

impl Spake2 {
    /// `scalar` fixes x (A) or y (B), for vectors; otherwise it is drawn from 48 random bytes.
    pub fn new(
        role: Role,
        w: Scalar,
        id_a: &[u8],
        id_b: &[u8],
        aad: &[u8],
        scalar: Option<Scalar>,
    ) -> Result<Spake2, String> {
        if is_zero(&w) {
            return Err("spake2: w = 0 is refused".into());
        }
        let xy = match scalar {
            Some(s) if is_zero(&s) => return Err("spake2: secret scalar is 0".into()),
            Some(s) => s,
            None => loop {
                let mut r = Zeroizing::new([0u8; 48]);
                fill_random(r.as_mut());
                let s = scalar_from_random(&r);
                if !is_zero(&s) {
                    break s;
                }
            },
        };
        let blind = if role == Role::A { m_point() } else { n_point() };
        let share_point = blind * w + ProjectivePoint::GENERATOR * xy;
        let mut share = [0u8; 65];
        share.copy_from_slice(share_point.to_affine().to_sec1_point(false).as_bytes());
        Ok(Spake2 { role, w, xy, id_a: id_a.to_vec(), id_b: id_b.to_vec(), aad: aad.to_vec(), share })
    }

    /// pA or pB: uncompressed SEC1, 65 bytes.
    pub fn share(&self) -> &[u8; 65] {
        &self.share
    }

    pub fn finish(&self, peer_share: &[u8]) -> Result<Keys, String> {
        let bad = || "spake2: peer share is not a valid uncompressed P-256 point".to_string();
        if peer_share.len() != 65 || peer_share.first() != Some(&0x04) {
            return Err(bad());
        }
        let ep = Sec1Point::from_bytes(peer_share).map_err(|_| bad())?;
        let peer = AffinePoint::from_sec1_point(&ep).into_option().ok_or_else(bad)?;
        // K = h*x*(pB - w*N) for A, h*y*(pA - w*M) for B; h = 1 on P-256.
        let unblind = if self.role == Role::A { n_point() } else { m_point() };
        let base = ProjectivePoint::from(peer) - unblind * self.w;
        if bool::from(base.is_identity()) {
            return Err("spake2: degenerate shared point".into());
        }
        let k_point = base * self.xy;
        let k = Zeroizing::new(k_point.to_affine().to_sec1_point(false).as_bytes().to_vec());
        let (pa, pb): (&[u8], &[u8]) =
            if self.role == Role::A { (&self.share, peer_share) } else { (peer_share, &self.share) };
        let w_bytes = Zeroizing::new(scalar_to_32(&self.w));
        let mut tt = Zeroizing::new(Vec::with_capacity(8 * 6 + 32 + 32 + 65 * 3 + 32));
        for part in [&self.id_a[..], &self.id_b[..], pa, pb, &k[..], &w_bytes[..]] {
            tt.extend_from_slice(&(part.len() as u64).to_le_bytes());
            tt.extend_from_slice(part);
        }
        let hash = Zeroizing::new(sha256(&tt));
        let mut ke = Zeroizing::new([0u8; 16]);
        let mut ka = Zeroizing::new([0u8; 16]);
        ke.copy_from_slice(&hash[..16]);
        ka.copy_from_slice(&hash[16..]);
        let mut info = b"ConfirmationKeys".to_vec();
        info.extend_from_slice(&self.aad);
        let kc = hkdf_array::<32>(ka.as_ref(), &[], &info);
        let mut kc_a = Zeroizing::new([0u8; 16]);
        let mut kc_b = Zeroizing::new([0u8; 16]);
        kc_a.copy_from_slice(&kc[..16]);
        kc_b.copy_from_slice(&kc[16..]);
        let c_a = hmac_sha256(kc_a.as_ref(), &[&tt]);
        let c_b = hmac_sha256(kc_b.as_ref(), &[&tt]);
        Ok(Keys { k, tt, hash, ke, ka, kc_a, kc_b, c_a, c_b, role: self.role })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_and_b_agree_and_detect_a_wrong_code() {
        let w = derive_w("7K2M9QXZ").unwrap();
        let a = Spake2::new(Role::A, w, SPAKE2_ID_A, SPAKE2_ID_B, b"id", None).unwrap();
        let b = Spake2::new(Role::B, w, SPAKE2_ID_A, SPAKE2_ID_B, b"id", None).unwrap();
        let ka = a.finish(b.share()).unwrap();
        let kb = b.finish(a.share()).unwrap();
        assert!(kb.verify_theirs(ka.ours()) && ka.verify_theirs(kb.ours()));
        assert_eq!(*ka.ke, *kb.ke);
        let wrong = Spake2::new(Role::B, derive_w("7K2M9QXY").unwrap(), SPAKE2_ID_A, SPAKE2_ID_B, b"id", None).unwrap();
        let kw = wrong.finish(a.share()).unwrap();
        assert!(!kw.verify_theirs(ka.ours()));
    }

    #[test]
    fn bad_shares_are_refused() {
        let w = derive_w("7K2M9QXZ").unwrap();
        let b = Spake2::new(Role::B, w, SPAKE2_ID_A, SPAKE2_ID_B, b"", None).unwrap();
        assert!(b.finish(&[4u8; 65]).is_err(), "not on the curve");
        assert!(b.finish(&[0u8; 1]).is_err(), "identity");
        let mut compressed = [0u8; 65];
        compressed[..33].copy_from_slice(&crate::bytes::from_hex(M_HEX).unwrap());
        assert!(b.finish(&compressed[..33]).is_err(), "compressed");
        // pA = w*M makes pA - w*M the identity: refused rather than keyed by a known K.
        let wm = (m_point() * w).to_affine().to_sec1_point(false);
        assert_eq!(b.finish(wm.as_bytes()).err().as_deref(), Some("spake2: degenerate shared point"));
        assert!(Spake2::new(Role::A, Scalar::ZERO, SPAKE2_ID_A, SPAKE2_ID_B, b"", None).is_err());
        assert!(Spake2::new(Role::A, w, SPAKE2_ID_A, SPAKE2_ID_B, b"", Some(Scalar::ZERO)).is_err());
    }

    #[test]
    fn reduction_mod_n() {
        // n itself reduces to 0, n + 1 to 1, and 2^384 - 1 to its value mod n.
        let n = crate::bytes::from_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551").unwrap();
        assert!(is_zero(&scalar_mod_n(&n)));
        let mut n1 = n.clone();
        n1[31] += 1;
        assert_eq!(scalar_mod_n(&n1), Scalar::ONE);
        assert_eq!(scalar_mod_n(&[0, 0, 5]), Scalar::from(5u64));
    }
}
