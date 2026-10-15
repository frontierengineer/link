//! The primitives of section 1, bound once from RustCrypto and dalek. Nothing here invents a
//! primitive; it pins the shapes the protocol needs: HKDF-SHA256, the ChaCha20-Poly1305 nonce
//! `4 zero bytes || u64le(counter)`, raw X25519 that refuses a non-contributory result, and
//! Ed25519 verified strictly, by the one rule every implementation shares.

use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// HMAC-SHA256. The output is a secret wherever it is a key, so it is zeroised on drop.
pub(crate) fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    // HMAC takes a key of any length; `new_from_slice` cannot fail for it.
    let mut mac = match HmacSha256::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => unreachable_hmac(),
    };
    for p in parts {
        mac.update(p);
    }
    Zeroizing::new(mac.finalize().into_bytes().into())
}

#[cold]
fn unreachable_hmac() -> ! {
    // HMAC accepts keys of every length (RFC 2104); RustCrypto's only error is for fixed-key MACs.
    panic!("HMAC-SHA256 refused a key, which it never does")
}

/// HKDF-SHA256 (RFC 5869) into `out` (at most 8160 bytes, far above anything the protocol asks).
pub(crate) fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), ikm);
    if hk.expand(info, out).is_err() {
        // Only reachable for an output over 255 * 32 bytes, which no caller asks for.
        panic!("HKDF-SHA256 output length over 8160 bytes");
    }
}

/// HKDF-SHA256 of `N` bytes, zeroised on drop.
pub(crate) fn hkdf_array<const N: usize>(ikm: &[u8], salt: &[u8], info: &[u8]) -> Zeroizing<[u8; N]> {
    let mut out = Zeroizing::new([0u8; N]);
    hkdf_sha256(ikm, salt, info, out.as_mut());
    out
}

/// Constant-time equality of two byte strings (the lengths are not secret).
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// Fills `buf` from the operating system's secure random source.
///
/// A node that cannot get secure randomness must not go on: it would reuse keys, indices and
/// nonces. That is not reachable from any input, so it panics rather than limp on.
pub(crate) fn fill_random(buf: &mut [u8]) {
    if getrandom::fill(buf).is_err() {
        panic!("the operating system's secure random source failed");
    }
}

pub(crate) fn random_array<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    fill_random(&mut b);
    b
}

// ── ChaCha20-Poly1305 with the nonce `4 zero bytes || u64le(counter)` ──

fn counter_nonce(n: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&n.to_le_bytes());
    nonce
}

/// Seals `plaintext` under `key` with the counter nonce `n`.
pub(crate) fn seal(key: &[u8; 32], n: u64, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    match cipher.encrypt(&counter_nonce(n).into(), Payload { msg: plaintext, aad: ad }) {
        Ok(ct) => ct,
        // Only reachable for a plaintext over 256 GiB.
        Err(_) => panic!("ChaCha20-Poly1305 refused a plaintext"),
    }
}

/// Opens `ciphertext`; `None` when the tag does not verify.
pub(crate) fn open(key: &[u8; 32], n: u64, ad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher.decrypt(&counter_nonce(n).into(), Payload { msg: ciphertext, aad: ad }).ok()
}

// ── X25519 ──

pub(crate) fn clamp_x25519(k: &mut [u8; 32]) {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
}

pub(crate) fn x25519_public(private: &[u8; 32]) -> [u8; 32] {
    let secret = x25519_dalek::StaticSecret::from(*private);
    x25519_dalek::PublicKey::from(&secret).to_bytes()
}

/// X25519. `None` when the result is all zeros (a low-order peer key), which Go's `crypto/ecdh`
/// and the TypeScript client both refuse; callers treat it as a failed handshake.
pub(crate) fn x25519_dh(private: &[u8; 32], public: &[u8; 32]) -> Option<Zeroizing<[u8; 32]>> {
    let secret = x25519_dalek::StaticSecret::from(*private);
    let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(*public));
    if !shared.was_contributory() {
        return None;
    }
    Some(Zeroizing::new(shared.to_bytes()))
}

// ── Ed25519 (RFC 8032) ──

/// Ed25519 verification, strict and the same in every implementation (spec section 1):
///
/// - `A` and `R` must be canonical encodings: `y < p`, and no `x = 0` with the sign bit set;
/// - neither `A` nor `R` may be one of the 8 small-order points;
/// - `S < L`;
/// - the equation is the cofactorless one, `[S]B = R + [k]A`.
///
/// ed25519-dalek's `verify_strict` refuses small-order `A` and `R`, refuses `S >= L`, and checks the
/// cofactorless equation by comparing `R`'s encoding with that of `[S]B - [k]A` (so a
/// non-canonical `R` never verifies). It decodes `A` leniently, though (`y` reduced mod `p`, a
/// sign bit on `x = 0` ignored), so both encodings are checked here, explicitly, first.
pub fn ed25519_verify(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let (r, _) = signature.split_first_chunk::<32>().unwrap_or((&[0; 32], &[]));
    let (Some(key), Some(r)) = (canonical_point(public), canonical_point(r)) else {
        return false;
    };
    if key.is_weak() || r.is_weak() {
        return false;
    }
    key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(signature)).is_ok()
}

/// The point an Ed25519 encoding names, if it is one and the encoding is canonical: decoding then
/// encoding again gives the same bytes exactly when `y < p` and no `x = 0` has its sign bit set.
fn canonical_point(bytes: &[u8; 32]) -> Option<ed25519_dalek::VerifyingKey> {
    let point = ed25519_dalek::VerifyingKey::from_bytes(bytes).ok()?;
    (point.to_edwards().compress().to_bytes() == *bytes).then_some(point)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::from_hex;

    fn hex32(s: &str) -> [u8; 32] {
        from_hex(s).and_then(|v| v.try_into().ok()).unwrap()
    }

    fn hex64(s: &str) -> [u8; 64] {
        from_hex(s).and_then(|v| v.try_into().ok()).unwrap()
    }

    /// A signature by hand: `S = r + k·a` for the claimed key bytes `public`, with nonce point
    /// `R = [r]B` unless `r_bytes` names another `R`.
    fn sign_raw(a: Scalar, public: &[u8; 32], r: Scalar, r_bytes: Option<[u8; 32]>, msg: &[u8]) -> [u8; 64] {
        use sha2::Sha512;
        let r_bytes = r_bytes.unwrap_or_else(|| EdwardsPoint::mul_base(&r).compress().to_bytes());
        let mut h = Sha512::new();
        h.update(r_bytes);
        h.update(public);
        h.update(msg);
        let k = Scalar::from_bytes_mod_order_wide(&h.finalize().into());
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_bytes);
        sig[32..].copy_from_slice((r + k * a).as_bytes());
        sig
    }

    use curve25519_dalek::constants::EIGHT_TORSION;
    use curve25519_dalek::{EdwardsPoint, Scalar};

    const L: &str = "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010";

    fn add_le(x: &[u8; 32], y: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut carry = 0u16;
        for i in 0..32 {
            let v = u16::from(x[i]) + u16::from(y[i]) + carry;
            out[i] = v as u8;
            carry = v >> 8;
        }
        out
    }

    #[test]
    fn ed25519_verification_is_strict() {
        let seed = [7u8; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();
        let msg = b"frontier-link";
        let sig = ed25519_dalek::Signer::sign(&sk, msg).to_bytes();
        assert!(ed25519_verify(&pk, msg, &sig));
        assert!(!ed25519_verify(&pk, b"other", &sig));

        // S < L: S + L (the same signature, malleated) and S = L are refused.
        let mut malleated = sig;
        malleated[32..].copy_from_slice(&add_le(sig[32..].try_into().unwrap(), &hex32(L)));
        assert!(!ed25519_verify(&pk, msg, &malleated));
        let mut s_is_l = sig;
        s_is_l[32..].copy_from_slice(&hex32(L));
        assert!(!ed25519_verify(&pk, msg, &s_is_l));

        // A small-order key: the identity, with R = identity and S = 0, satisfies the equation
        // for every message, and is refused; so is each of the 8 small-order points as the key.
        let identity = hex32("0100000000000000000000000000000000000000000000000000000000000000");
        let mut weak = [0u8; 64];
        weak[..32].copy_from_slice(&identity);
        assert!(!ed25519_verify(&identity, b"anything at all", &weak));
        for t in EIGHT_TORSION {
            assert!(!ed25519_verify(&t.compress().to_bytes(), b"anything at all", &weak));
        }

        // A small-order R on an honest key: with R = identity and S = k·a, [S]B = R + [k]A holds
        // (the lenient check accepts it); only the small-order rule refuses it.
        let a = sk.to_scalar();
        let small_r = sign_raw(a, &pk, Scalar::ZERO, Some(identity), msg);
        assert!(ed25519_dalek::Verifier::verify(&sk.verifying_key(), msg, &small_r.into()).is_ok());
        assert!(!ed25519_verify(&pk, msg, &small_r));

        // Non-canonical R: the identity written as y = p + 1.
        let p_plus_1 = hex32("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        let mut noncanon_r = weak;
        noncanon_r[..32].copy_from_slice(&p_plus_1);
        assert!(!ed25519_verify(&identity, b"anything at all", &noncanon_r));
        // Non-canonical A: the same encoding as the key.
        assert!(!ed25519_verify(&p_plus_1, b"anything at all", &weak));

        // Cofactorless: a key with an order-8 component, A' = aB + T. A signature on it satisfies
        // the cofactored equation always, the cofactorless one only when 8 divides k.
        let mixed = (EdwardsPoint::mul_base(&a) + EIGHT_TORSION[1]).compress().to_bytes();
        let mut refused = 0;
        for i in 0..16u8 {
            let m = [b'm', i];
            let s = sign_raw(a, &mixed, Scalar::from(u64::from(i) + 99), None, &m);
            if !ed25519_verify(&mixed, &m, &s) {
                refused += 1;
            }
        }
        assert!(refused >= 8, "{refused} of 16 refused");

        // Not a curve point.
        let not_a_point = hex32("0200000000000000000000000000000000000000000000000000000000000000");
        assert!(!ed25519_verify(&not_a_point, msg, &hex64(&"00".repeat(64))));
    }

    #[test]
    fn only_canonical_encodings_name_points() {
        // Every honest key is canonical.
        for seed in 0..32u8 {
            let pk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes();
            assert!(canonical_point(&pk).is_some());
        }
        // y >= p: p + y for each small y that is a curve point, written with y unreduced.
        let p = hex32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
        let mut points = 0;
        for y in 0..19u8 {
            let mut small = [0u8; 32];
            small[0] = y;
            let big = add_le(&p, &small);
            if ed25519_dalek::VerifyingKey::from_bytes(&big).is_ok() {
                points += 1;
                assert!(canonical_point(&big).is_none(), "y = p + {y}");
                assert!(canonical_point(&small).is_some(), "y = {y}");
                // Refused before anything else: even a would-be signature never verifies.
                assert!(!ed25519_verify(&big, b"m", &[0; 64]));
            }
        }
        assert!(points >= 2, "{points}");
        // x = 0 with the sign bit set: y = 1 and y = p - 1, the only points with x = 0.
        for enc in [
            "0100000000000000000000000000000000000000000000000000000000000080",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ] {
            let e = hex32(enc);
            assert!(ed25519_dalek::VerifyingKey::from_bytes(&e).is_ok(), "{enc} decodes leniently");
            assert!(canonical_point(&e).is_none(), "{enc}");
        }
    }

    #[test]
    fn x25519_refuses_low_order_keys() {
        let mut k = [9u8; 32];
        clamp_x25519(&mut k);
        assert!(x25519_dh(&k, &[0u8; 32]).is_none());
        let mut one = [0u8; 32];
        one[0] = 1;
        assert!(x25519_dh(&k, &one).is_none());
        assert!(x25519_dh(&k, &x25519_public(&k)).is_some());
    }

    #[test]
    fn aead_round_trip_and_tag() {
        let key = [3u8; 32];
        let ct = seal(&key, 5, b"ad", b"hello");
        assert_eq!(open(&key, 5, b"ad", &ct).as_deref(), Some(&b"hello"[..]));
        assert!(open(&key, 6, b"ad", &ct).is_none());
        assert!(open(&key, 5, b"", &ct).is_none());
        assert!(open(&key, 5, b"ad", &ct[..10]).is_none());
        assert!(ct_eq(b"abc", b"abc") && !ct_eq(b"abc", b"abd") && !ct_eq(b"ab", b"abc"));
    }
}
