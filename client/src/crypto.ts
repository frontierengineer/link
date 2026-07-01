// The cryptographic primitives, in one place, all adopted from audited zero-dep
// libraries (@noble/*). Nothing in this file invents a primitive: it only binds
// the exact functions Noise and SPAKE2 require and pins their encodings (nonce
// layout, DH, HKDF shape). Concentrating the primitives here keeps the audit
// surface tiny and makes "do we hand-roll crypto?" answerable at a glance: no.

import { x25519, ed25519 } from '@noble/curves/ed25519.js';
import { p256 } from '@noble/curves/nist.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
import { hkdf as nobleHkdf } from '@noble/hashes/hkdf.js';
import { concatBytes } from '@noble/hashes/utils.js';

export const HASH_LEN = 32; // SHA-256
export const KEY_LEN = 32; // ChaCha20 / x25519 key
export const DH_LEN = 32; // x25519 public key + shared secret
export const TAG_LEN = 16; // Poly1305 tag
export const NONCE_LEN = 12; // ChaCha20-Poly1305 nonce

export interface KeyPair {
  readonly priv: Uint8Array;
  readonly pub: Uint8Array;
}

// — hashing —

export function sha256d(data: Uint8Array): Uint8Array {
  return sha256(data);
}

export function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha256, key, data);
}

// — X25519 Diffie-Hellman —

export function x25519Keygen(): KeyPair {
  const priv = x25519.utils.randomSecretKey();
  return { priv, pub: x25519.getPublicKey(priv) };
}

export function x25519PublicKey(priv: Uint8Array): Uint8Array {
  return x25519.getPublicKey(priv);
}

// Raw X25519 (RFC 7748). A peer can force the all-zero output by sending a
// low-order point; Noise's security does not rely on rejecting that (the
// transcript hash binds the ephemerals), and our callers treat any DH failure
// as a failed handshake, so we surface the raw result and let the AEAD tags be
// the gate.
export function x25519Dh(priv: Uint8Array, pub: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(priv, pub);
}

// — Ed25519 signatures (RFC 8032) —
//
// Used ONLY for authenticated address registration (see registerAuth.ts): the
// host proves control of an address by signing each register frame. The key is
// derived from the host's x25519 static key (HKDF, domain-separated) — never the
// DH scalar reused directly. A `seed` here is the 32-byte Ed25519 private seed.
// The Link server verifies these signatures with Node's built-in crypto (it has
// no @noble dependency), so the wire form is the raw 32-byte public key + raw
// 64-byte signature — interoperable by construction (both are RFC 8032).

export function ed25519PublicKey(seed: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(seed);
}

export function ed25519Sign(seed: Uint8Array, message: Uint8Array): Uint8Array {
  return ed25519.sign(message, seed);
}

export function ed25519Verify(sig: Uint8Array, message: Uint8Array, pub: Uint8Array): boolean {
  try {
    return ed25519.verify(sig, message, pub);
  } catch {
    return false;
  }
}

// — ChaCha20-Poly1305 AEAD with the Noise nonce layout —

// Noise encodes the 64-bit message counter `n` as a 96-bit nonce: 32 bits of
// zeros followed by the little-endian counter. Getting this exact is what makes
// our transport interoperate with the published Noise test vectors.
export function noiseNonce(n: bigint): Uint8Array {
  if (n < 0n || n > 0xffff_ffff_ffff_ffffn) throw new RangeError('nonce counter out of range');
  const nonce = new Uint8Array(NONCE_LEN);
  new DataView(nonce.buffer).setBigUint64(4, n, true); // bytes 0..3 stay zero
  return nonce;
}

export function aeadEncrypt(key: Uint8Array, n: bigint, ad: Uint8Array, plaintext: Uint8Array): Uint8Array {
  return chacha20poly1305(key, noiseNonce(n), ad).encrypt(plaintext);
}

// Throws on authentication failure (tamper, wrong key, or wrong nonce). Callers
// MUST treat a throw as "reject this frame / abort this handshake" — never
// retry with a different nonce.
export function aeadDecrypt(key: Uint8Array, n: bigint, ad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  return chacha20poly1305(key, noiseNonce(n), ad).decrypt(ciphertext);
}

// — HKDF —

// Noise's bespoke HKDF: HMAC-extract with the chaining key as the salt, then
// expand into 2 or 3 fixed 32-byte outputs. Implemented straight from the spec
// (Noise §4.3) rather than via the generic HKDF so the structure is auditable
// line-for-line and the chaining-key role is explicit.
export function hkdfNoise(chainingKey: Uint8Array, ikm: Uint8Array, outputs: 2): [Uint8Array, Uint8Array];
export function hkdfNoise(chainingKey: Uint8Array, ikm: Uint8Array, outputs: 3): [Uint8Array, Uint8Array, Uint8Array];
export function hkdfNoise(chainingKey: Uint8Array, ikm: Uint8Array, outputs: 2 | 3): Uint8Array[] {
  const tempKey = hmacSha256(chainingKey, ikm);
  const o1 = hmacSha256(tempKey, Uint8Array.of(1));
  const o2 = hmacSha256(tempKey, concatBytes(o1, Uint8Array.of(2)));
  if (outputs === 2) return [o1, o2];
  const o3 = hmacSha256(tempKey, concatBytes(o2, Uint8Array.of(3)));
  return [o1, o2, o3];
}

// Standard RFC 5869 HKDF (extract+expand) for deriving keys outside the Noise
// state machine — e.g. turning a SPAKE2 shared secret into two transport keys.
export function hkdfSha256(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  return nobleHkdf(sha256, ikm, salt, info, length);
}

// — P-256 group, re-exported for the SPAKE2 module —
export const P256Point = p256.Point;
export const P256_ORDER: bigint = p256.Point.Fn.ORDER;
