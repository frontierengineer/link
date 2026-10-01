// The primitives of section 1, bound once from the audited @noble libraries.
// Nothing here invents a primitive; it pins the encodings the protocol needs
// (the Noise nonce layout, HKDF shapes, raw Ed25519 and X25519).

import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { p256 } from '@noble/curves/nist.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
import { hkdf as nobleHkdf } from '@noble/hashes/hkdf.js';
import { concat } from './bytes.js';

export interface KeyPair {
  readonly priv: Uint8Array;
  readonly pub: Uint8Array;
}

export function sha256(data: Uint8Array): Uint8Array {
  return nobleSha256(data);
}

export function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(nobleSha256, key, data);
}

/** RFC 5869 HKDF-SHA256. */
export function hkdf(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  return nobleHkdf(nobleSha256, ikm, salt, info, length);
}

/** Noise's HKDF (Noise section 4.3): two or three 32-byte outputs keyed by the chaining key. */
export function hkdfNoise(ck: Uint8Array, ikm: Uint8Array, outputs: 2 | 3): Uint8Array[] {
  const temp = hmacSha256(ck, ikm);
  const o1 = hmacSha256(temp, Uint8Array.of(1));
  const o2 = hmacSha256(temp, concat(o1, Uint8Array.of(2)));
  if (outputs === 2) return [o1, o2];
  return [o1, o2, hmacSha256(temp, concat(o2, Uint8Array.of(3)))];
}

// ── ChaCha20-Poly1305 with the nonce `4 zero bytes || u64le(counter)` ──

export function counterNonce(n: bigint): Uint8Array {
  if (n < 0n || n > 0xffff_ffff_ffff_ffffn) throw new RangeError('nonce counter out of range');
  const nonce = new Uint8Array(12);
  new DataView(nonce.buffer).setBigUint64(4, n, true);
  return nonce;
}

export function seal(key: Uint8Array, n: bigint, ad: Uint8Array, plaintext: Uint8Array): Uint8Array {
  return chacha20poly1305(key, counterNonce(n), ad).encrypt(plaintext);
}

/** Throws when the tag does not verify. */
export function open(key: Uint8Array, n: bigint, ad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  return chacha20poly1305(key, counterNonce(n), ad).decrypt(ciphertext);
}

// ── X25519 ──

export function clampX25519(k: Uint8Array): Uint8Array {
  const c = k.slice();
  c[0]! &= 248;
  c[31]! &= 127;
  c[31]! |= 64;
  return c;
}

export function x25519Public(priv: Uint8Array): Uint8Array {
  return x25519.getPublicKey(priv);
}

export function x25519Generate(): KeyPair {
  const priv = clampX25519(x25519.utils.randomSecretKey());
  return { priv, pub: x25519Public(priv) };
}

/** Throws on a low-order peer key; callers treat that as a failed handshake. */
export function x25519Dh(priv: Uint8Array, pub: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(priv, pub);
}

// ── Ed25519 (RFC 8032) ──

export function ed25519Public(seed: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(seed);
}

export function ed25519Sign(seed: Uint8Array, message: Uint8Array): Uint8Array {
  return ed25519.sign(message, seed);
}

/** Strict RFC 8032 verification (canonical encodings only), as Go's crypto/ed25519 does. */
export function ed25519Verify(sig: Uint8Array, message: Uint8Array, pub: Uint8Array): boolean {
  try {
    return ed25519.verify(sig, message, pub, { zip215: false });
  } catch {
    return false;
  }
}

// ── P-256, for SPAKE2 ──

export const P256Point = p256.Point;
export type P256PointT = InstanceType<typeof p256.Point>;
export const P256_ORDER: bigint = p256.Point.Fn.ORDER;
