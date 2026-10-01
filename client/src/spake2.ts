// SPAKE2 over P-256, RFC 9382 ciphersuite P256-SHA256-HKDF-HMAC, with this
// protocol's parameters (section 5.3). A is the newcomer and uses M; B is the
// primary and uses N. Proven against RFC 9382 Appendix B in the tests.

import { concat, EMPTY, equalBytes, u64le, utf8 } from './bytes.js';
import { hkdf, hmacSha256, P256_ORDER, P256Point, sha256, type P256PointT } from './crypto.js';

// RFC 9382 section 6, compressed SEC1.
const M = P256Point.fromHex('02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f');
const N = P256Point.fromHex('03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49');
const G = P256Point.BASE;

export const SPAKE2_ID_A = utf8('frontier-link/1/newcomer');
export const SPAKE2_ID_B = utf8('frontier-link/1/primary');

export type Spake2Role = 'A' | 'B';

export function bytesToBigint(b: Uint8Array): bigint {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}

export function scalarTo32(v: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** `w` from a normalised pairing code: 40 HKDF bytes, big-endian, mod n. */
export function deriveW(code: string): bigint {
  const wide = hkdf(utf8(code), EMPTY, utf8('frontier-link/1/spake2/w'), 40);
  const w = bytesToBigint(wide) % P256_ORDER;
  if (w === 0n) throw new Error('spake2: w = 0 is refused');
  return w;
}

/** A secret scalar from 48 random bytes, mod n. */
export function scalarFromRandom(r: Uint8Array): bigint {
  if (r.length !== 48) throw new Error('spake2: scalar randomness must be 48 bytes');
  return bytesToBigint(r) % P256_ORDER;
}

export interface Spake2Keys {
  /** The full TT transcript. */
  tt: Uint8Array;
  /** SHA-256(TT). */
  hash: Uint8Array;
  ke: Uint8Array;
  ka: Uint8Array;
  kcA: Uint8Array;
  kcB: Uint8Array;
  cA: Uint8Array;
  cB: Uint8Array;
  /** The confirmation this side sends, and the one it expects. */
  ours: Uint8Array;
  theirs: Uint8Array;
}

export interface Spake2Options {
  role: Spake2Role;
  w: bigint;
  idA?: Uint8Array;
  idB?: Uint8Array;
  /** Appended to "ConfirmationKeys" in the KcA/KcB info (the code id here). */
  aad?: Uint8Array;
  /** The secret scalar x (A) or y (B); fresh randomness when absent. */
  scalar?: bigint;
}

export class Spake2 {
  readonly role: Spake2Role;
  /** pA or pB: uncompressed SEC1, 65 bytes. */
  readonly share: Uint8Array;
  private readonly w: bigint;
  private readonly xy: bigint;
  private readonly idA: Uint8Array;
  private readonly idB: Uint8Array;
  private readonly aad: Uint8Array;

  constructor(opts: Spake2Options) {
    this.role = opts.role;
    this.w = opts.w % P256_ORDER;
    if (this.w === 0n) throw new Error('spake2: w = 0 is refused');
    this.idA = opts.idA ?? SPAKE2_ID_A;
    this.idB = opts.idB ?? SPAKE2_ID_B;
    this.aad = opts.aad ?? EMPTY;
    let xy = opts.scalar;
    while (xy === undefined || xy % P256_ORDER === 0n) {
      if (opts.scalar !== undefined) throw new Error('spake2: secret scalar is 0');
      const r = new Uint8Array(48);
      globalThis.crypto.getRandomValues(r);
      xy = scalarFromRandom(r);
    }
    this.xy = xy % P256_ORDER;
    const blind = this.role === 'A' ? M : N;
    this.share = blind.multiply(this.w).add(G.multiply(this.xy)).toBytes(false);
  }

  finish(peerShare: Uint8Array): Spake2Keys {
    let peer: P256PointT;
    try {
      if (peerShare.length !== 65) throw new Error('length');
      peer = P256Point.fromBytes(peerShare);
      peer.assertValidity();
    } catch {
      throw new Error('spake2: peer share is not a valid uncompressed P-256 point');
    }
    // K = h*x*(pB - w*N) for A, h*y*(pA - w*M) for B; h = 1 on P-256.
    const unblind = this.role === 'A' ? N : M;
    const kPoint = peer.subtract(unblind.multiply(this.w));
    if (kPoint.is0()) throw new Error('spake2: degenerate shared point');
    const K = kPoint.multiply(this.xy).toBytes(false);
    const pA = this.role === 'A' ? this.share : peerShare;
    const pB = this.role === 'A' ? peerShare : this.share;
    const L = (b: Uint8Array) => concat(u64le(b.length), b);
    const tt = concat(L(this.idA), L(this.idB), L(pA), L(pB), L(K), L(scalarTo32(this.w)));
    const hash = sha256(tt);
    const ke = hash.slice(0, 16);
    const ka = hash.slice(16, 32);
    const kc = hkdf(ka, EMPTY, concat(utf8('ConfirmationKeys'), this.aad), 32);
    const kcA = kc.slice(0, 16);
    const kcB = kc.slice(16, 32);
    const cA = hmacSha256(kcA, tt);
    const cB = hmacSha256(kcB, tt);
    return {
      tt, hash, ke, ka, kcA, kcB, cA, cB,
      ours: this.role === 'A' ? cA : cB,
      theirs: this.role === 'A' ? cB : cA,
    };
  }
}

/** Constant-time check of the peer's confirmation MAC. */
export function verifyConfirmation(keys: Spake2Keys, received: Uint8Array): boolean {
  return equalBytes(received, keys.theirs);
}
