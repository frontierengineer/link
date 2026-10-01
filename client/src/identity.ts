// Keys and ids (section 2). One 32-byte seed yields the node's Ed25519 identity
// and its X25519 session key; the node id is a hash of the Ed25519 public key.

import { b32, fromB32, randomBytes, utf8, EMPTY } from './bytes.js';
import { clampX25519, ed25519Public, ed25519Sign, hkdf, sha256, x25519Public } from './crypto.js';

export interface Identity {
  /** The 32-byte secret seed. Persist it; it never leaves the node. */
  readonly seed: Uint8Array;
  /** The node id: 26 lowercase base32 characters. */
  readonly id: string;
  readonly ed25519: { readonly seed: Uint8Array; readonly pub: Uint8Array };
  /** `priv` is clamped. */
  readonly x25519: { readonly priv: Uint8Array; readonly pub: Uint8Array };
  sign(message: Uint8Array): Uint8Array;
}

export function identityFromSeed(seed: Uint8Array): Identity {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) throw new TypeError('seed must be 32 bytes');
  const edSeed = hkdf(seed, EMPTY, utf8('frontier-link/1/ed25519'), 32);
  const xPriv = clampX25519(hkdf(seed, EMPTY, utf8('frontier-link/1/x25519'), 32));
  const edPub = ed25519Public(edSeed);
  return Object.freeze({
    seed: seed.slice(),
    id: nodeIdFromEd25519(edPub),
    ed25519: Object.freeze({ seed: edSeed, pub: edPub }),
    x25519: Object.freeze({ priv: xPriv, pub: x25519Public(xPriv) }),
    sign: (message: Uint8Array) => ed25519Sign(edSeed, message),
  });
}

export function createIdentity(): Identity {
  return identityFromSeed(randomBytes(32));
}

/** `b32(SHA-256(ed25519Public)[0..16])`. */
export function nodeIdFromEd25519(pub: Uint8Array): string {
  return b32(nodeIdBytesFromEd25519(pub));
}

export function nodeIdBytesFromEd25519(pub: Uint8Array): Uint8Array {
  return sha256(pub).slice(0, 16);
}

const NODE_ID_RE = /^[a-z2-7]{26}$/;

export function isNodeId(s: unknown): s is string {
  if (typeof s !== 'string' || !NODE_ID_RE.test(s)) return false;
  try {
    fromB32(s);
    return true;
  } catch {
    return false;
  }
}

/** The raw 16 bytes a frame's `peer` field carries. */
export function nodeIdToBytes(id: string): Uint8Array {
  if (!isNodeId(id)) throw new Error(`not a node id: ${id}`);
  return fromB32(id);
}

export function nodeIdFromBytes(b: Uint8Array): string {
  if (b.length !== 16) throw new Error('node id must be 16 bytes');
  return b32(b);
}
