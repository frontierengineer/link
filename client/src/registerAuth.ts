// Authenticated address registration — the anti-squat trust boundary.
//
// An address is an opaque, high-entropy, long-lived rendezvous handle. Link pins
// it to a key so that knowing an address is not enough to claim it:
//
//   • The host signs every `register` frame with a long-lived key, binding the
//     address + a fresh timestamp + nonce (so a captured frame cannot be replayed).
//   • Link pins the presenting public key on the FIRST registration of an address
//     (trust-on-first-use) and, for the lifetime of that registration, requires
//     every later register for the same address to be signed by the SAME pinned
//     key. A party who merely KNOWS an address — but does not hold the key — cannot
//     steal the rendezvous. (End-to-end crypto stops impersonation regardless; this
//     protects the introduction itself from being disrupted.)
//
// The signing key is an Ed25519 key DERIVED from the host's x25519 static private
// key via HKDF with a dedicated info string. This binds the registration identity
// to the host's static identity and is deterministic (stable across restarts)
// without reusing the DH scalar as a signing scalar.
//
// The exact bytes signed here are reproduced byte-for-byte by Link's own verifier
// (link/server/registerAuth.ts). Keep the two in lock-step.

import { ed25519PublicKey, ed25519Sign, hkdfSha256 } from './crypto.js';
import { Writer, toB64url, randomBytes, utf8 } from './bytes.js';

// Domain-separation tag prefixed to every signed message. Bumping the version
// string instantly invalidates every old signature and guarantees a registration
// signature can never be a valid signature for any other protocol message.
const REGISTER_DOMAIN = utf8('frontier-link-register-v1');
// HKDF `info` for deriving the Ed25519 signing seed from the x25519 static key.
const SIGNER_HKDF_INFO = utf8('frontier-link-register-ed25519-v1');
const NONCE_BYTES = 16;

export interface RegisterSigner {
  readonly pub: Uint8Array; // 32-byte Ed25519 public key
  sign(message: Uint8Array): Uint8Array; // 64-byte Ed25519 signature
}

// The auth object carried inside a signed `register` frame.
export interface RegisterAuth {
  alg: 'ed25519';
  pub: string; // base64url, 32-byte Ed25519 public key
  ts: number; // ms since epoch — bounds replay to the server's skew window
  nonce: string; // base64url random — replay uniqueness within the window
  sig: string; // base64url, 64-byte Ed25519 signature over registerSigningMessage
}

// The canonical bytes signed: a fixed domain tag, then LENGTH-PREFIXED address,
// decimal timestamp and nonce. Length-prefixing makes the encoding unambiguous
// for any field contents (no delimiter can be smuggled in). Link rebuilds these
// exact bytes before verifying.
export function registerSigningMessage(address: string, ts: number, nonce: string): Uint8Array {
  return new Writer().bytes(REGISTER_DOMAIN).lenStr(address).lenStr(String(ts)).lenStr(nonce).finish();
}

// Derive the long-lived Ed25519 registration signer from a 32-byte x25519 static
// private key. Deterministic and domain-separated from the key's DH use.
export function registerSignerFromStatic(x25519Priv: Uint8Array): RegisterSigner {
  const seed = hkdfSha256(x25519Priv, new Uint8Array(0), SIGNER_HKDF_INFO, 32);
  const pub = ed25519PublicKey(seed);
  return { pub, sign: (message) => ed25519Sign(seed, message) };
}

// Build the auth object for a `register` frame: a fresh timestamp + nonce, signed
// over the canonical message. Call this for EVERY register/re-register so each
// frame is unique (the server rejects a stale/replayed timestamp).
export function makeRegisterAuth(signer: RegisterSigner, address: string): RegisterAuth {
  const ts = Date.now();
  const nonce = toB64url(randomBytes(NONCE_BYTES));
  const sig = signer.sign(registerSigningMessage(address, ts, nonce));
  return { alg: 'ed25519', pub: toB64url(signer.pub), ts, nonce, sig: toB64url(sig) };
}
