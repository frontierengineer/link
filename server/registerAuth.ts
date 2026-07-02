// Verifier for AUTHENTICATED address registration (the anti-squat boundary).
//
// A `register` frame carries an `auth` object: the host's Ed25519 public key, a
// timestamp, a nonce, and a signature over a canonical message binding the
// address + ts + nonce. This module checks that signature and the freshness
// window; the registry (registry.ts) holds the trust-on-first-use PIN state and
// decides accept/replace/reject. Splitting it this way keeps registry pure (no
// crypto, unit-testable with plain objects) and all crypto/time here.
//
// Zero new dependencies: Link's only runtime dependency is `ws`, so verification
// uses Node's BUILT-IN crypto (Ed25519 is RFC 8032; the client signs with @noble,
// the wire form is raw 32-byte key + raw 64-byte signature, so the two
// interoperate by construction). The signed bytes are reproduced here EXACTLY as
// the client builds them in link/client/src/registerAuth.ts — keep in lock-step.

import { createHash, createPublicKey, verify, type KeyObject } from 'node:crypto';

// Must equal the client's REGISTER_DOMAIN, and the length-prefix framing must
// match the client's bytes.ts Writer.lenStr (u32 big-endian length + UTF-8).
const REGISTER_DOMAIN = Buffer.from('frontier-link-register-v1', 'utf8');

// A register timestamp must be within this much of the server clock. Bounds how
// long a captured frame stays replayable to a DIFFERENT Link instance; within the
// window the registry's strictly-increasing-timestamp rule blocks replays to the
// SAME instance. Generous enough to tolerate ordinary host/Link clock drift.
export const REGISTER_MAX_SKEW_MS = 5 * 60 * 1000;

const ED25519_PUB_LEN = 32;
const ED25519_SIG_LEN = 64;
const MAX_NONCE_LEN = 88; // base64url of a generous nonce; bounds work per frame

function lenStr(s: string): Buffer {
  const body = Buffer.from(s, 'utf8');
  const head = Buffer.alloc(4);
  head.writeUInt32BE(body.length, 0);
  return Buffer.concat([head, body]);
}

// The canonical bytes a register signs. `origin` is the Link authority the frame
// is meant for (host[:port]); binding it means a signature captured at one Link no
// longer verifies at another, so a still-fresh frame cannot be replayed across
// instances. An empty origin binds nothing (kept for the length-prefix framing).
// Reproduced byte-for-byte by the client (link/client/src/registerAuth.ts).
export function registerSigningMessage(address: string, ts: number, nonce: string, origin = ''): Buffer {
  return Buffer.concat([REGISTER_DOMAIN, lenStr(address), lenStr(String(ts)), lenStr(nonce), lenStr(origin)]);
}

// The address that a given register public key commits to: base64url(SHA-256(pub)).
// A register's address MUST equal this: an address is a commitment to a key nobody
// else holds, so squatting is impossible by construction (not merely refused). This
// is the ONLY address model — there is no opaque-handle address. `pub` is the raw
// 32-byte Ed25519 key.
export function addressForRegisterKey(pub: Buffer): string {
  return createHash('sha256').update(pub).digest('base64url');
}

// What a verified register yields: the pinned-key identity (pub, base64url) and
// the frame's timestamp. The registry uses `pub` for the TOFU pin / same-key
// check and `ts` for its strictly-increasing anti-replay rule.
export interface VerifiedRegister {
  pub: string;
  ts: number;
}

function importEd25519(pub: Buffer): KeyObject | null {
  try {
    return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: pub.toString('base64url') }, format: 'jwk' });
  } catch {
    return null;
  }
}

// Options for the introduction-plane checks that ride alongside signature
// verification. An additive gate that never touches the end-to-end crypto.
export interface RegisterAuthPolicy {
  // The Link authority the signature must be bound to (host[:port]). The client
  // folds the uplink it dialed into its signature; verifying against our own
  // origin rejects a frame signed for a different Link.
  origin: string;
}

// Verify the auth on a register frame. Returns the pinned-key identity on
// success, or null if anything is missing, malformed, out of the skew window, the
// signature does not check out, or the address is not the commitment to the
// presenting key (address-key binding is always enforced). A null result means
// "reject this frame".
export function verifyRegisterAuth(address: string, auth: unknown, now: number, policy: RegisterAuthPolicy): VerifiedRegister | null {
  if (!auth || typeof auth !== 'object') return null;
  const a = auth as Record<string, unknown>;
  if (a.alg !== 'ed25519') return null;
  if (typeof a.pub !== 'string' || typeof a.sig !== 'string' || typeof a.nonce !== 'string') return null;
  if (typeof a.ts !== 'number' || !Number.isInteger(a.ts)) return null;
  if (Math.abs(now - a.ts) > REGISTER_MAX_SKEW_MS) return null;
  if (a.nonce.length === 0 || a.nonce.length > MAX_NONCE_LEN) return null;

  const pub = Buffer.from(a.pub, 'base64url');
  const sig = Buffer.from(a.sig, 'base64url');
  if (pub.length !== ED25519_PUB_LEN || sig.length !== ED25519_SIG_LEN) return null;

  // The address is a commitment to this key: reject before the signature check so a
  // squatter cannot even present a frame for an address it does not own the key for.
  if (address !== addressForRegisterKey(pub)) return null;

  const key = importEd25519(pub);
  if (!key) return null;
  const message = registerSigningMessage(address, a.ts, a.nonce, policy.origin);
  let ok = false;
  try {
    ok = verify(null, message, key, sig);
  } catch {
    return null;
  }
  if (!ok) return null;
  // Normalise pub to its canonical base64url form so the pin compares stably.
  return { pub: pub.toString('base64url'), ts: a.ts };
}
