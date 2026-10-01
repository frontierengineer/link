// The two signed statements besides the roster: registration (section 4.1) and
// resignation (section 7.3).

import { b64u, concat, fromB64uLen, lenStr, u64be } from './bytes.js';
import { ed25519Verify } from './crypto.js';
import type { Identity } from './identity.js';

/**
 * The lowercased `host[:port]` of a dialled URL, with the port only when it is
 * not the scheme's default (80 for ws/http, 443 for wss/https).
 */
export function originOf(url: string): string {
  const u = new URL(url);
  if (!['ws:', 'wss:', 'http:', 'https:'].includes(u.protocol)) throw new Error(`unsupported relay URL scheme: ${u.protocol}`);
  // URL already lowercases the host and drops a default port for these schemes.
  return u.host.toLowerCase();
}

export function registerSigningBytes(p: {
  network: string;
  node: string;
  challenge: Uint8Array;
  ts: number;
  origin: string;
}): Uint8Array {
  if (p.challenge.length !== 32) throw new Error('challenge must be 32 bytes');
  return concat(
    lenStr('frontier-link/1/register'),
    lenStr(p.network),
    lenStr(p.node),
    p.challenge,
    u64be(p.ts),
    lenStr(p.origin),
  );
}

export function resignSigningBytes(p: { network: string; node: string; ts: number }): Uint8Array {
  return concat(lenStr('frontier-link/1/resign'), lenStr(p.network), lenStr(p.node), u64be(p.ts));
}

export interface Resignation {
  node: string;
  ts: number;
  sig: string;
}

export function signResignation(identity: Identity, network: string, ts: number): Resignation {
  return { node: identity.id, ts, sig: b64u(identity.sign(resignSigningBytes({ network, node: identity.id, ts }))) };
}

export function verifyResignation(r: Resignation, network: string, ed25519: Uint8Array): boolean {
  try {
    const sig = fromB64uLen(r.sig, 64, 'sig');
    return ed25519Verify(sig, resignSigningBytes({ network, node: r.node, ts: r.ts }), ed25519);
  } catch {
    return false;
  }
}
