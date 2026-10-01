// The two signed statements besides the roster: registration (section 4.1) and
// resignation (section 7.3).

import { b64u, concat, fromB64uLen, lenStr, u64be } from './bytes.js';
import { ed25519Verify } from './crypto.js';
import type { Identity } from './identity.js';

/**
 * The lowercased `host[:port]` of a dialled URL, with the port omitted when it
 * is 80 or 443 whatever the scheme (section 4.1), as the relay compares it.
 */
export function originOf(url: string): string {
  const u = new URL(url);
  if (!['ws:', 'wss:', 'http:', 'https:'].includes(u.protocol)) throw new Error(`unsupported relay URL scheme: ${u.protocol}`);
  // URL lowercases the host and drops the scheme's own default port; 80 and 443 go for any scheme.
  return (u.port === '80' || u.port === '443' ? u.hostname : u.host).toLowerCase();
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
