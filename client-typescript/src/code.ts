// Pairing codes, code ids and pairing links (section 5.1).

import { fromB64uLen, randomBytes } from './bytes.js';
import { isNodeId } from './identity.js';

export const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
export const CODE_LENGTH = 8;
export const CODE_ID_LENGTH = 8;

/** A fresh code in its canonical form: 8 Crockford characters, no hyphen. */
export function generateCode(): string {
  // 256 is a multiple of 32, so `byte & 31` is uniform.
  return [...randomBytes(CODE_LENGTH)].map((b) => CROCKFORD[b & 31]!).join('');
}

/**
 * The canonical code for user input: hyphens and whitespace dropped, upper-cased,
 * I and L read as 1, O as 0. Throws when the result is not 8 Crockford characters.
 */
export function normalizeCode(input: string): string {
  const code = input
    .replace(/[\s-]/g, '')
    .toUpperCase()
    .replace(/[IL]/g, '1')
    .replace(/O/g, '0');
  if (code.length !== CODE_LENGTH || [...code].some((c) => !CROCKFORD.includes(c))) {
    throw new Error('a pairing code is 8 characters from 0-9 and A-Z without I, L, O, U');
  }
  return code;
}

/** `XXXX-XXXX`. */
export function formatCode(code: string): string {
  const c = normalizeCode(code);
  return `${c.slice(0, 4)}-${c.slice(4)}`;
}

export function generateCodeId(): Uint8Array {
  return randomBytes(CODE_ID_LENGTH);
}

export interface PairingLink {
  network: string;
  /** Canonical code, no hyphen. */
  code: string;
  /** b64u of the 8-byte code id. */
  codeId: string;
  relay: string;
}

export function buildPairingLink(p: PairingLink): string {
  if (!isNodeId(p.network)) throw new Error('network is not a node id');
  fromB64uLen(p.codeId, CODE_ID_LENGTH, 'code id');
  return `frontier://pair?v=1&n=${p.network}&c=${normalizeCode(p.code)}&i=${p.codeId}&r=${encodeURIComponent(p.relay)}`;
}

export function parsePairingLink(link: string): PairingLink {
  const prefix = 'frontier://pair?';
  if (!link.startsWith(prefix)) throw new Error('not a frontier://pair link');
  const params = new Map<string, string>();
  for (const part of link.slice(prefix.length).split('&')) {
    if (part === '') continue;
    const eq = part.indexOf('=');
    if (eq < 0) throw new Error(`pairing link parameter without a value: ${part}`);
    const key = part.slice(0, eq);
    if (params.has(key)) throw new Error(`pairing link repeats ${key}`);
    params.set(key, decodeURIComponent(part.slice(eq + 1)));
  }
  if (params.get('v') !== '1') throw new Error('unsupported pairing link version');
  const network = params.get('n');
  const code = params.get('c');
  const codeId = params.get('i');
  const relay = params.get('r');
  if (!network || !isNodeId(network)) throw new Error('pairing link: bad network id');
  if (!code) throw new Error('pairing link: missing code');
  if (!codeId) throw new Error('pairing link: missing code id');
  fromB64uLen(codeId, CODE_ID_LENGTH, 'pairing link code id');
  if (!relay) throw new Error('pairing link: missing relay');
  const proto = new URL(relay).protocol;
  if (proto !== 'wss:' && proto !== 'ws:') throw new Error('pairing link: relay must be a ws:// or wss:// URL');
  return { network, code: normalizeCode(code), codeId, relay };
}
