// Pairing codes, code ids and pairing links (section 5.1).

import { fromB64uLen, randomBytes } from './bytes.js';
import { InvalidError } from './errors.js';
import { isNodeId } from './identity.js';
import { isRelayUrl } from './roster.js';

export const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
export const CODE_LENGTH = 8;
export const CODE_ID_LENGTH = 8;
/** The default code's id: 8 zero bytes (section 5.1). A primary holds at most one default code;
 * pairing parameters leave its id out, and a reader takes a missing id as this one. */
export const DEFAULT_CODE_ID = 'AAAAAAAAAAA';

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

/** A separate code's id: 8 random bytes, never the default code's 8 zero bytes. */
export function generateCodeId(): Uint8Array {
  for (;;) {
    const id = randomBytes(CODE_ID_LENGTH);
    if (id.some((b) => b !== 0)) return id;
  }
}

/** What a pairing code gives a newcomer (section 5.1): the pairing parameters, as read. */
export interface PairingLink {
  network: string;
  /** Canonical code, no hyphen. */
  code: string;
  /** b64u of the 8-byte code id: `DEFAULT_CODE_ID` when the parameters name none. */
  codeId: string;
  relay: string;
}

/** The pairing parameters to write: no `codeId` (or `DEFAULT_CODE_ID`) for the default code. */
export type PairingParts = Omit<PairingLink, 'codeId'> & { codeId?: string };

/** The pairing parameters (section 5.1), `v=1&n=…&c=…&i=…&r=…`, with no scheme around them and
 * no `i` for the default code. */
function paramString(p: PairingParts, Err: new (message: string) => Error): string {
  if (!isNodeId(p.network)) throw new Err('network is not a node id');
  const codeId = p.codeId ?? DEFAULT_CODE_ID;
  try {
    fromB64uLen(codeId, CODE_ID_LENGTH, 'code id');
  } catch (e) {
    throw new Err((e as Error).message);
  }
  let code: string;
  try {
    code = normalizeCode(p.code);
  } catch (e) {
    throw new Err((e as Error).message);
  }
  const i = codeId === DEFAULT_CODE_ID ? '' : `&i=${encodeURIComponent(codeId)}`;
  return `v=1&n=${encodeURIComponent(p.network)}&c=${encodeURIComponent(code)}${i}&r=${encodeURIComponent(p.relay)}`;
}

/** Reads pairing parameters (section 5.1); `what` names them in errors. */
function readParams(s: string, what: string, Err: new (message: string) => Error, versionMessage?: string): PairingLink {
  const params = new Map<string, string>();
  for (const part of s.split('&')) {
    if (part === '') continue;
    const eq = part.indexOf('=');
    if (eq < 0) throw new Err(`${what} parameter without a value: ${part}`);
    const key = part.slice(0, eq);
    if (params.has(key)) throw new Err(`${what} repeats ${key}`);
    let value: string;
    try {
      value = decodeURIComponent(part.slice(eq + 1));
    } catch {
      throw new Err(`${what}: malformed percent-encoding in ${key}`);
    }
    params.set(key, value);
  }
  const v = params.get('v');
  if (!v) throw new Err(versionMessage ?? `${what}: missing v`);
  if (v !== '1') throw new Err(versionMessage ?? `${what}: unknown version ${v}`);
  const network = params.get('n');
  const code = params.get('c');
  // A missing `i` is the default code's; an empty one is refused like every other empty value.
  const codeId = params.get('i') ?? DEFAULT_CODE_ID;
  const relay = params.get('r');
  if (!network) throw new Err(`${what}: missing n (the network id)`);
  if (!isNodeId(network)) throw new Err(`${what}: bad network id`);
  if (!code) throw new Err(`${what}: missing c (the code)`);
  if (!codeId) throw new Err(`${what}: empty i (the code id)`);
  try {
    fromB64uLen(codeId, CODE_ID_LENGTH, `${what} code id`);
  } catch (e) {
    throw new Err((e as Error).message);
  }
  if (!relay) throw new Err(`${what}: missing r (the relay)`);
  let proto: string;
  try {
    proto = new URL(relay).protocol;
  } catch {
    throw new Err(`${what}: relay is not a URL`);
  }
  if (proto !== 'wss:' && proto !== 'ws:') throw new Err(`${what}: relay must be a ws:// or wss:// URL`);
  let canonical: string;
  try {
    canonical = normalizeCode(code);
  } catch (e) {
    throw new Err((e as Error).message);
  }
  return { network, code: canonical, codeId, relay };
}

/**
 * The pairing parameters alone (section 5.1): `v=1&n=<network>&c=<code>&i=<code id>&r=<relay>`,
 * each value percent-encoded, with no `i` for the default code (no `codeId`, or
 * `DEFAULT_CODE_ID`). Link defines these, not a scheme: an application wraps them as it
 * likes, in a link's query or an https URL's fragment. Throws InvalidError for a network that is
 * not a node id, a code id not of 8 bytes, a code that is not one, or a relay that is not a
 * ws:// or wss:// URL.
 */
export function buildPairingParams(p: PairingParts): string {
  if (!isRelayUrl(p.relay)) throw new InvalidError('pairing parameters: relay must be a ws:// or wss:// URL');
  return paramString(p, InvalidError);
}

/**
 * Reads pairing parameters (section 5.1), as `buildPairingParams` writes them, in any order;
 * parameters it does not know are ignored. The code may be in its displayed form; a missing `i`
 * is the default code's, `DEFAULT_CODE_ID`. Throws
 * InvalidError on a missing parameter, an unknown version, a repeated parameter, or a value that
 * is not what its parameter holds (the relay as `isRelayUrl` says, section 3.2).
 */
export function parsePairingParams(params: string): PairingLink {
  const p = readParams(params, 'pairing parameters', InvalidError);
  if (!isRelayUrl(p.relay)) throw new InvalidError('pairing parameters: relay must be a ws:// or wss:// URL');
  return p;
}

/** `frontier://pair?` followed by the pairing parameters: one wrapping of them (section 5.1). */
export function buildPairingLink(p: PairingParts): string {
  return `frontier://pair?${paramString(p, Error)}`;
}

/** Reads a `frontier://pair?` link: the pairing parameters in that wrapping (section 5.1). */
export function parsePairingLink(link: string): PairingLink {
  const prefix = 'frontier://pair?';
  if (!link.startsWith(prefix)) throw new Error('not a frontier://pair link');
  return readParams(link.slice(prefix.length), 'pairing link', Error, 'unsupported pairing link version');
}
