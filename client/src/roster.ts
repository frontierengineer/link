// The roster (section 3): the signed list of a network's members. Only the
// primary signs it; every member checks it against the primary key it pinned.

import { b64u, concat, equalBytes, fromB64uLen, utf8 } from './bytes.js';
import { ed25519Verify } from './crypto.js';
import { isNodeId, nodeIdFromEd25519, type Identity } from './identity.js';
import { canonicalize } from './jcs.js';

export type MemberKind = 'primary' | 'worker' | 'surface' | 'mcp';
export type PairingKind = Exclude<MemberKind, 'primary'>;

export const MEMBER_KINDS: readonly MemberKind[] = ['primary', 'worker', 'surface', 'mcp'];
export const PAIRING_KINDS: readonly PairingKind[] = ['worker', 'surface', 'mcp'];

export interface RosterMember {
  id: string;
  ed25519: string;
  x25519: string;
  kind: MemberKind;
}

export interface UnsignedRoster {
  network: string;
  version: number;
  issuedAt: number;
  relay: string;
  primary: { ed25519: string };
  members: RosterMember[];
}

export interface Roster extends UnsignedRoster {
  signature: string;
}

const ROSTER_LABEL = utf8('frontier-link/1/roster');

/** The bytes the primary signs: the label followed by JCS of the roster without `signature`. */
export function rosterSigningBytes(roster: UnsignedRoster | Roster): Uint8Array {
  const { signature: _omit, ...rest } = roster as Roster;
  return concat(ROSTER_LABEL, utf8(canonicalize(rest)));
}

export function compareIds(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Sorts members, then signs. `primary` must be the roster's primary identity. */
export function signRoster(unsigned: UnsignedRoster, primary: Identity): Roster {
  const members = [...unsigned.members].sort((a, b) => compareIds(a.id, b.id));
  const body: UnsignedRoster = { ...unsigned, members };
  const signature = b64u(primary.sign(rosterSigningBytes(body)));
  const roster: Roster = { ...body, signature };
  const problem = rosterProblem(roster);
  if (problem) throw new Error(`signRoster: ${problem}`);
  return roster;
}

export function memberFromIdentity(identity: Identity, kind: MemberKind): RosterMember {
  return {
    id: identity.id,
    ed25519: b64u(identity.ed25519.pub),
    x25519: b64u(identity.x25519.pub),
    kind,
  };
}

/** The first roster of a new network: version 1, the primary alone. */
export function createNetwork(opts: { identity: Identity; relay: string; now?: number }): Roster {
  return signRoster(
    {
      network: opts.identity.id,
      version: 1,
      issuedAt: opts.now ?? Date.now(),
      relay: opts.relay,
      primary: { ed25519: b64u(opts.identity.ed25519.pub) },
      members: [memberFromIdentity(opts.identity, 'primary')],
    },
    opts.identity,
  );
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function isNonNegInt(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
}

/** Why `value` is not a valid roster, or `null` when it is (section 3, "Valid"). */
export function rosterProblem(value: unknown): string | null {
  if (!isPlainObject(value)) return 'not an object';
  const r = value;
  if (!isNodeId(r.network)) return 'network is not a node id';
  if (!isNonNegInt(r.version) || r.version < 1) return 'version is not a positive integer';
  if (!isNonNegInt(r.issuedAt)) return 'issuedAt is not a non-negative integer';
  if (typeof r.relay !== 'string') return 'relay is not a string';
  if (!isPlainObject(r.primary)) return 'primary is not an object';
  let primaryKey: Uint8Array;
  try {
    primaryKey = fromB64uLen(r.primary.ed25519, 32, 'primary.ed25519');
  } catch (e) {
    return (e as Error).message;
  }
  if (nodeIdFromEd25519(primaryKey) !== r.network) return 'network is not derived from primary.ed25519';
  if (!Array.isArray(r.members)) return 'members is not an array';
  let primaries = 0;
  let prev: string | null = null;
  for (const m of r.members as unknown[]) {
    if (!isPlainObject(m)) return 'member is not an object';
    if (!isNodeId(m.id)) return 'member id is not a node id';
    if (prev !== null && compareIds(prev, m.id) >= 0) return 'members are not sorted by id (or repeat)';
    prev = m.id;
    let ed: Uint8Array;
    try {
      ed = fromB64uLen(m.ed25519, 32, 'member ed25519');
      fromB64uLen(m.x25519, 32, 'member x25519');
    } catch (e) {
      return (e as Error).message;
    }
    if (nodeIdFromEd25519(ed) !== m.id) return `member ${m.id}: id is not derived from its ed25519`;
    if (typeof m.kind !== 'string' || !MEMBER_KINDS.includes(m.kind as MemberKind)) return `member ${m.id}: bad kind`;
    if (m.kind === 'primary') {
      primaries++;
      if (m.ed25519 !== r.primary.ed25519) return 'primary member key differs from primary.ed25519';
      if (m.id !== r.network) return 'primary member id differs from network';
    }
  }
  if (primaries !== 1) return 'roster must have exactly one primary member';
  let sig: Uint8Array;
  try {
    sig = fromB64uLen(r.signature, 64, 'signature');
  } catch (e) {
    return (e as Error).message;
  }
  let signed: Uint8Array;
  try {
    signed = rosterSigningBytes(r as unknown as Roster);
  } catch (e) {
    return (e as Error).message;
  }
  if (!ed25519Verify(sig, signed, primaryKey)) return 'signature does not verify';
  return null;
}

export function isValidRoster(value: unknown): value is Roster {
  return rosterProblem(value) === null;
}

/**
 * Section 3 acceptance: valid, signed by the pinned primary key, and newer than
 * the version held. Returns the reason for refusal, or `null` to accept.
 */
export function acceptanceProblem(candidate: unknown, pinnedPrimary: string, heldVersion: number): string | null {
  const problem = rosterProblem(candidate);
  if (problem) return problem;
  const r = candidate as Roster;
  if (r.primary.ed25519 !== pinnedPrimary) return 'roster is signed by a different primary';
  if (r.version <= heldVersion) return 'roster is not newer than the one held';
  return null;
}

export function findMember(roster: Roster, id: string): RosterMember | undefined {
  return roster.members.find((m) => m.id === id);
}

export function findMemberByX25519(roster: Roster, x25519: Uint8Array): RosterMember | undefined {
  return roster.members.find((m) => equalBytes(fromB64uLen(m.x25519, 32, 'x25519'), x25519));
}

/** A deep copy that is safe to hand out or persist. */
export function cloneRoster(r: Roster): Roster {
  return JSON.parse(JSON.stringify(r)) as Roster;
}
