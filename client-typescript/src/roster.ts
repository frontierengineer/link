// The roster (section 3): the signed list of a network's members. The network
// key signs it, held by the primary alone; every member checks it against the
// network key it pinned.

import { b64u, concat, equalBytes, fromB64uLen, utf8 } from './bytes.js';
import { ed25519Verify } from './crypto.js';
import { createNetworkSeed, isNodeId, networkKeyFromSeed, nodeIdFromEd25519, type Identity, type NetworkKey } from './identity.js';
import { canonicalize } from './jcs.js';
import { RosterFullError } from './errors.js';
import { integerMember } from './json.js';

export interface RosterMember {
  id: string;
  ed25519: string;
  x25519: string;
}

export interface UnsignedRoster {
  network: string;
  version: number;
  issuedAt: number;
  relay: string;
  /** The network key's public half, b64u; `network` is derived from it. */
  networkKey: string;
  /** The node id of the primary: one of `members`. */
  primary: string;
  members: RosterMember[];
}

export interface Roster extends UnsignedRoster {
  signature: string;
}

const ROSTER_LABEL = utf8('frontier-link/1/roster');

/** The most a roster's JCS encoding, signature included, may take (section 3): one session message. */
export const MAX_ROSTER_BYTES = 65000;

/** The length of a roster's JCS encoding, signature included. */
export function rosterSize(roster: Roster): number {
  return utf8(canonicalize(roster)).length;
}

/** The bytes the network key signs: the label followed by JCS of the roster without `signature`. */
export function rosterSigningBytes(roster: UnsignedRoster | Roster): Uint8Array {
  const { signature: _omit, ...rest } = roster as Roster;
  return concat(ROSTER_LABEL, utf8(canonicalize(rest)));
}

export function compareIds(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Sorts members, then signs with the network key. */
export function signRoster(unsigned: UnsignedRoster, networkKey: NetworkKey): Roster {
  const members = [...unsigned.members].sort((a, b) => compareIds(a.id, b.id));
  const body: UnsignedRoster = { ...unsigned, members };
  const signature = b64u(networkKey.sign(rosterSigningBytes(body)));
  const roster: Roster = { ...body, signature };
  const problem = rosterProblem(roster);
  if (problem) throw new Error(`signRoster: ${problem}`);
  return roster;
}

export function memberFromIdentity(identity: Identity): RosterMember {
  return {
    id: identity.id,
    ed25519: b64u(identity.ed25519.pub),
    x25519: b64u(identity.x25519.pub),
  };
}

/** An Ed25519 signature's b64u length, for measuring a roster before it is signed. */
const PLACEHOLDER_SIGNATURE = 'A'.repeat(86);

/** The roster after `prev`, with `members` and `primary` (the same primary when absent),
 * unsigned: the next version, the same network. */
export function nextUnsignedRoster(prev: Roster, members: RosterMember[], now: number, primary = prev.primary): UnsignedRoster {
  return {
    network: prev.network,
    version: prev.version + 1,
    issuedAt: Math.max(now, prev.issuedAt),
    relay: prev.relay,
    networkKey: prev.networkKey,
    primary,
    members: [...members].sort((a, b) => compareIds(a.id, b.id)),
  };
}

/** The JCS size the roster after `prev`, with `members`, would have once signed. */
export function nextRosterSize(prev: Roster, members: RosterMember[], now: number): number {
  return rosterSize({ ...nextUnsignedRoster(prev, members, now), signature: PLACEHOLDER_SIGNATURE });
}

/** The roster after `prev`, with `members` and `primary`, signed. Throws RosterFullError over
 * 65000 bytes. */
export function signNextRoster(prev: Roster, members: RosterMember[], key: NetworkKey, now: number, primary = prev.primary): Roster {
  const size = nextRosterSize(prev, members, now);
  if (size > MAX_ROSTER_BYTES) throw new RosterFullError(size);
  return signRoster(nextUnsignedRoster(prev, members, now, primary), key);
}

/**
 * A new network (section 3.1): a network seed minted for it, apart from the node's own, and
 * its first roster, version 1, with `identity` alone as the primary. Persist the network seed
 * as secretly as the node's seed, and hand it to the primary as `networkSeed`.
 */
export function createNetwork(opts: { identity: Identity; relay: string; now?: number; networkSeed?: Uint8Array }): {
  roster: Roster;
  networkSeed: Uint8Array;
} {
  const networkSeed = opts.networkSeed?.slice() ?? createNetworkSeed();
  const key = networkKeyFromSeed(networkSeed);
  const roster = signRoster(
    {
      network: key.id,
      version: 1,
      issuedAt: opts.now ?? Date.now(),
      relay: opts.relay,
      networkKey: b64u(key.ed25519.pub),
      primary: opts.identity.id,
      members: [memberFromIdentity(opts.identity)],
    },
    key,
  );
  return { roster, networkSeed };
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Why `value` is not a valid roster, or `null` when it is (section 3, "Valid"). */
export function rosterProblem(value: unknown): string | null {
  if (!isPlainObject(value)) return 'not an object';
  const r = value;
  if (!isNodeId(r.network)) return 'network is not an id';
  // Integer literals only (section 3): `12.0` and `1.2e1` are not versions, though JSON.parse
  // makes 12 of them.
  const version = integerMember(r, 'version');
  if (version === undefined || version < 1) return 'version is not a positive integer';
  const issuedAt = integerMember(r, 'issuedAt');
  if (issuedAt === undefined || issuedAt < 0) return 'issuedAt is not a non-negative integer';
  if (typeof r.relay !== 'string') return 'relay is not a string';
  let networkKey: Uint8Array;
  try {
    networkKey = fromB64uLen(r.networkKey, 32, 'networkKey');
  } catch (e) {
    return (e as Error).message;
  }
  if (nodeIdFromEd25519(networkKey) !== r.network) return 'network is not derived from networkKey';
  if (!isNodeId(r.primary)) return 'primary is not a node id';
  if (!Array.isArray(r.members)) return 'members is not an array';
  let primaryListed = false;
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
    if (m.id === r.primary) primaryListed = true;
  }
  if (!primaryListed) return 'primary is not a member';
  let size: number;
  try {
    size = rosterSize(r as unknown as Roster);
  } catch (e) {
    return (e as Error).message;
  }
  if (size > MAX_ROSTER_BYTES) return `roster is ${size} bytes, over the ${MAX_ROSTER_BYTES}-byte limit`;
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
  if (!ed25519Verify(sig, signed, networkKey)) return 'signature does not verify';
  return null;
}

export function isValidRoster(value: unknown): value is Roster {
  return rosterProblem(value) === null;
}

/**
 * Section 3 acceptance: valid, signed by the pinned network key, and newer than
 * the version held. Returns the reason for refusal, or `null` to accept.
 */
export function acceptanceProblem(candidate: unknown, pinnedNetworkKey: string, heldVersion: number): string | null {
  const problem = rosterProblem(candidate);
  if (problem) return problem;
  const r = candidate as Roster;
  if (r.networkKey !== pinnedNetworkKey) return 'roster is signed by another network key';
  if (r.version <= heldVersion) return 'roster is not newer than the one held';
  return null;
}

export function findMember(roster: Roster, id: string): RosterMember | undefined {
  return roster.members.find((m) => m.id === id);
}

/** The member the roster names primary: the one holding the network seed (section 3.1). */
export function primaryOf(roster: Roster): RosterMember {
  return roster.members.find((m) => m.id === roster.primary)!;
}

export function findMemberByX25519(roster: Roster, x25519: Uint8Array): RosterMember | undefined {
  return roster.members.find((m) => equalBytes(fromB64uLen(m.x25519, 32, 'x25519'), x25519));
}

/** A deep copy that is safe to hand out or persist. */
export function cloneRoster(r: Roster): Roster {
  return JSON.parse(JSON.stringify(r)) as Roster;
}
