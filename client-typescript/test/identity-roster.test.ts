// Keys and ids (section 2), rosters (section 3), registration and resignation
// signatures (sections 4.1, 7.3).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { b32, b64u, concat, fromB64u, fromHex, toHex, utf8, EMPTY } from '../src/bytes.js';
import { ed25519Verify, hkdf, sha256 } from '../src/crypto.js';
import { createIdentity, createNetworkSeed, identityFromSeed, isNodeId, networkKeyFromSeed, nodeIdFromBytes, nodeIdToBytes } from '../src/identity.js';
import { canonicalize } from '../src/jcs.js';
import {
  acceptanceProblem,
  createNetwork,
  memberFromIdentity,
  MAX_ROSTER_BYTES,
  rosterProblem,
  rosterSigningBytes,
  rosterSize,
  signRoster,
  type Roster,
  type RosterMember,
} from '../src/roster.js';
import { originOf, registerSigningBytes, signResignation, verifyResignation } from '../src/signed.js';
import { ed25519 } from '@noble/curves/ed25519.js';

const seed = (n: number) => new Uint8Array(32).fill(n);

test('identity derivation follows section 2', () => {
  const id = identityFromSeed(seed(1));
  const edSeed = hkdf(seed(1), EMPTY, utf8('frontier-link/1/ed25519'), 32);
  assert.deepEqual(id.ed25519.seed, edSeed);
  assert.deepEqual(id.ed25519.pub, ed25519.getPublicKey(edSeed));
  const x = hkdf(seed(1), EMPTY, utf8('frontier-link/1/x25519'), 32);
  assert.equal(id.x25519.priv[0]! & 7, 0);
  assert.equal(id.x25519.priv[31]! & 0x80, 0);
  assert.equal(id.x25519.priv[31]! & 0x40, 0x40);
  assert.deepEqual(id.x25519.priv.subarray(1, 31), x.subarray(1, 31));
  assert.equal(id.id, b32(sha256(id.ed25519.pub).subarray(0, 16)));
  assert.equal(id.id.length, 26);
  assert.ok(isNodeId(id.id));
  assert.equal(nodeIdFromBytes(nodeIdToBytes(id.id)), id.id);
  assert.ok(ed25519Verify(id.sign(utf8('m')), utf8('m'), id.ed25519.pub));
  assert.equal(identityFromSeed(seed(1)).id, id.id);
  assert.notEqual(createIdentity().id, createIdentity().id);
  assert.throws(() => identityFromSeed(new Uint8Array(31)));
});

test('isNodeId refuses wrong length, case and trailing bits', () => {
  const id = identityFromSeed(seed(2)).id;
  assert.ok(!isNodeId(id.toUpperCase()));
  assert.ok(!isNodeId(id.slice(1)));
  assert.ok(!isNodeId(id.slice(0, 25) + '7')); // last char carries 2 data bits
});

const primary = identityFromSeed(seed(1));
const net = networkKeyFromSeed(seed(0x80));

test('a network has a seed of its own: its key and id derive from it, not from the primary (section 2)', () => {
  const edSeed = hkdf(seed(0x80), EMPTY, utf8('frontier-link/1/network'), 32);
  assert.deepEqual(net.ed25519.seed, edSeed);
  assert.deepEqual(net.ed25519.pub, ed25519.getPublicKey(edSeed));
  assert.equal(net.id, b32(sha256(net.ed25519.pub).subarray(0, 16)));
  assert.ok(isNodeId(net.id));
  // The same 32 bytes as a node seed give another key: the info string keeps them apart.
  assert.notEqual(net.id, identityFromSeed(seed(0x80)).id);
  assert.ok(ed25519Verify(net.sign(utf8('m')), utf8('m'), net.ed25519.pub));
  assert.throws(() => networkKeyFromSeed(new Uint8Array(31)));
  assert.notDeepEqual(createNetworkSeed(), createNetworkSeed());
  // createNetwork mints a seed apart from the node's, and the network id is the seed's.
  const made = createNetwork({ identity: primary, relay: 'wss://r/v1', now: 5 });
  const key = networkKeyFromSeed(made.networkSeed);
  assert.equal(made.roster.network, key.id);
  assert.notEqual(made.roster.network, primary.id);
  assert.equal(made.roster.networkKey, b64u(key.ed25519.pub));
  assert.notDeepEqual(made.networkSeed, primary.seed);
  assert.notEqual(createNetwork({ identity: primary, relay: 'wss://r/v1' }).roster.network, made.roster.network);
  assert.equal(createNetwork({ identity: primary, relay: 'wss://r/v1', networkSeed: seed(0x80) }).roster.network, net.id);
});
const alice = identityFromSeed(seed(2));
const bob = identityFromSeed(seed(3));

function sample(): Roster {
  return signRoster(
    {
      network: net.id,
      version: 3,
      issuedAt: 1790000000000,
      relay: 'wss://eu.frontierengineer.link/v1',
      networkKey: b64u(net.ed25519.pub),
      primary: primary.id,
      members: [
        memberFromIdentity(bob),
        memberFromIdentity(primary),
        memberFromIdentity(alice),
      ],
    },
    net,
  );
}

test('roster signing: label || JCS without signature, members sorted', () => {
  const r = sample();
  const ids = r.members.map((m) => m.id);
  assert.deepEqual(ids, [...ids].sort());
  const { signature, ...rest } = r;
  assert.deepEqual(rosterSigningBytes(r), concat(utf8('frontier-link/1/roster'), utf8(canonicalize(rest))));
  assert.ok(ed25519Verify(fromB64u(signature), rosterSigningBytes(r), net.ed25519.pub));
  assert.ok(!ed25519Verify(fromB64u(signature), rosterSigningBytes(r), primary.ed25519.pub));
  assert.equal(rosterProblem(r), null);
  const { roster: first } = createNetwork({ identity: primary, relay: 'wss://r/v1', now: 5 });
  assert.equal(first.version, 1);
  assert.equal(first.members.length, 1);
  assert.equal(first.primary, primary.id);
  assert.equal(rosterProblem(first), null);
});

test("a roster is signed by the network key: the primary's own key does not do, and a new primary changes no key", () => {
  const r = sample();
  const { signature: _s, ...rest } = r;
  const byPrimary: Roster = { ...rest, signature: b64u(primary.sign(rosterSigningBytes(rest))) };
  assert.match(rosterProblem(byPrimary)!, /signature does not verify/);
  // Once alice is the primary: the same network, key and signer.
  const moved = signRoster({ ...rest, version: 4, primary: alice.id }, net);
  assert.equal(rosterProblem(moved), null);
  assert.equal(acceptanceProblem(moved, r.networkKey, 3), null);
  assert.equal(moved.network, r.network);
});

test('a field the protocol does not define, on a member or the roster, is signed and otherwise ignored', () => {
  const r = sample();
  const { signature: _s, ...rest } = r;
  const labelled = { ...rest, members: rest.members.map((m, i) => (i === 0 ? { ...m, kind: 'label' } : m)), x: [1, 'two'] };
  const signed = { ...labelled, signature: b64u(net.sign(rosterSigningBytes(labelled as unknown as Roster))) };
  assert.equal(rosterProblem(signed), null);
  assert.equal(acceptanceProblem(signed, r.networkKey, 2), null);
  // Still signed: changing it after signing breaks the signature.
  const changed = { ...signed, members: signed.members.map((m, i) => (i === 0 ? { ...m, kind: 'other' } : m)) };
  assert.match(rosterProblem(changed)!, /signature does not verify/);
});

test('roster validation refuses each broken rule', () => {
  const mutate = (f: (r: Roster) => void, resign = true): Roster => {
    const r = JSON.parse(JSON.stringify(sample())) as Roster;
    f(r);
    if (!resign) return r;
    const { signature: _s, ...rest } = r;
    return { ...rest, signature: b64u(net.sign(rosterSigningBytes(rest as Roster))) };
  };
  const cases: [string, Roster][] = [
    ['tampered body', mutate((r) => (r.version = 4), false)],
    ['bad signature', mutate((r) => (r.signature = b64u(new Uint8Array(64))), false)],
    ['network not derived', mutate((r) => (r.network = alice.id))],
    ["network is the primary's node id", mutate((r) => (r.network = primary.id))],
    ['networkKey missing', mutate((r) => delete (r as Partial<Roster>).networkKey)],
    ['unsorted', mutate((r) => r.members.reverse())],
    ['duplicate', mutate((r) => r.members.push({ ...r.members[r.members.length - 1]! }))],
    ['id not derived', mutate((r) => (r.members.find((m) => m.id === alice.id)!.ed25519 = b64u(bob.ed25519.pub)))],
    ['primary missing', mutate((r) => delete (r as Partial<Roster>).primary)],
    ['primary not a node id', mutate((r) => (r.primary = 'P'))],
    ['primary not a member', mutate((r) => (r.members = r.members.filter((m) => m.id !== r.primary)))],
    ['version zero', mutate((r) => (r.version = 0))],
    ['fractional version', mutate((r) => (r.version = 1.5))],
    ['short key', mutate((r) => (r.members[0]!.x25519 = b64u(new Uint8Array(31))))],
  ];
  for (const [name, r] of cases) assert.notEqual(rosterProblem(r), null, name);
  // Another network's roster is valid, but not acceptable to a member that pinned this one.
  const { roster: other } = createNetwork({ identity: alice, relay: 'wss://r/v1' });
  assert.equal(rosterProblem(other), null);
  assert.match(acceptanceProblem(other, b64u(net.ed25519.pub), 0)!, /another network key/);
});

test('roster acceptance needs a newer version under the pinned network key', () => {
  const r = sample();
  const pin = r.networkKey;
  assert.equal(acceptanceProblem(r, pin, 2), null);
  assert.match(acceptanceProblem(r, pin, 3)!, /not newer/);
  assert.match(acceptanceProblem(r, pin, 4)!, /not newer/);
  assert.notEqual(acceptanceProblem({ ...r, version: 9 }, pin, 2), null);
});

test('registration signing bytes and origin', () => {
  assert.equal(originOf('wss://EU.Example.com/v1'), 'eu.example.com');
  assert.equal(originOf('wss://eu.example.com:443/v1'), 'eu.example.com');
  assert.equal(originOf('wss://eu.example.com:8443/v1'), 'eu.example.com:8443');
  assert.equal(originOf('ws://127.0.0.1:80/v1'), '127.0.0.1');
  assert.equal(originOf('ws://127.0.0.1:9000/v1'), '127.0.0.1:9000');
  assert.equal(originOf('ws://[::1]:9000/v1'), '[::1]:9000');
  // Section 4.1 (spec 71b8288): 80 and 443 are dropped whatever the scheme, as the relay does.
  assert.equal(originOf('ws://eu.example.com:443/v1'), 'eu.example.com');
  assert.equal(originOf('wss://eu.example.com:80/v1'), 'eu.example.com');
  assert.equal(originOf('ws://[::1]:443/v1'), '[::1]');
  assert.equal(originOf('wss://eu.example.com:4430/v1'), 'eu.example.com:4430');
  const challenge = fromHex('aa'.repeat(32));
  const bytes = registerSigningBytes({ network: 'n', node: 'm', challenge, ts: 1, origin: 'o:1' });
  assert.equal(
    toHex(bytes),
    '00000018' + toHex(utf8('frontier-link/1/register')) +
      '00000001' + '6e' +
      '00000001' + '6d' +
      'aa'.repeat(32) +
      '0000000000000001' +
      '00000003' + toHex(utf8('o:1')),
  );
});

test('resignation signatures verify only for the signer, network and node', () => {
  const r = signResignation(alice, primary.id, 1790000000000);
  assert.ok(verifyResignation(r, primary.id, alice.ed25519.pub));
  assert.ok(!verifyResignation(r, alice.id, alice.ed25519.pub));
  assert.ok(!verifyResignation({ ...r, ts: r.ts + 1 }, primary.id, alice.ed25519.pub));
  assert.ok(!verifyResignation(r, primary.id, bob.ed25519.pub));
});

test('a roster is valid up to 65000 bytes of JCS, signature included, and invalid one byte over', () => {
  const p = identityFromSeed(seed(9));
  const members: RosterMember[] = [memberFromIdentity(p)];
  for (let i = 0; i < 300; i++) {
    const s = Uint8Array.from({ length: 32 }, (_, j) => (j === 0 ? i >> 8 : j === 1 ? i & 0xff : 7));
    members.push(memberFromIdentity(identityFromSeed(s)));
  }
  const make = (relay: string) => signRoster({ network: net.id, version: 3, issuedAt: 1790000000000, relay, networkKey: b64u(net.ed25519.pub), primary: p.id, members }, net);
  const base = rosterSize(make(''));
  assert.ok(base < MAX_ROSTER_BYTES);
  const exact = make('x'.repeat(MAX_ROSTER_BYTES - base));
  assert.equal(rosterSize(exact), MAX_ROSTER_BYTES);
  assert.equal(rosterProblem(exact), null);
  // signRoster refuses to produce one over; a hand-signed one is invalid on arrival.
  assert.throws(() => make('x'.repeat(MAX_ROSTER_BYTES - base + 1)), /over the 65000-byte limit/);
  const { signature: _s, ...unsigned } = exact;
  const over = { ...unsigned, relay: exact.relay + 'x' };
  const signed: Roster = { ...over, signature: b64u(net.sign(rosterSigningBytes(over))) };
  assert.equal(rosterSize(signed), MAX_ROSTER_BYTES + 1);
  assert.match(rosterProblem(signed)!, /over the 65000-byte limit/);
  assert.match(acceptanceProblem(signed, signed.networkKey, 1)!, /over the 65000-byte limit/);
  // Multi-byte characters count as bytes, not characters.
  const chars = MAX_ROSTER_BYTES - base;
  assert.throws(() => make('\u00e9'.repeat(Math.ceil(chars / 2) + 1)), /over the 65000-byte limit/);
  assert.equal(rosterSize(make('\u00e9'.repeat(Math.floor(chars / 2)))) <= MAX_ROSTER_BYTES, true);
});
