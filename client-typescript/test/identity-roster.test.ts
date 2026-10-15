// Keys and ids (section 2), rosters (section 3), registration and resignation
// signatures (sections 4.1, 7.3).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { b32, b64u, concat, fromB64u, fromHex, toHex, utf8, EMPTY } from '../src/bytes.js';
import { ed25519Verify, hkdf, sha256 } from '../src/crypto.js';
import { createIdentity, identityFromSeed, isNodeId, nodeIdFromBytes, nodeIdToBytes } from '../src/identity.js';
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
const worker = identityFromSeed(seed(2));
const surface = identityFromSeed(seed(3));

function sample(): Roster {
  return signRoster(
    {
      network: primary.id,
      version: 3,
      issuedAt: 1790000000000,
      relay: 'wss://eu.frontierengineer.link/v1',
      primary: { ed25519: b64u(primary.ed25519.pub) },
      members: [
        memberFromIdentity(surface, 'surface'),
        memberFromIdentity(primary, 'primary'),
        memberFromIdentity(worker, 'worker'),
      ],
    },
    primary,
  );
}

test('roster signing: label || JCS without signature, members sorted', () => {
  const r = sample();
  const ids = r.members.map((m) => m.id);
  assert.deepEqual(ids, [...ids].sort());
  const { signature, ...rest } = r;
  assert.deepEqual(rosterSigningBytes(r), concat(utf8('frontier-link/1/roster'), utf8(canonicalize(rest))));
  assert.ok(ed25519Verify(fromB64u(signature), rosterSigningBytes(r), primary.ed25519.pub));
  assert.equal(rosterProblem(r), null);
  const first = createNetwork({ identity: primary, relay: 'wss://r/v1', now: 5 });
  assert.equal(first.version, 1);
  assert.equal(first.members.length, 1);
  assert.equal(rosterProblem(first), null);
});

test('roster validation refuses each broken rule', () => {
  const mutate = (f: (r: Roster) => void, resign = true): Roster => {
    const r = JSON.parse(JSON.stringify(sample())) as Roster;
    f(r);
    if (!resign) return r;
    const { signature: _s, ...rest } = r;
    return { ...rest, signature: b64u(primary.sign(rosterSigningBytes(rest as Roster))) };
  };
  const cases: [string, Roster][] = [
    ['tampered body', mutate((r) => (r.version = 4), false)],
    ['bad signature', mutate((r) => (r.signature = b64u(new Uint8Array(64))), false)],
    ['network not derived', mutate((r) => (r.network = worker.id))],
    ['unsorted', mutate((r) => r.members.reverse())],
    ['duplicate', mutate((r) => r.members.push({ ...r.members[r.members.length - 1]! }))],
    ['id not derived', mutate((r) => (r.members.find((m) => m.kind === 'worker')!.ed25519 = b64u(surface.ed25519.pub)))],
    ['two primaries', mutate((r) => (r.members.find((m) => m.kind === 'worker')!.kind = 'primary'))],
    ['no primary', mutate((r) => (r.members = r.members.filter((m) => m.kind !== 'primary')))],
    ['bad kind', mutate((r) => ((r.members[0] as { kind: string }).kind = 'admin'))],
    ['version zero', mutate((r) => (r.version = 0))],
    ['fractional version', mutate((r) => (r.version = 1.5))],
    ['short key', mutate((r) => (r.members[0]!.x25519 = b64u(new Uint8Array(31))))],
  ];
  for (const [name, r] of cases) assert.notEqual(rosterProblem(r), null, name);
  // A different signer with a roster naming itself is valid, but not acceptable to a pinned member.
  const other = createNetwork({ identity: worker, relay: 'wss://r/v1' });
  assert.equal(rosterProblem(other), null);
  assert.match(acceptanceProblem(other, b64u(primary.ed25519.pub), 0)!, /different primary/);
});

test('roster acceptance needs a newer version from the pinned primary', () => {
  const r = sample();
  const pin = r.primary.ed25519;
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
  const r = signResignation(worker, primary.id, 1790000000000);
  assert.ok(verifyResignation(r, primary.id, worker.ed25519.pub));
  assert.ok(!verifyResignation(r, worker.id, worker.ed25519.pub));
  assert.ok(!verifyResignation({ ...r, ts: r.ts + 1 }, primary.id, worker.ed25519.pub));
  assert.ok(!verifyResignation(r, primary.id, surface.ed25519.pub));
});

test('a roster is valid up to 65000 bytes of JCS, signature included, and invalid one byte over', () => {
  const p = identityFromSeed(seed(9));
  const members: RosterMember[] = [memberFromIdentity(p, 'primary')];
  for (let i = 0; i < 300; i++) {
    const s = Uint8Array.from({ length: 32 }, (_, j) => (j === 0 ? i >> 8 : j === 1 ? i & 0xff : 7));
    members.push(memberFromIdentity(identityFromSeed(s), 'mcp'));
  }
  const make = (relay: string) => signRoster({ network: p.id, version: 3, issuedAt: 1790000000000, relay, primary: { ed25519: members[0]!.ed25519 }, members }, p);
  const base = rosterSize(make(''));
  assert.ok(base < MAX_ROSTER_BYTES);
  const exact = make('x'.repeat(MAX_ROSTER_BYTES - base));
  assert.equal(rosterSize(exact), MAX_ROSTER_BYTES);
  assert.equal(rosterProblem(exact), null);
  // signRoster refuses to produce one over; a hand-signed one is invalid on arrival.
  assert.throws(() => make('x'.repeat(MAX_ROSTER_BYTES - base + 1)), /over the 65000-byte limit/);
  const { signature: _s, ...unsigned } = exact;
  const over = { ...unsigned, relay: exact.relay + 'x' };
  const signed: Roster = { ...over, signature: b64u(p.sign(rosterSigningBytes(over))) };
  assert.equal(rosterSize(signed), MAX_ROSTER_BYTES + 1);
  assert.match(rosterProblem(signed)!, /over the 65000-byte limit/);
  assert.match(acceptanceProblem(signed, signed.primary.ed25519, 1)!, /over the 65000-byte limit/);
  // Multi-byte characters count as bytes, not characters.
  const chars = MAX_ROSTER_BYTES - base;
  assert.throws(() => make('\u00e9'.repeat(Math.ceil(chars / 2) + 1)), /over the 65000-byte limit/);
  assert.equal(rosterSize(make('\u00e9'.repeat(Math.floor(chars / 2)))) <= MAX_ROSTER_BYTES, true);
});
