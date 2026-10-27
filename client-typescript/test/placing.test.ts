// A network made with no relay, and placed later (section 3.2): createNetwork's relay and
// members, isPlaced, placeNetwork, and a member of an unplaced network refused locally.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  acceptanceProblem,
  canonicalize,
  createIdentity,
  createNetwork,
  identityFromSeed,
  InvalidError,
  isPlaced,
  isRelayUrl,
  Member,
  memberFromIdentity,
  pair,
  placeNetwork,
  Primary,
  RosterFullError,
  rosterProblem,
  type Roster,
} from '../src/index.js';
import { b64u } from '../src/bytes.js';
import { networkKeyFromSeed } from '../src/identity.js';
import { rosterSigningBytes } from '../src/roster.js';
import { FAST, bytesOf, inbox, textOf } from './support/network.js';
import { TestRelay } from './support/relay.js';

const seed = (n: number) => new Uint8Array(32).fill(n);
const primary = identityFromSeed(seed(1));
const second = identityFromSeed(seed(2));
const third = identityFromSeed(seed(3));
const networkSeed = seed(0x80);
const RELAY = 'wss://eu.frontierengineer.link/v1';

const invalid = (what: RegExp) => (e: unknown) => {
  assert.ok(e instanceof InvalidError, String(e));
  assert.equal(e.code, 'invalid');
  assert.match(e.message, what);
  return true;
};

test('createNetwork: the relay defaults to none, and extra members are listed in version 1 beside the primary', () => {
  const { roster, networkSeed: s } = createNetwork({ identity: primary, networkSeed, now: 1790000000000, members: [memberFromIdentity(third), memberFromIdentity(second)] });
  assert.deepEqual(s, networkSeed);
  assert.equal(rosterProblem(roster), null);
  assert.equal(roster.relay, '');
  assert.equal(isPlaced(roster), false);
  assert.equal(roster.version, 1);
  assert.equal(roster.issuedAt, 1790000000000);
  assert.equal(roster.primary, primary.id);
  assert.deepEqual(
    roster.members.map((m) => m.id),
    [primary.id, second.id, third.id].sort(),
  );
  // Only the protocol's three fields of a given entry are listed.
  const labelled = { ...memberFromIdentity(second), kind: 'phone' };
  const r2 = createNetwork({ identity: primary, networkSeed, now: 5, members: [labelled] }).roster;
  assert.ok(!canonicalize(r2).includes('kind'));
  // Placed at creation, as before.
  const placed = createNetwork({ identity: primary, relay: RELAY, networkSeed }).roster;
  assert.equal(placed.relay, RELAY);
  assert.equal(isPlaced(placed), true);
  assert.equal(placed.members.length, 1);
});

test('createNetwork refuses a member listed twice, an entry that is not one, and a roster over 65000 bytes', () => {
  assert.throws(() => createNetwork({ identity: primary, members: [memberFromIdentity(primary)] }), invalid(/listed twice/));
  assert.throws(() => createNetwork({ identity: primary, members: [memberFromIdentity(second), memberFromIdentity(second)] }), invalid(/listed twice/));
  const forged = { ...memberFromIdentity(second), id: third.id };
  assert.throws(() => createNetwork({ identity: primary, members: [forged] }), invalid(/not derived/));
  const short = { ...memberFromIdentity(second), x25519: 'AAAA' };
  assert.throws(() => createNetwork({ identity: primary, members: [short] }), invalid(/x25519/));
  assert.throws(() => createNetwork({ identity: primary, now: -1 }), invalid(/now/));
  assert.throws(() => createNetwork({ identity: primary, networkSeed: new Uint8Array(31) }), invalid(/networkSeed/));
  const many = Array.from({ length: 500 }, () => memberFromIdentity(createIdentity()));
  assert.throws(() => createNetwork({ identity: primary, members: many }), RosterFullError);
});

test('placeNetwork: the next version, with the relay set and nothing else changed, signed by the network key', () => {
  const { roster } = createNetwork({ identity: primary, networkSeed, now: 1790000000000, members: [memberFromIdentity(second)] });
  const placed = placeNetwork({ roster, networkSeed, relay: RELAY, now: 1790000060000 });
  assert.equal(rosterProblem(placed), null);
  assert.equal(isPlaced(placed), true);
  assert.equal(placed.version, 2);
  assert.equal(placed.issuedAt, 1790000060000);
  assert.equal(placed.relay, RELAY);
  const { signature: _a, relay: _r, version: _v, issuedAt: _i, ...same } = placed;
  const { signature: _b, relay: _r0, version: _v0, issuedAt: _i0, ...before } = roster;
  assert.deepEqual(same, before);
  assert.equal(acceptanceProblem(placed, roster.networkKey, 1), null, 'a member holding version 1 accepts it');
  // issuedAt never goes back, as for any next roster.
  assert.equal(placeNetwork({ roster, networkSeed, relay: RELAY, now: 5 }).issuedAt, 1790000000000);
  // Deterministic: the same inputs sign the same roster.
  assert.equal(canonicalize(placeNetwork({ roster, networkSeed, relay: RELAY, now: 1790000060000 })), canonicalize(placed));
  // A field the protocol does not define is kept, as signed.
  const key = networkKeyFromSeed(networkSeed);
  const { signature: _s, ...rest } = roster;
  const extended = { ...rest, future: [1, 'x'] };
  const withField = { ...extended, signature: b64u(key.sign(rosterSigningBytes(extended as unknown as Roster))) } as unknown as Roster;
  assert.equal(rosterProblem(withField), null);
  const placedWithField = placeNetwork({ roster: withField, networkSeed, relay: RELAY, now: 1 }) as unknown as Record<string, unknown>;
  assert.deepEqual(placedWithField.future, [1, 'x']);
});

test('placeNetwork refuses a placed roster, a relay that is not a ws(s) URL, a seed of another network, an invalid roster', () => {
  const { roster } = createNetwork({ identity: primary, networkSeed });
  const placed = placeNetwork({ roster, networkSeed, relay: RELAY });
  assert.throws(() => placeNetwork({ roster: placed, networkSeed, relay: 'wss://elsewhere.example/v1' }), invalid(/placed already/));
  for (const relay of ['', 'https://eu.frontierengineer.link/v1', 'eu.frontierengineer.link/v1', 'wss://', 'wss:///v1', 'ws:/x', 'WSS://relay.example/v1', 'wss://a b/v1']) {
    assert.throws(() => placeNetwork({ roster, networkSeed, relay }), invalid(/ws:\/\/ or wss:\/\//), relay);
  }
  assert.throws(() => placeNetwork({ roster, networkSeed: seed(0x81), relay: RELAY }), invalid(/does not derive/));
  assert.throws(() => placeNetwork({ roster, networkSeed: new Uint8Array(16), relay: RELAY }), invalid(/32 bytes/));
  assert.throws(() => placeNetwork({ roster: { ...roster, version: 7 }, networkSeed, relay: RELAY }), invalid(/not valid/));
  assert.ok(isRelayUrl('ws://127.0.0.1:8080/v1'));
  assert.ok(isRelayUrl('wss://Relay.Example:8443/v1?x=1'));
  assert.ok(isRelayUrl('wss://relé.example/v1'));
  assert.ok(!isRelayUrl(undefined));
});

test('a member or primary of an unplaced network, with no relay URL of its own, is refused at once: no socket, no crash', async () => {
  const { roster } = createNetwork({ identity: primary, networkSeed, members: [memberFromIdentity(second)] });
  let crashed: unknown;
  const onUncaught = (e: unknown) => (crashed = e);
  process.on('uncaughtException', onUncaught);
  try {
    assert.throws(() => new Primary({ identity: primary, roster, networkSeed }), invalid(/no relay yet/));
    assert.throws(() => new Member({ identity: second, roster }), invalid(/no relay yet/));
    assert.throws(() => new Member({ identity: second, roster, relayUrl: '' }), invalid(/no relay yet/));
    await assert.rejects(Primary.connect({ identity: primary, roster, networkSeed }), invalid(/no relay yet/));
    await assert.rejects(Member.connect({ identity: second, roster }), invalid(/no relay yet/));
    // A relay URL that is not a URL is refused the same way, rather than thrown from a socket later.
    assert.throws(() => new Member({ identity: second, roster, relayUrl: 'not a url' }), invalid(/not a URL/));
    await new Promise((r) => setTimeout(r, 50));
  } finally {
    process.off('uncaughtException', onUncaught);
  }
  assert.equal(crashed, undefined);
});

test('an unplaced network, placed, registers and pairs; given a relay URL itself, its primary can connect before', async () => {
  const relay = await TestRelay.start();
  const nodes: Member[] = [];
  try {
    const listed = createIdentity();
    const created = createNetwork({ identity: primary, members: [memberFromIdentity(listed)] });
    // Started on the unplaced roster with a relay URL of its own, the primary dials that one,
    // and its pairing links name it.
    const early = await Primary.connect({ identity: primary, roster: created.roster, networkSeed: created.networkSeed, relayUrl: relay.url, timing: FAST });
    nodes.push(early);
    assert.ok(early.openPairingCode().link.includes(`&r=${encodeURIComponent(relay.url)}`));
    early.close();

    const placed = placeNetwork({ roster: created.roster, networkSeed: created.networkSeed, relay: relay.url });
    const p = await Primary.connect({ identity: primary, roster: placed, networkSeed: created.networkSeed, timing: FAST });
    nodes.push(p);
    assert.equal(p.roster.version, 2);
    // The member listed at creation joins with the placed roster, no pairing.
    const m = await Member.connect({ identity: listed, roster: placed, timing: FAST });
    nodes.push(m);
    const newcomer = createIdentity();
    const code = p.openPairingCode();
    assert.ok(code.link.includes(`&r=${encodeURIComponent(relay.url)}`));
    const paired = await pair({ link: code.link, identity: newcomer });
    assert.equal(paired.roster.version, 3);
    assert.equal(paired.roster.relay, relay.url);
    const n = await Member.connect({ identity: newcomer, roster: paired.roster, timing: FAST });
    nodes.push(n);
    const got = inbox(n);
    await m.send(newcomer.id, bytesOf('placed'));
    assert.equal(textOf((await got.next())[0]!.bytes), 'placed');
  } finally {
    for (const x of nodes) x.close();
    await relay.stop();
  }
});
