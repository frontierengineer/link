// Pairing and registration through the real relay: codes and links, SPAKE2, the roster
// push, the effective-roster rule, and the pairing channel's end in every way it can end.

import { before, test } from 'node:test';
import assert from 'node:assert/strict';
import { createIdentity, Member, pair, type Primary } from '@frontierengineer/link-client';
import { relayBinary, startRelay } from './support/relay.js';
import { bytesOf, FAST, inbox, raw, sleep, startNet, textOf, until, type Raw } from './support/net.js';

before(() => {
  relayBinary();
});

test('a primary pairs alice and bob; the roster reaches everyone; sessions run every way', async () => {
  const net = await startNet();
  try {
    const { primary } = net;
    const paired: { node: string; codeId: string }[] = [];
    primary.on('paired', (p) => paired.push({ node: p.member.id, codeId: p.codeId }));
    const alice = await net.add();
    assert.equal(alice.roster.version, 2);
    assert.equal(alice.state, 'connected');

    // The second node pairs from the code's parts rather than the link.
    const bobId = createIdentity();
    const code = primary.openPairingCode();
    assert.match(code.code, /^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);
    // As a person might type it: lower case, O for 0 and l for 1.
    const typed = code.code.toLowerCase().replace(/0/g, 'o').replace(/1/g, 'l');
    const { roster, pinnedNetworkKey } = await pair({
      link: { network: primary.network, code: typed, codeId: code.codeId, relay: net.relay.url },
      identity: bobId,
    });
    assert.equal(roster.version, 3);
    assert.equal(pinnedNetworkKey, primary.roster.networkKey);
    const bob = await Member.connect({ identity: bobId, roster, timing: FAST });
    net.members.push(bob);
    // The primary names the code that admitted each node: an application labels its members by code.
    assert.equal(paired.length, 2);
    assert.equal(paired[0]!.node, alice.id);
    assert.deepEqual(paired[1], { node: bob.id, codeId: code.codeId });

    // The primary pushed v3 to alice over their session.
    await until(() => alice.roster.version === 3, 'alice to receive v3');
    assert.ok(alice.roster.members.some((m) => m.id === bob.id));

    const wIn = inbox(alice);
    const sIn = inbox(bob);
    const pIn = inbox(primary);
    await alice.send(bob.id, bytesOf('alice to bob'));
    await bob.send(alice.id, bytesOf('bob to alice'));
    await primary.send(bob.id, bytesOf('primary to bob'));
    await bob.send(primary.id, bytesOf('bob to primary'));
    await alice.send(primary.id, bytesOf('alice to primary'));
    await primary.send(alice.id, bytesOf('primary to alice'));
    const s = await sIn.next(2);
    assert.deepEqual(s.map((m) => [m.from, textOf(m.bytes)]), [
      [alice.id, 'alice to bob'],
      [primary.id, 'primary to bob'],
    ]);
    const w = await wIn.next(2);
    assert.deepEqual(w.map((m) => [m.from, textOf(m.bytes)]), [
      [bob.id, 'bob to alice'],
      [primary.id, 'primary to alice'],
    ]);
    const p = await pIn.next(2);
    assert.deepEqual(p.map((m) => [m.from, textOf(m.bytes)]).sort(), [
      [bob.id, 'bob to primary'],
      [alice.id, 'alice to primary'],
    ].sort());
  } finally {
    await net.close();
  }
});

test('effective roster: a member offline during a pairing is brought up to date at registration', async () => {
  const net = await startNet();
  try {
    const alice = await net.add();
    const identity = alice.identity;
    const stale = alice.roster;
    alice.close();
    await sleep(100);
    const bob = await net.add();
    assert.equal(net.primary.roster.version, 3);

    // It presents v2; the relay holds v3 and returns it in `registered`.
    const back = new Member({ identity, roster: stale, timing: FAST });
    net.members.push(back);
    const seen: { version: number; state: string }[] = [];
    back.on('roster', (r) => seen.push({ version: r.version, state: back.state }));
    await back.waitConnected(10_000);
    assert.equal(back.roster.version, 3);
    // Applied before anything is sent under it: the roster event comes before `connected`.
    assert.deepEqual(seen, [{ version: 3, state: 'connecting' }]);

    const sIn = inbox(bob);
    await back.send(bob.id, bytesOf('caught up'));
    assert.equal(textOf((await sIn.next())[0]!.bytes), 'caught up');
  } finally {
    await net.close();
  }
});

test('a member revoked while offline is closed 4008 at registration and stays revoked', async () => {
  const net = await startNet();
  try {
    const alice = await net.add();
    const identity = alice.identity;
    const stale = alice.roster;
    alice.close();
    await sleep(100);
    net.primary.revoke(identity.id);
    const back = new Member({ identity, roster: stale, timing: FAST });
    net.members.push(back);
    const codes: number[] = [];
    back.on('disconnect', (d) => codes.push(d.code));
    await assert.rejects(back.waitConnected(10_000), { code: 'revoked' });
    assert.deepEqual(codes, [4008]);
    await sleep(300);
    assert.deepEqual(codes, [4008], 'no reconnect after 4008');
    assert.equal(back.state, 'revoked');
  } finally {
    await net.close();
  }
});

test('wrong codes burn after five; a used code admits one node; an absent primary is unreachable', async () => {
  const net = await startNet();
  try {
    const { primary } = net;
    const failures: string[] = [];
    primary.on('pairingFailed', (f) => failures.push(f.reason));
    const code = primary.openPairingCode();
    const wrong = { network: primary.network, code: code.code === 'AAAA-AAAA' ? 'BBBB-BBBB' : 'AAAA-AAAA', codeId: code.codeId, relay: net.relay.url };
    for (let i = 0; i < 5; i++) await assert.rejects(pair({ link: wrong, identity: createIdentity() }), { code: 'pairing' });
    assert.deepEqual(failures, Array(5).fill('wrong code'));
    await assert.rejects(pair({ link: code.link, identity: createIdentity() }), { code: 'pairing' });

    const once = primary.openPairingCode();
    assert.equal((await pair({ link: once.link, identity: createIdentity() })).roster.version, 2);
    await assert.rejects(pair({ link: once.link, identity: createIdentity() }), { code: 'pairing' });

    const later = primary.openPairingCode();
    primary.close();
    await sleep(100);
    await assert.rejects(pair({ link: later.link, identity: createIdentity() }), { code: 'unreachable' });
  } finally {
    await net.close();
  }
});

/** The generator of P-256, uncompressed: a valid point, so the primary answers it with P2. */
const P256_G = Uint8Array.from(
  Buffer.from(
    '046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
    'hex',
  ),
);

/** A newcomer that sends a well-formed P1, receives P2, and then goes quiet. */
async function stalledNewcomer(url: string, network: string, codeId: string): Promise<Raw> {
  const r = raw(url);
  assert.equal((await r.json()).type, 'hello');
  r.ws.send(JSON.stringify({ type: 'pair', network, code: codeId }));
  const pairing = await r.json();
  assert.equal(pairing.type, 'pairing');
  const channel = Buffer.from(pairing.channel as string, 'base64url');
  r.ws.send(Buffer.concat([Buffer.from([1, 6]), channel, P256_G]));
  const p2 = await r.next();
  assert.ok(p2 instanceof Uint8Array && p2.length === 18 + 65 && p2[1] === 6, 'P2 arrives');
  return r;
}

async function lastSlotHeld(primary: Primary, url: string) {
  const code = primary.openPairingCode();
  const wrong = { network: primary.network, code: code.code === 'AAAA-AAAA' ? 'BBBB-BBBB' : 'AAAA-AAAA', codeId: code.codeId, relay: url };
  for (let i = 0; i < 4; i++) await assert.rejects(pair({ link: wrong, identity: createIdentity() }), { code: 'pairing' });
  const stalled = await stalledNewcomer(url, primary.network, code.codeId);
  const reasons: string[] = [];
  primary.on('pairingFailed', (f) => reasons.push(f.reason));
  // The fifth slot is in flight: the right code is turned away for now.
  await assert.rejects(pair({ link: code.link, identity: createIdentity() }), { code: 'pairing' });
  assert.deepEqual(reasons, ['no attempts left']);
  return { code, stalled, reasons };
}

test('pairEnd: a newcomer that drops mid-pairing refunds its slot at the primary', async () => {
  const net = await startNet();
  try {
    const { code, stalled, reasons } = await lastSlotHeld(net.primary, net.relay.url);
    stalled.ws.close();
    await until(() => reasons.length === 2, 'the relay to tell the primary');
    assert.equal(reasons[1], 'the newcomer left');
    const ok = await pair({ link: code.link, identity: createIdentity() });
    assert.equal(ok.roster.version, 2);
  } finally {
    await net.close();
  }
});

test('pairEnd: the relay ends a channel after its timeout, tells both sides, and the slot is refunded', async () => {
  const net = await startNet({ env: { LINK_PAIR_TIMEOUT: '1s' } });
  try {
    const { code, stalled, reasons } = await lastSlotHeld(net.primary, net.relay.url);
    const end = await stalled.json(5000);
    assert.equal(end.type, 'pairEnd');
    assert.equal(await stalled.closed, 1000);
    await until(() => reasons.length === 2, 'the primary to hear pairEnd');
    assert.equal(reasons[1], 'the newcomer left');
    assert.equal((await pair({ link: code.link, identity: createIdentity() })).roster.version, 2);
  } finally {
    await net.close();
  }
});

test('a node that sends neither register nor pair in time is closed 4000', async () => {
  const relay = await startRelay({ LINK_HELLO_TIMEOUT: '300ms' });
  try {
    const r = raw(relay.url);
    assert.equal((await r.json()).type, 'hello');
    const started = Date.now();
    assert.equal(await r.closed, 4000);
    assert.ok(Date.now() - started >= 250);
  } finally {
    assert.equal(await relay.stop(), 0);
  }
});
