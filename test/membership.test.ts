// Membership through the real relay: revocation, resignation, refusal by a member whose
// roster does not list the sender, the relay forgetting an idle network, and usage.

import { before, test } from 'node:test';
import assert from 'node:assert/strict';
import { Member, Primary } from '@frontierengineer/link-client';
import { relayBinary } from './support/relay.js';
import { bytesOf, FAST, inbox, sessionsOf, sleep, startNet, textOf, until } from './support/net.js';

before(() => {
  relayBinary();
});

test('revocation: the relay closes the member 4008, it is revoked for good, the others drop it', async () => {
  const net = await startNet();
  try {
    const alice = await net.add();
    const bob = await net.add();
    const wIn = inbox(alice);
    await bob.send(alice.id, bytesOf('before'));
    await wIn.next();
    await alice.send(bob.id, bytesOf('a session both ways'));
    const codes: number[] = [];
    const states: string[] = [];
    bob.on('disconnect', (d) => codes.push(d.code));
    bob.on('state', (s) => states.push(s));

    const r = net.primary.revoke(bob.id);
    assert.equal(r.version, 4);
    await until(() => bob.state === 'revoked', 'bob to be revoked');
    await until(() => alice.roster.version === 4, 'alice to receive v4');
    assert.deepEqual(codes, [4008]);
    assert.equal(sessionsOf(alice).sessionInfo(bob.id).length, 0, 'alice dropped its sessions');
    await assert.rejects(alice.send(bob.id, bytesOf('to the revoked')), { code: 'invalid' });
    await assert.rejects(bob.send(alice.id, bytesOf('from the revoked')), { code: 'revoked' });
    await assert.rejects(bob.waitConnected(), { code: 'revoked' });
    await sleep(400);
    assert.deepEqual(codes, [4008], 'no reconnect after 4008');
    assert.deepEqual(states, ['revoked']);

    // A new copy of the revoked identity, with its old roster, is turned away at registration.
    const again = new Member({ identity: bob.identity, roster: bob.roster, timing: FAST });
    net.members.push(again);
    await assert.rejects(again.waitConnected(10_000), { code: 'revoked' });
  } finally {
    await net.close();
  }
});

test('resign: the primary publishes a roster without the member, which the relay then closes', async () => {
  const net = await startNet();
  try {
    const alice = await net.add();
    const bob = await net.add();
    const codes: number[] = [];
    bob.on('disconnect', (d) => codes.push(d.code));
    await bob.resign();
    assert.equal(bob.state, 'revoked');
    assert.deepEqual(codes, [4008]);
    assert.equal(net.primary.roster.version, 4);
    assert.ok(!net.primary.roster.members.some((m) => m.id === bob.id));
    await until(() => alice.roster.version === 4, 'alice to receive v4');
    await assert.rejects(alice.send(bob.id, bytesOf('x')), { code: 'invalid' });
  } finally {
    await net.close();
  }
});

/** Closes everything and waits until the relay has forgotten the network (LINK_NETWORK_TTL). */
async function allOffline(...ms: Member[]): Promise<void> {
  for (const m of ms) m.close();
  await sleep(1500);
}

test('refused: a member whose roster lacks the sender refuses it, then catches up from the primary', async () => {
  // The relay forgets an idle network; the first member back presents an old roster and
  // the relay knows no better. A newer roster from the next member replaces it at the
  // relay, but nobody pushes it to the first: only the member itself can catch up.
  const net = await startNet({ env: { LINK_NETWORK_TTL: '500ms' } });
  try {
    const { primary } = net;
    const alice = await net.add();
    const wIdentity = alice.identity;
    const wRoster = alice.roster; // v2
    alice.close();
    await sleep(100);
    const bob = await net.add(); // v3, which alice never saw
    const sIdentity = bob.identity;
    const sRoster = bob.roster;
    const pIdentity = primary.identity;
    const pRoster = primary.roster;
    await allOffline(bob, primary);

    const w = new Member({ identity: wIdentity, roster: wRoster, timing: FAST });
    net.members.push(w);
    await w.waitConnected();
    assert.equal(w.roster.version, 2, 'the relay had nothing newer');
    const s = new Member({ identity: sIdentity, roster: sRoster, timing: FAST });
    net.members.push(s);
    await s.waitConnected();
    assert.equal(w.state, 'connected', 'v3 still lists alice');

    const err = await s.send(w.id, bytesOf('do you know me?')).then(
      () => undefined,
      (e: unknown) => e as { code?: string; reason?: number },
    );
    assert.equal(err?.code, 'refused');
    assert.equal(err?.reason, 1);
    assert.equal(w.roster.version, 2, 'the primary is away, so alice cannot catch up yet');

    const p = await Primary.connect({ identity: pIdentity, roster: pRoster, networkSeed: net.networkSeed, timing: FAST });
    net.members.push(p);
    assert.equal(await w.syncRoster(), true);
    assert.equal(w.roster.version, 3);
    const wIn = inbox(w);
    await s.send(w.id, bytesOf('now you do'));
    assert.equal(textOf((await wIn.next())[0]!.bytes), 'now you do');
  } finally {
    await net.close();
  }
});

test('a revoked member that reaches a relay which forgot the network is closed 4008 once an up-to-date member registers', async () => {
  const net = await startNet({ env: { LINK_NETWORK_TTL: '500ms' } });
  try {
    const { primary } = net;
    const alice = await net.add();
    const bob = await net.add();
    const stale = bob.roster; // v3
    bob.close();
    await sleep(100);
    primary.revoke(bob.id); // v4, while bob is away
    const pIdentity = primary.identity;
    const pRoster = primary.roster;
    await allOffline(alice, primary);

    const back = new Member({ identity: bob.identity, roster: stale, timing: FAST });
    net.members.push(back);
    await back.waitConnected();
    const codes: number[] = [];
    back.on('disconnect', (d) => codes.push(d.code));
    // The primary presents v4, which replaces the relay's v3 and evicts bob.
    const p = await Primary.connect({ identity: pIdentity, roster: pRoster, networkSeed: net.networkSeed, timing: FAST });
    net.members.push(p);
    await until(() => back.state === 'revoked', 'bob to be closed');
    assert.deepEqual(codes, [4008]);
  } finally {
    await net.close();
  }
});

test('usage: the primary reads the network totals, and each member counts its own traffic', async () => {
  const net = await startNet();
  try {
    const alice = await net.add();
    const bob = await net.add();
    await net.pairOnly(); // on the roster, never connected
    const before = await net.primary.usage();
    const askedAt = Date.now();
    assert.equal(before.network.connections, 3);
    assert.deepEqual(before.network.limits, { rateBps: 0, quotaBytesHour: 0, trickleBps: 0 });
    assert.equal(before.network.quotaUsed, 0);
    assert.equal(before.network.slowed, false);
    // Totals only: the relay keeps no per-member figures.
    assert.deepEqual(Object.keys(before), ['network']);
    assert.deepEqual(Object.keys(before.network).sort(), ['bytesHour', 'connections', 'limits', 'quotaUsed', 'slowed']);

    alice.resetTraffic();
    bob.resetTraffic();
    const sIn = inbox(bob);
    const payload = new Uint8Array(300_000).fill(7);
    await alice.send(bob.id, payload);
    await sIn.next();
    // One ask per 10 s per network (section 4.3).
    await sleep(Math.max(0, askedAt + 10_100 - Date.now()));
    const after = await net.primary.usage();
    assert.ok(after.network.bytesHour - before.network.bytesHour >= payload.length);
    // What the relay no longer counts per member, the members count themselves.
    const sent = alice.traffic().peers[bob.id]!.sent;
    const got = bob.traffic().peers[alice.id]!.received;
    assert.equal(sent.messages, 1);
    assert.equal(sent.bytes, payload.length);
    assert.deepEqual(got.messages, 1);
    assert.equal(got.bytes, payload.length);
    assert.equal(got.frames, sent.frames);
    assert.equal(got.frameBytes, sent.frameBytes);
    assert.ok(sent.frameBytes > payload.length && sent.frameBytes < payload.length * 1.01, `${sent.frameBytes} frame bytes`);
  } finally {
    await net.close();
  }
});

test("quota: every member is told the network is slowed, the primary's usage says so, and the trickle rate slows traffic", async () => {
  const quota = 1_000_000;
  const trickle = 200_000;
  const net = await startNet({ env: { LINK_QUOTA_BYTES_HOUR: String(quota), LINK_TRICKLE_BPS: String(trickle) } });
  try {
    const alice = await net.add();
    const bob = await net.add();
    const pushed: string[] = [];
    (net.primary as unknown as { relay: { on(e: string, f: (m: { type: string }) => void): void } }).relay.on('control', (m) => {
      if (m.type !== 'usage' && m.type !== 'error') pushed.push(m.type);
    });
    const told: { rateBps: number; slowed: boolean }[] = [];
    for (const m of [net.primary, alice, bob]) {
      assert.deepEqual(m.shaping, { rateBps: 0, slowed: false });
      m.on('shaping', (sh) => told.push(sh));
    }
    const sIn = inbox(bob);
    await alice.send(bob.id, new Uint8Array(1_100_000));
    await sIn.next(1, 20_000);
    // The relay pushed the trickle to all three, once each, and nothing else.
    await until(() => told.length >= 3, 'all three to be told');
    assert.deepEqual(told, Array(3).fill({ rateBps: trickle, slowed: true }));
    for (const m of [net.primary, alice, bob]) assert.deepEqual(m.shaping, { rateBps: trickle, slowed: true });
    assert.deepEqual(pushed, ['shaping']);
    const u = await net.primary.usage();
    assert.equal(u.network.slowed, true);
    assert.ok(u.network.quotaUsed >= 1, `quotaUsed ${u.network.quotaUsed}`);
    assert.deepEqual(u.network.limits, { rateBps: 0, quotaBytesHour: quota, trickleBps: trickle });

    // At the trickle rate (its bucket starts with one second of tokens), 600 kB take over 1.5 s,
    // once the relay's grace of a second after the notice is over.
    await sleep(1000);
    const started = Date.now();
    await alice.send(bob.id, new Uint8Array(600_000));
    await sIn.next(1, 20_000);
    const took = Date.now() - started;
    assert.ok(took >= 1500, `600 kB at ${trickle} B/s arrived in ${took} ms`);
    assert.deepEqual(pushed, ['shaping'], 'the relay pushed nothing more: usage itself is never pushed');
  } finally {
    await net.close();
  }
});

test('a revocation spreads member to member: with the primary offline and the relay forgetful, the up-to-date peer hands it on', async () => {
  // The relay forgets a network 300 ms after its last member leaves.
  const net = await startNet({ env: { LINK_NETWORK_TTL: '300ms' } });
  try {
    const { identity: wId } = await net.pairOnly();
    const { identity: tId } = await net.pairOnly();
    const { identity: xId, roster: before } = await net.pairOnly();
    const start = (identity: typeof wId, roster: typeof before) => {
      const m = new Member({ identity, roster, timing: FAST });
      net.members.push(m);
      return m;
    };
    // The tablet stays offline while the primary revokes the phone (x).
    const w = start(wId, net.primary.roster);
    await w.waitConnected(10_000);
    const tRoster = net.primary.roster;
    net.primary.revoke(xId.id);
    const after = net.primary.roster.version;
    await until(() => w.roster.version === after, 'alice to learn the revocation');
    // Everyone goes; the relay forgets the network.
    w.close();
    net.primary.close();
    await sleep(800);
    // The tablet and the revoked phone come back first, both on the roster from before: a relay
    // that knows nothing newer lets them in, and they would talk.
    const t = start(tId, tRoster);
    const x = start(xId, before);
    await t.waitConnected(10_000);
    await x.waitConnected(10_000);
    const xIn = inbox(x);
    await t.send(x.id, bytesOf('before'));
    await xIn.next();
    // Alice comes back with the revocation. The primary is still offline: the tablet
    // learns it from alice alone, then refuses the phone by itself.
    const w2 = start(wId, w.roster);
    await w2.waitConnected(10_000);
    const wIn = inbox(w2);
    await t.send(w2.id, bytesOf('hello'));
    await wIn.next();
    await until(() => t.roster.version === after, 'the tablet to learn the revocation from its peer');
    await assert.rejects(t.send(x.id, bytesOf('after')), { code: 'invalid' });
  } finally {
    await net.close();
  }
});
