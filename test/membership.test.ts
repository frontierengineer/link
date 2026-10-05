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
    const worker = await net.add('worker');
    const surface = await net.add('surface');
    const wIn = inbox(worker);
    await surface.send(worker.id, bytesOf('before'));
    await wIn.next();
    await worker.send(surface.id, bytesOf('a session both ways'));
    const codes: number[] = [];
    const states: string[] = [];
    surface.on('disconnect', (d) => codes.push(d.code));
    surface.on('state', (s) => states.push(s));

    const r = net.primary.revoke(surface.id);
    assert.equal(r.version, 4);
    await until(() => surface.state === 'revoked', 'the surface to be revoked');
    await until(() => worker.roster.version === 4, 'the worker to receive v4');
    assert.deepEqual(codes, [4008]);
    assert.equal(sessionsOf(worker).sessionInfo(surface.id).length, 0, 'the worker dropped its sessions');
    await assert.rejects(worker.send(surface.id, bytesOf('to the revoked')), { code: 'invalid' });
    await assert.rejects(surface.send(worker.id, bytesOf('from the revoked')), { code: 'revoked' });
    await assert.rejects(surface.waitConnected(), { code: 'revoked' });
    await sleep(400);
    assert.deepEqual(codes, [4008], 'no reconnect after 4008');
    assert.deepEqual(states, ['revoked']);

    // A new copy of the revoked identity, with its old roster, is turned away at registration.
    const again = new Member({ identity: surface.identity, roster: surface.roster, timing: FAST });
    net.members.push(again);
    await assert.rejects(again.waitConnected(10_000), { code: 'revoked' });
  } finally {
    await net.close();
  }
});

test('resign: the primary publishes a roster without the member, which the relay then closes', async () => {
  const net = await startNet();
  try {
    const worker = await net.add('worker');
    const surface = await net.add('surface');
    const codes: number[] = [];
    surface.on('disconnect', (d) => codes.push(d.code));
    await surface.resign();
    assert.equal(surface.state, 'revoked');
    assert.deepEqual(codes, [4008]);
    assert.equal(net.primary.roster.version, 4);
    assert.ok(!net.primary.roster.members.some((m) => m.id === surface.id));
    await until(() => worker.roster.version === 4, 'the worker to receive v4');
    await assert.rejects(worker.send(surface.id, bytesOf('x')), { code: 'invalid' });
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
    const worker = await net.add('worker');
    const wIdentity = worker.identity;
    const wRoster = worker.roster; // v2
    worker.close();
    await sleep(100);
    const surface = await net.add('surface'); // v3, which the worker never saw
    const sIdentity = surface.identity;
    const sRoster = surface.roster;
    const pIdentity = primary.identity;
    const pRoster = primary.roster;
    await allOffline(surface, primary);

    const w = new Member({ identity: wIdentity, roster: wRoster, timing: FAST });
    net.members.push(w);
    await w.waitConnected();
    assert.equal(w.roster.version, 2, 'the relay had nothing newer');
    const s = new Member({ identity: sIdentity, roster: sRoster, timing: FAST });
    net.members.push(s);
    await s.waitConnected();
    assert.equal(w.state, 'connected', 'v3 still lists the worker');

    const err = await s.send(w.id, bytesOf('do you know me?')).then(
      () => undefined,
      (e: unknown) => e as { code?: string; reason?: number },
    );
    assert.equal(err?.code, 'refused');
    assert.equal(err?.reason, 1);
    assert.equal(w.roster.version, 2, 'the primary is away, so the worker cannot catch up yet');

    const p = await Primary.connect({ identity: pIdentity, roster: pRoster, timing: FAST });
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
    const worker = await net.add('worker');
    const surface = await net.add('surface');
    const stale = surface.roster; // v3
    surface.close();
    await sleep(100);
    primary.revoke(surface.id); // v4, while the surface is away
    const pIdentity = primary.identity;
    const pRoster = primary.roster;
    await allOffline(worker, primary);

    const back = new Member({ identity: surface.identity, roster: stale, timing: FAST });
    net.members.push(back);
    await back.waitConnected();
    const codes: number[] = [];
    back.on('disconnect', (d) => codes.push(d.code));
    // The primary presents v4, which replaces the relay's v3 and evicts the surface.
    const p = await Primary.connect({ identity: pIdentity, roster: pRoster, timing: FAST });
    net.members.push(p);
    await until(() => back.state === 'revoked', 'the surface to be closed');
    assert.deepEqual(codes, [4008]);
  } finally {
    await net.close();
  }
});

test('usage: the primary reads the network totals, and each member counts its own traffic', async () => {
  const net = await startNet();
  try {
    const worker = await net.add('worker');
    const surface = await net.add('surface');
    await net.pairOnly('mcp'); // on the roster, never connected
    const before = await net.primary.usage();
    assert.equal(before.network.connections, 3);
    assert.deepEqual(before.network.limits, { rateBps: 0, quotaBytesHour: 0, trickleBps: 0 });
    assert.equal(before.network.quotaUsed, 0);
    assert.equal(before.network.slowed, false);
    // Totals only: the relay keeps no per-member figures.
    assert.deepEqual(Object.keys(before), ['network']);
    assert.deepEqual(Object.keys(before.network).sort(), ['bytesHour', 'connections', 'limits', 'quotaUsed', 'slowed']);

    worker.resetTraffic();
    surface.resetTraffic();
    const sIn = inbox(surface);
    const payload = new Uint8Array(300_000).fill(7);
    await worker.send(surface.id, payload);
    await sIn.next();
    const after = await net.primary.usage();
    assert.ok(after.network.bytesHour - before.network.bytesHour >= payload.length);
    // What the relay no longer counts per member, the members count themselves.
    const sent = worker.traffic().peers[surface.id]!.sent;
    const got = surface.traffic().peers[worker.id]!.received;
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

test('quota: the primary asks and learns the network is slowed; the trickle rate slows traffic; nothing is pushed', async () => {
  const quota = 1_000_000;
  const trickle = 200_000;
  const net = await startNet({ env: { LINK_QUOTA_BYTES_HOUR: String(quota), LINK_TRICKLE_BPS: String(trickle) } });
  try {
    const worker = await net.add('worker');
    const surface = await net.add('surface');
    const pushed: string[] = [];
    (net.primary as unknown as { relay: { on(e: string, f: (m: { type: string }) => void): void } }).relay.on('control', (m) => {
      if (m.type !== 'usage' && m.type !== 'error') pushed.push(m.type);
    });
    const sIn = inbox(surface);
    await worker.send(surface.id, new Uint8Array(1_100_000));
    await sIn.next(1, 20_000);
    const u = await net.primary.usage();
    assert.equal(u.network.slowed, true);
    assert.ok(u.network.quotaUsed >= 1, `quotaUsed ${u.network.quotaUsed}`);
    assert.deepEqual(u.network.limits, { rateBps: 0, quotaBytesHour: quota, trickleBps: trickle });

    // At the trickle rate (its bucket starts with one second of tokens), 600 kB take over 1.5 s.
    const started = Date.now();
    await worker.send(surface.id, new Uint8Array(600_000));
    await sIn.next(1, 20_000);
    const took = Date.now() - started;
    assert.ok(took >= 1500, `600 kB at ${trickle} B/s arrived in ${took} ms`);
    assert.deepEqual(pushed, [], 'the relay pushed nothing to the primary');
  } finally {
    await net.close();
  }
});

test('a revocation spreads member to member: with the primary offline and the relay forgetful, the up-to-date peer hands it on', async () => {
  // The relay forgets a network 300 ms after its last member leaves.
  const net = await startNet({ env: { LINK_NETWORK_TTL: '300ms' } });
  try {
    const { identity: wId } = await net.pairOnly('worker');
    const { identity: tId } = await net.pairOnly('surface');
    const { identity: xId, roster: before } = await net.pairOnly('worker');
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
    await until(() => w.roster.version === after, 'the worker to learn the revocation');
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
    // The worker comes back with the revocation. The primary is still offline: the tablet
    // learns it from the worker alone, then refuses the phone by itself.
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
