// The relay's limits against the real client: shaping with LINK_RATE_BPS, liveness pings
// while a sender is held back, the 65000-byte roster limit, the 128 KiB control message
// limit, and the relay's answers to control messages a member may not send.

import { before, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createIdentity,
  createNetworkSeed,
  MAX_ROSTER_BYTES,
  Member,
  memberFromIdentity,
  networkKeyFromSeed,
  nodeIdFromEd25519,
  pair,
  Primary,
  rosterSize,
  signRoster,
  type NetworkKey,
  type Roster,
  type RosterMember,
} from '@frontierengineer/link-client';
import { randomBytes } from 'node:crypto';
import { relayBinary, startRelay } from './support/relay.js';
import { bytesOf, FAST, inbox, raw, startNet, until } from './support/net.js';

before(() => {
  relayBinary();
});

async function timedTransfer(env: Record<string, string>, size: number) {
  const net = await startNet({ env });
  try {
    const alice = await net.add();
    const bob = await net.add();
    const drops: number[] = [];
    for (const m of [net.primary, alice, bob]) m.on('disconnect', (d) => drops.push(d.code));
    const sIn = inbox(bob);
    const started = Date.now();
    await alice.send(bob.id, new Uint8Array(size).fill(1));
    const [got] = await sIn.next(1, 60_000);
    const took = Date.now() - started;
    assert.equal(got!.bytes.length, size);
    const usage = await net.primary.usage();
    return { took, drops: [...drops], usage };
  } finally {
    await net.close();
  }
}

// The relay drops a connection that has not answered a ping by the next one, so the interval is
// the time a member has to answer. A second is enough on a loaded machine, where 100 ms is not
// (the relay's real interval is 30 s).
const PING = '1s';

test('shaping: LINK_RATE_BPS slows a transfer, and pings never drop the sender held back', async () => {
  const size = 2 * 1024 * 1024;
  const rate = 512 * 1024;
  // A ping every second; the sender is paused for seconds at a time and must be exempt.
  const shaped = await timedTransfer({ LINK_RATE_BPS: String(rate), LINK_PING_INTERVAL: PING }, size);
  // The bucket holds one second of tokens, so 2 MiB at 512 KiB/s take at least 3 s: a lower
  // bound from the rate alone, which no machine, however fast or loaded, can beat.
  assert.ok(shaped.took >= 2700, `shaped transfer took ${shaped.took} ms`);
  assert.deepEqual(shaped.drops, [], 'no connection was dropped');
  assert.equal(shaped.usage.network.limits.rateBps, rate);
  assert.equal(shaped.usage.network.slowed, false, 'slowed means the trickle rate, not shaping');
});

test('liveness: members answer the relay\'s pings and stay connected', async () => {
  const net = await startNet({ env: { LINK_PING_INTERVAL: PING } });
  try {
    const alice = await net.add();
    const drops: number[] = [];
    for (const m of [net.primary, alice]) m.on('disconnect', (d) => drops.push(d.code));
    // Three pings each, every one answered in time, or the relay would have dropped the member.
    await new Promise((r) => setTimeout(r, 3500));
    assert.deepEqual(drops, []);
    const pIn = inbox(net.primary);
    await alice.send(net.primary.id, bytesOf('still here'));
    await pIn.next();
  } finally {
    await net.close();
  }
});

function fakeMember(): RosterMember {
  const pub = randomBytes(32);
  return { id: nodeIdFromEd25519(pub), ed25519: pub.toString('base64url'), x25519: randomBytes(32).toString('base64url') };
}

function rosterOf(net: NetworkKey, version: number, relay: string, members: RosterMember[], primary = members[0]!.id): Roster {
  const sorted = [...members].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return signRoster(
    { network: net.id, version, issuedAt: Date.now(), relay, networkKey: Buffer.from(net.ed25519.pub).toString('base64url'), primary, members: sorted },
    net,
  );
}

test('a roster at the 65000-byte limit travels in register, in registered and in a session; no member fits beyond', async () => {
  const relay = await startRelay();
  const opened: Member[] = [];
  try {
    const p = createIdentity();
    const w = createIdentity();
    const networkSeed = createNetworkSeed();
    const net = networkKeyFromSeed(networkSeed);
    const base = [memberFromIdentity(p), memberFromIdentity(w)];
    const small = rosterOf(net, 1, relay.url, base);
    // Every entry has the same length: fill v2 so that exactly one more member fits.
    const entry = JSON.stringify(fakeMember()).length + 1;
    const room = MAX_ROSTER_BYTES - rosterSize(rosterOf(net, 2, relay.url, base));
    const fakes = Array.from({ length: Math.floor(room / entry) - 1 }, fakeMember);
    const big = rosterOf(net, 2, relay.url, [...base, ...fakes]);
    assert.ok(MAX_ROSTER_BYTES - rosterSize(big) >= entry && MAX_ROSTER_BYTES - rosterSize(big) < 2 * entry);

    const primary = await Primary.connect({ identity: p, roster: big, networkSeed, timing: FAST });
    opened.push(primary);
    const alice = new Member({ identity: w, roster: small, timing: FAST });
    opened.push(alice);
    await alice.waitConnected(10_000);
    assert.equal(alice.roster.version, 2, 'the relay handed the big roster back in registered');
    const pIn = inbox(primary);
    await alice.send(p.id, bytesOf('under the big roster'));
    await pIn.next();

    // The last member that fits; v3 reaches alice over their session, through the relay.
    const { roster: v3 } = await pair({ link: primary.openPairingCode().link, identity: createIdentity() });
    assert.ok(rosterSize(v3) <= MAX_ROSTER_BYTES && rosterSize(v3) > MAX_ROSTER_BYTES - entry);
    await until(() => alice.roster.version === 3, 'alice to receive v3 in a session');
    // Full: the primary refuses another, and nobody accepts a roster over the limit.
    assert.throws(() => primary.openPairingCode(), { code: 'roster-full' });
    const over = { ...v3, relay: v3.relay + 'x'.repeat(MAX_ROSTER_BYTES) };
    assert.throws(() => new Member({ identity: w, roster: over as Roster, timing: FAST }), { code: 'invalid' });
  } finally {
    for (const m of opened) m.close();
    assert.equal(await relay.stop(), 0);
  }
});

test('128 KiB control messages: exactly 131072 bytes are read, one byte more closes 4000', async () => {
  const relay = await startRelay();
  try {
    const network = createIdentity().id;
    const pad = (target: number) => {
      const head = { type: 'pair', network, code: randomBytes(8).toString('base64url'), pad: '' };
      const text = JSON.stringify(head);
      return JSON.stringify({ ...head, pad: 'x'.repeat(target - text.length) });
    };
    const exact = raw(relay.url);
    assert.equal((await exact.json()).type, 'hello');
    const ok = pad(131072);
    assert.equal(Buffer.byteLength(ok), 131072);
    exact.ws.send(ok);
    // Read and understood: there is no primary to pair with.
    assert.deepEqual(await exact.json(), { type: 'error', code: 'unreachable', message: "the network's primary is not connected" });
    assert.equal(await exact.closed, 1000);

    const over = raw(relay.url);
    assert.equal((await over.json()).type, 'hello');
    over.ws.send(pad(131073));
    assert.equal(await over.closed, 4000);
  } finally {
    assert.equal(await relay.stop(), 0);
  }
});

test('control messages a member may not send are answered, and the connection stays open', async () => {
  const net = await startNet();
  try {
    const alice = await net.add();
    const errors: { code: string; id?: string }[] = [];
    alice.on('relayError', (e) => errors.push(e));
    const send = (msg: Record<string, unknown>) =>
      (alice as unknown as { relay: { sendControl(m: Record<string, unknown>): boolean } }).relay.sendControl({ type: 'x', ...msg });
    assert.ok(send({ type: 'usage', id: 'u1' }));
    // Any member may push a roster (spec section 4.2): one the relay holds already is ignored.
    assert.ok(send({ type: 'roster', roster: net.primary.roster }));
    assert.ok(send({ type: 'nonsense', id: 'n1' }));
    await until(() => errors.length === 2, 'two answers');
    assert.deepEqual(
      errors.map((e) => [e.code, e.id]),
      [
        ['forbidden', 'u1'],
        ['bad_request', 'n1'],
      ],
    );
    assert.equal(alice.state, 'connected');
    const pIn = inbox(net.primary);
    await alice.send(net.primary.id, bytesOf('still connected'));
    await pIn.next();
  } finally {
    await net.close();
  }
});
