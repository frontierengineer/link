// The relay's limits against the real client: shaping with LINK_RATE_BPS, liveness pings
// while a sender is held back, the 65000-byte roster limit, the 128 KiB control message
// limit, and the relay's answers to control messages a member may not send.

import { before, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createIdentity,
  MAX_ROSTER_BYTES,
  Member,
  memberFromIdentity,
  nodeIdFromEd25519,
  pair,
  Primary,
  rosterSize,
  signRoster,
  type Identity,
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
    const worker = await net.add('worker');
    const surface = await net.add('surface');
    const drops: number[] = [];
    for (const m of [net.primary, worker, surface]) m.on('disconnect', (d) => drops.push(d.code));
    const sIn = inbox(surface);
    const started = Date.now();
    await worker.send(surface.id, new Uint8Array(size).fill(1));
    const [got] = await sIn.next(1, 60_000);
    const took = Date.now() - started;
    assert.equal(got!.bytes.length, size);
    const usage = await net.primary.usage();
    return { took, drops: [...drops], usage };
  } finally {
    await net.close();
  }
}

test('shaping: LINK_RATE_BPS slows a transfer, and pings never drop the sender held back', async () => {
  const size = 2 * 1024 * 1024;
  const rate = 512 * 1024;
  const fast = await timedTransfer({}, size);
  // Pings every 200 ms; the sender is paused for seconds at a time and must be exempt.
  const shaped = await timedTransfer({ LINK_RATE_BPS: String(rate), LINK_PING_INTERVAL: '200ms' }, size);
  // The bucket holds one second of tokens, so 2 MiB at 512 KiB/s take at least 3 s.
  assert.ok(shaped.took >= 2700, `shaped transfer took ${shaped.took} ms`);
  assert.ok(shaped.took > fast.took * 2, `shaped ${shaped.took} ms against ${fast.took} ms unshaped`);
  assert.deepEqual(shaped.drops, [], 'no connection was dropped');
  assert.equal(shaped.usage.network.limits.rateBps, rate);
  assert.equal(shaped.usage.network.slowed, false, 'slowed means the trickle rate, not shaping');
});

test('liveness: members answer the relay\'s pings and stay connected', async () => {
  const net = await startNet({ env: { LINK_PING_INTERVAL: '100ms' } });
  try {
    const worker = await net.add('worker');
    const drops: number[] = [];
    for (const m of [net.primary, worker]) m.on('disconnect', (d) => drops.push(d.code));
    await new Promise((r) => setTimeout(r, 1500));
    assert.deepEqual(drops, []);
    const pIn = inbox(net.primary);
    await worker.send(net.primary.id, bytesOf('still here'));
    await pIn.next();
  } finally {
    await net.close();
  }
});

function fakeMember(): RosterMember {
  const pub = randomBytes(32);
  return { id: nodeIdFromEd25519(pub), ed25519: pub.toString('base64url'), x25519: randomBytes(32).toString('base64url'), kind: 'mcp' };
}

function rosterOf(primary: Identity, version: number, relay: string, members: RosterMember[]): Roster {
  const sorted = [...members].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return signRoster(
    { network: primary.id, version, issuedAt: Date.now(), relay, primary: { ed25519: Buffer.from(primary.ed25519.pub).toString('base64url') }, members: sorted },
    primary,
  );
}

test('a roster at the 65000-byte limit travels in register, in registered and in a session; no member fits beyond', async () => {
  const relay = await startRelay();
  const opened: Member[] = [];
  try {
    const p = createIdentity();
    const w = createIdentity();
    const base = [memberFromIdentity(p, 'primary'), memberFromIdentity(w, 'worker')];
    const small = rosterOf(p, 1, relay.url, base);
    // Every entry has the same length: fill v2 so that exactly one more member fits.
    const entry = JSON.stringify(fakeMember()).length + 1;
    const room = MAX_ROSTER_BYTES - rosterSize(rosterOf(p, 2, relay.url, base));
    const fakes = Array.from({ length: Math.floor(room / entry) - 1 }, fakeMember);
    const big = rosterOf(p, 2, relay.url, [...base, ...fakes]);
    assert.ok(MAX_ROSTER_BYTES - rosterSize(big) >= entry && MAX_ROSTER_BYTES - rosterSize(big) < 2 * entry);

    const primary = await Primary.connect({ identity: p, roster: big, timing: FAST });
    opened.push(primary);
    const worker = new Member({ identity: w, roster: small, timing: FAST });
    opened.push(worker);
    await worker.waitConnected(10_000);
    assert.equal(worker.roster.version, 2, 'the relay handed the big roster back in registered');
    const pIn = inbox(primary);
    await worker.send(p.id, bytesOf('under the big roster'));
    await pIn.next();

    // The last member that fits; v3 reaches the worker over their session, through the relay.
    const { roster: v3 } = await pair({ link: primary.openPairingCode('surface').link, identity: createIdentity() });
    assert.ok(rosterSize(v3) <= MAX_ROSTER_BYTES && rosterSize(v3) > MAX_ROSTER_BYTES - entry);
    await until(() => worker.roster.version === 3, 'the worker to receive v3 in a session');
    // Full: the primary refuses another, and nobody accepts a roster over the limit.
    assert.throws(() => primary.openPairingCode('mcp'), { code: 'roster-full' });
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
    const worker = await net.add('worker');
    const errors: { code: string; id?: string }[] = [];
    worker.on('relayError', (e) => errors.push(e));
    const send = (msg: Record<string, unknown>) =>
      (worker as unknown as { relay: { sendControl(m: Record<string, unknown>): boolean } }).relay.sendControl({ type: 'x', ...msg });
    assert.ok(send({ type: 'usage', id: 'u1' }));
    assert.ok(send({ type: 'roster', roster: net.primary.roster }));
    assert.ok(send({ type: 'nonsense', id: 'n1' }));
    await until(() => errors.length === 3, 'three answers');
    assert.deepEqual(
      errors.map((e) => [e.code, e.id]),
      [
        ['forbidden', 'u1'],
        ['forbidden', undefined],
        ['bad_request', 'n1'],
      ],
    );
    assert.equal(worker.state, 'connected');
    const pIn = inbox(net.primary);
    await worker.send(net.primary.id, bytesOf('still connected'));
    await pIn.next();
  } finally {
    await net.close();
  }
});
