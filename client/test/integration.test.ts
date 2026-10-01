// The client against the in-process test relay: real WebSockets, real
// pairing, real sessions.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createIdentity, Member, pair, type Roster } from '../src/index.js';
import { fromB64u } from '../src/bytes.js';
import { encodeFrame, FrameType } from '../src/frames.js';
import { NewcomerExchange } from '../src/pairing.js';
import { FAST, bytesOf, inbox, startNetwork, textOf, until } from './support/network.js';

test('primary, pairing a worker and a surface, sessions both ways', async () => {
  const net = await startNetwork();
  try {
    const { primary } = net;
    assert.equal(primary.state, 'connected');
    const worker = await net.add('worker');
    assert.equal(worker.roster.version, 2);
    const surface = await net.add('surface');
    assert.equal(surface.roster.version, 3);
    await until(() => worker.roster.version === 3, 'worker to receive roster v3');
    assert.equal(primary.roster.members.find((m) => m.id === surface.id)?.kind, 'surface');

    const wIn = inbox(worker);
    const sIn = inbox(surface);
    const pIn = inbox(primary);
    await worker.send(surface.id, bytesOf('hello surface'));
    const [m1] = await sIn.next();
    assert.equal(m1!.from, worker.id);
    assert.equal(textOf(m1!.bytes), 'hello surface');
    await surface.send(worker.id, bytesOf('hello worker'));
    assert.equal(textOf((await wIn.next())[0]!.bytes), 'hello worker');
    await primary.send(worker.id, bytesOf('from primary'));
    assert.equal(textOf((await wIn.next())[0]!.bytes), 'from primary');
    await surface.send(primary.id, bytesOf('to primary'));
    assert.equal(textOf((await pIn.next())[0]!.bytes), 'to primary');
  } finally {
    await net.close();
  }
});

test('large messages fragment and reassemble, up to 64 MiB, with credit flow control', async () => {
  const net = await startNetwork({ member: { creditWindow: 256 * 1024 } });
  try {
    const worker = await net.add('worker');
    const surface = await net.add('surface');
    const sIn = inbox(surface);
    const big = new Uint8Array(5 * 1024 * 1024 + 3);
    for (let i = 0; i < big.length; i++) big[i] = (i * 31 + 7) & 0xff;
    await worker.send(surface.id, big);
    const [got] = await sIn.next(1, 20000);
    assert.equal(got!.bytes.length, big.length);
    assert.deepEqual(got!.bytes, big);
    // Every data frame stays under Noise's 65535-byte message limit.
    const frames = net.relay.frameLog.filter((f) => f.from === worker.id && f.type === 3);
    assert.ok(frames.length >= 80);
    assert.ok(frames.every((f) => f.size <= 18 + 4 + 65535));

    const max = new Uint8Array(64 * 1024 * 1024);
    max[max.length - 1] = 0xab;
    await surface.send(worker.id, new Uint8Array(0));
    const wIn = inbox(worker);
    await surface.send(worker.id, max);
    const [whole] = await wIn.next(2, 120000).then((m) => m.slice(1));
    assert.equal(whole!.bytes.length, max.length);
    assert.equal(whole!.bytes[max.length - 1], 0xab);
    await assert.rejects(surface.send(worker.id, new Uint8Array(64 * 1024 * 1024 + 1)), { code: 'invalid' });
  } finally {
    await net.close();
  }
});

test('a sender waits for credit while the receiver does not consume', async () => {
  // Fragments of a message in progress are credited at once only while the
  // application has nothing waiting; complete messages are credited when taken.
  const window = 256 * 1024;
  const net = await startNetwork({ member: { creditWindow: window } });
  try {
    const worker = await net.add('worker');
    const surface = await net.add('surface');
    const reader = surface.messages;
    const msgs = [1, 2, 3].map((n) => new Uint8Array(200 * 1024).fill(n));
    await worker.send(surface.id, msgs[0]!);
    await worker.send(surface.id, msgs[1]!);
    let cDone = false;
    const cSent = worker.send(surface.id, msgs[2]!).then(() => (cDone = true));
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(cDone, false, 'the third message must wait for credit');
    assert.deepEqual((await reader.next()).value!.bytes, msgs[0]);
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(cDone, false, 'one message is still waiting to be read');
    assert.deepEqual((await reader.next()).value!.bytes, msgs[1]);
    await cSent;
    assert.deepEqual((await reader.next()).value!.bytes, msgs[2]);
  } finally {
    await net.close();
  }
});

test('rekey: the initiator starts a new session on a timer and messages keep flowing in order', async () => {
  const timing = { ...FAST, rekeyIntervalMs: 150, retireGraceMs: 100 };
  const net = await startNetwork({ member: { timing } });
  try {
    const worker = await net.add('worker');
    const surface = await net.add('surface');
    const sIn = inbox(surface);
    const sessions = (worker as unknown as { sessions: { sessionInfo(p: string): { localIndex: number; initiator: boolean; current: boolean }[] } }).sessions;
    await worker.send(surface.id, bytesOf('0'));
    const first = sessions.sessionInfo(surface.id).find((s) => s.current)!;
    assert.equal(first.initiator, true);
    for (let i = 1; i < 40; i++) {
      await worker.send(surface.id, bytesOf(String(i)));
      await new Promise((r) => setTimeout(r, 15));
    }
    const got = await sIn.next(40, 10000);
    assert.deepEqual(got.map((m) => textOf(m.bytes)), Array.from({ length: 40 }, (_, i) => String(i)));
    const now = sessions.sessionInfo(surface.id).find((s) => s.current)!;
    assert.notEqual(now.localIndex, first.localIndex, 'a rekey replaced the session');
    // Handshake-inits from the worker: the first plus at least two rekeys.
    const inits = net.relay.frameLog.filter((f) => f.from === worker.id && f.to === surface.id && f.type === 1);
    assert.ok(inits.length >= 3, `expected rekeys, saw ${inits.length} handshakes`);
    // The retired session is forgotten after its grace period.
    await until(() => sessions.sessionInfo(surface.id).length === 1, 'retired sessions to expire');
  } finally {
    await net.close();
  }
});

test('rekey after a message count, and both directions survive it', async () => {
  const timing = { ...FAST, rekeyMessages: 5 };
  const net = await startNetwork({ member: { timing } });
  try {
    const worker = await net.add('worker');
    const surface = await net.add('surface');
    const sIn = inbox(surface);
    const wIn = inbox(worker);
    for (let i = 0; i < 30; i++) {
      await worker.send(surface.id, bytesOf(`w${i}`));
      await surface.send(worker.id, bytesOf(`s${i}`));
      // Let frames cross the relay, as real traffic would.
      await new Promise((r) => setTimeout(r, 5));
    }
    assert.deepEqual((await sIn.next(30)).map((m) => textOf(m.bytes)), Array.from({ length: 30 }, (_, i) => `w${i}`));
    assert.deepEqual((await wIn.next(30)).map((m) => textOf(m.bytes)), Array.from({ length: 30 }, (_, i) => `s${i}`));
    const inits = net.relay.frameLog.filter((f) => f.from === worker.id && f.type === 1);
    assert.ok(inits.length >= 5, `expected several rekeys, saw ${inits.length}`);
  } finally {
    await net.close();
  }
});

test('revocation: the member is closed 4008 into a terminal state; the others drop it', async () => {
  const net = await startNetwork();
  try {
    const worker = await net.add('worker');
    const surface = await net.add('surface');
    const wIn = inbox(worker);
    await surface.send(worker.id, bytesOf('before'));
    await wIn.next();
    const states: string[] = [];
    surface.on('state', (s) => states.push(s));
    const r = net.primary.revoke(surface.id);
    assert.equal(r.version, 4);
    await until(() => surface.state === 'revoked', 'surface revoked');
    await until(() => worker.roster.version === 4, 'worker roster v4');
    assert.equal(net.relay.isConnected(net.primary.id, surface.id), false);
    await assert.rejects(surface.send(worker.id, bytesOf('after')), { code: 'revoked' });
    await assert.rejects(worker.send(surface.id, bytesOf('to revoked')), { code: 'invalid' });
    await assert.rejects(surface.waitConnected(), { code: 'revoked' });
    // Terminal: no reconnect attempts follow.
    const closes = net.relay.closes.length;
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(net.relay.closes.length, closes);
    assert.equal(surface.state, 'revoked');
    assert.deepEqual(states.slice(-1), ['revoked']);
  } finally {
    await net.close();
  }
});

test('a member refuses a node that is not on its roster', async () => {
  // The relay does not enforce the pushed roster here, so the revoked surface
  // stays connected and not yet aware of its removal.
  const net = await startNetwork({ relay: { enforceRoster: false } });
  try {
    const worker = await net.add('worker');
    const surface = await net.add('surface');
    net.primary.revoke(surface.id);
    await until(() => worker.roster.version === 4, 'worker roster v4');
    assert.equal(surface.state, 'connected');
    const err = await surface.send(worker.id, bytesOf('let me in')).then(
      () => undefined,
      (e: unknown) => e,
    );
    assert.equal((err as { code?: string }).code, 'refused');
    assert.equal((err as { reason?: number }).reason, 1);
    assert.ok(net.relay.frameLog.some((f) => f.from === worker.id && f.to === surface.id && f.type === 5));
  } finally {
    await net.close();
  }
});

test('resign: the primary publishes a roster without the member, which ends revoked', async () => {
  const net = await startNetwork();
  try {
    const worker = await net.add('worker');
    const surface = await net.add('surface');
    await surface.resign();
    assert.equal(surface.state, 'revoked');
    await until(() => net.primary.roster.version === 4, 'primary roster v4');
    assert.equal(net.primary.roster.members.some((m) => m.id === surface.id), false);
    await until(() => worker.roster.version === 4, 'worker roster v4');
  } finally {
    await net.close();
  }
});

test('roster sync: a member that missed a push learns the roster from a handshake and roster-request', async () => {
  const net = await startNetwork();
  try {
    const worker = await net.add('worker');
    // Block the primary's frames to the worker: the push of v3 is lost.
    net.relay.filter = (f) => (f.from === net.primary.id && f.to === worker.id ? 'unreachable' : 'pass');
    const surface = await net.add('surface');
    await until(() => net.primary.roster.version === 3, 'primary v3');
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(worker.roster.version, 2, 'the push was blocked');
    net.relay.filter = undefined;
    // The worker refuses the unknown surface, but its handshake payload says
    // v3, so the worker asks the primary for the roster.
    await assert.rejects(surface.send(worker.id, bytesOf('hi')), { code: 'refused' });
    await until(() => worker.roster.version === 3, 'worker to sync to v3');
    const wIn = inbox(worker);
    await surface.send(worker.id, bytesOf('hi again'));
    assert.equal(textOf((await wIn.next())[0]!.bytes), 'hi again');

    // And explicitly: roster-request / roster.
    net.relay.filter = (f) => (f.from === net.primary.id && f.to === worker.id ? 'unreachable' : 'pass');
    net.primary.revoke(surface.id);
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(worker.roster.version, 3);
    net.relay.filter = undefined;
    assert.equal(await worker.syncRoster(), true);
    assert.equal(worker.roster.version, 4);
    assert.equal(await worker.syncRoster(), false);
  } finally {
    await net.close();
  }
});

test('a send to a peer that is not connected fails at once with Unreachable', async () => {
  const net = await startNetwork();
  try {
    const worker = await net.add('worker');
    const absent = createIdentity();
    const code = net.primary.openPairingCode('mcp');
    await pair({ link: code.link, identity: absent });
    await until(() => worker.roster.members.some((m) => m.id === absent.id), 'worker roster lists the mcp');
    const started = Date.now();
    await assert.rejects(worker.send(absent.id, bytesOf('x')), { code: 'unreachable' });
    assert.ok(Date.now() - started < 1000);
    await assert.rejects(worker.send(createIdentity().id, bytesOf('x')), { code: 'invalid' });
  } finally {
    await net.close();
  }
});

test('a peer that goes away mid-session: its sessions end and the next send fails Unreachable', async () => {
  const net = await startNetwork();
  try {
    const worker = await net.add('worker');
    const surface = await net.add('surface');
    const sIn = inbox(surface);
    await worker.send(surface.id, bytesOf('1'));
    await sIn.next();
    const sessions = (worker as unknown as { sessions: { sessionInfo(p: string): { localIndex: number; current: boolean }[] } }).sessions;
    // The relay now reports the surface absent.
    net.relay.filter = (f) => (f.to === surface.id ? 'unreachable' : 'pass');
    await worker.send(surface.id, bytesOf('in flight')); // already handed off; answered unreachable
    await until(() => sessions.sessionInfo(surface.id).length === 0, 'the session to end');
    await assert.rejects(worker.send(surface.id, bytesOf('x')), { code: 'unreachable' });
    net.relay.filter = undefined;
    await worker.send(surface.id, bytesOf('2'));
    assert.equal(textOf((await sIn.next())[0]!.bytes), '2');
  } finally {
    await net.close();
  }
});

test('a peer that lost its session state is re-keyed by the next frame it cannot place', async () => {
  const net = await startNetwork();
  try {
    const worker = await net.add('worker');
    const surface = await net.add('surface');
    const sIn = inbox(surface);
    await worker.send(surface.id, bytesOf('1'));
    await sIn.next();
    const sessions = (worker as unknown as { sessions: { sessionInfo(p: string): { localIndex: number; current: boolean }[] } }).sessions;
    const before = sessions.sessionInfo(surface.id).find((s) => s.current)!.localIndex;
    // The surface's connection drops; it forgets its sessions and reconnects.
    net.relay.dropNode(net.primary.id, surface.id);
    await until(() => surface.state === 'disconnected', 'surface disconnected');
    await until(() => surface.state === 'connected', 'surface reconnected');
    // A frame on the stale session is lost, and makes the surface open a new session.
    await worker.send(surface.id, bytesOf('lost'));
    await until(() => sessions.sessionInfo(surface.id).some((s) => s.current && s.localIndex !== before), 'a new session');
    await worker.send(surface.id, bytesOf('2'));
    const got = await sIn.next();
    assert.equal(textOf(got[0]!.bytes), '2');
    assert.ok(!sIn.messages.some((m) => textOf(m.bytes) === 'lost'));
  } finally {
    await net.close();
  }
});

test('reconnect with backoff after a drop; 4009 surfaces moved and re-resolves the relay', async () => {
  const net = await startNetwork();
  try {
    const lookups: string[] = [];
    const worker = await net.add('worker', {
      resolveRelay: async (network) => {
        lookups.push(network);
        return undefined;
      },
    });
    const states: string[] = [];
    worker.on('state', (s) => states.push(s));
    net.relay.dropNode(net.primary.id, worker.id);
    await until(() => states.includes('disconnected') && worker.state === 'connected', 'reconnect after drop');
    const moved: string[] = [];
    worker.on('moved', (m) => moved.push(m.network));
    net.relay.closeNode(net.primary.id, worker.id, 4009);
    await until(() => moved.length === 1 && worker.state === 'connected', 'reconnect after 4009');
    assert.deepEqual(moved, [net.primary.id]);
    assert.deepEqual(lookups, [net.primary.id]);
  } finally {
    await net.close();
  }
});

test('usage and usageAlert reach the primary', async () => {
  const net = await startNetwork();
  try {
    const worker = await net.add('worker');
    await worker.send(net.primary.id, bytesOf('some bytes'));
    const u = await net.primary.usage();
    assert.equal(u.network.connections, 2);
    const w = u.members.find((m) => m.id === worker.id)!;
    assert.equal(w.connected, true);
    assert.ok(w.bytesHour > 0);
    const alerts: { quotaUsed: number; slowed: boolean }[] = [];
    net.primary.on('usageAlert', (a) => alerts.push(a));
    net.relay.usageAlert(net.primary.id, 0.8, false);
    await until(() => alerts.length === 1, 'usageAlert');
    assert.deepEqual(alerts[0], { quotaUsed: 0.8, slowed: false });
  } finally {
    await net.close();
  }
});

test('pairing: wrong codes burn after five, expired and unknown codes fail, absent primary is unreachable', async () => {
  const net = await startNetwork();
  try {
    const code = net.primary.openPairingCode('worker');
    const link = new URL(code.link.replace('frontier://', 'http://'));
    const wrong = { network: net.primary.id, code: code.code === 'AAAA-AAAA' ? 'BBBB-BBBB' : 'AAAA-AAAA', codeId: code.codeId, relay: net.relay.url };
    assert.equal(link.searchParams.get('i'), code.codeId);
    for (let i = 0; i < 5; i++) {
      await assert.rejects(pair({ link: wrong, identity: createIdentity() }), { code: 'pairing' });
    }
    // Burned: even the right code fails now.
    await assert.rejects(pair({ link: code.link, identity: createIdentity() }), { code: 'pairing' });

    const short = net.primary.openPairingCode('surface', { lifetimeMs: 50 });
    await new Promise((r) => setTimeout(r, 80));
    await assert.rejects(pair({ link: short.link, identity: createIdentity() }), { code: 'pairing' });

    // A used code admits one node only.
    const once = net.primary.openPairingCode('surface');
    const first = await pair({ link: once.link, identity: createIdentity() });
    assert.equal(first.roster.version, 2);
    await assert.rejects(pair({ link: once.link, identity: createIdentity() }), { code: 'pairing' });

    const failed: string[] = [];
    net.primary.on('pairingFailed', (f) => failed.push(f.reason));
    const after = net.primary.openPairingCode('worker');
    net.primary.close();
    await until(() => !net.relay.isConnected(net.primary.id, net.primary.id), 'primary gone');
    await assert.rejects(pair({ link: after.link, identity: createIdentity() }), { code: 'unreachable' });
  } finally {
    await net.close();
  }
});

test('slots: a failed confirmation keeps its slot, an attempt in flight holds one, a dropped attempt refunds it', async () => {
  const net = await startNetwork();
  try {
    const code = net.primary.openPairingCode('worker');
    const wrong = { network: net.primary.id, code: code.code === 'AAAA-AAAA' ? 'BBBB-BBBB' : 'AAAA-AAAA', codeId: code.codeId, relay: net.relay.url };
    for (let i = 0; i < 4; i++) await assert.rejects(pair({ link: wrong, identity: createIdentity() }), { code: 'pairing' });
    // A fifth attempt reaches the primary (P1, P2) and then stalls: it holds the last slot.
    const stalled = await startStalledAttempt(net.relay.url, net.primary.id, code.codeId);
    const reasons: string[] = [];
    net.primary.on('pairingFailed', (f) => reasons.push(f.reason));
    await assert.rejects(pair({ link: code.link, identity: createIdentity() }), { code: 'pairing' });
    assert.deepEqual(reasons, ['no attempts left']);
    // The stalled newcomer drops: its slot is refunded and the right code works.
    stalled.close();
    await until(() => reasons.length === 2, 'the dropped attempt to end');
    assert.equal(reasons[1], 'the newcomer left');
    const ok = await pair({ link: code.link, identity: createIdentity() });
    assert.equal(ok.roster.version, 2);
  } finally {
    await net.close();
  }
});

/** A newcomer that sends a well-formed P1, waits for P2, and then goes quiet. */
async function startStalledAttempt(url: string, network: string, codeId: string): Promise<{ close(): void }> {
  const ws = new WebSocket(url);
  ws.binaryType = 'arraybuffer';
  const exchange = new NewcomerExchange('ZZZZZZZZ', fromB64u(codeId));
  await new Promise<void>((resolve, reject) => {
    ws.onmessage = (ev) => {
      if (typeof ev.data === 'string') {
        const msg = JSON.parse(ev.data) as { type: string; channel?: string };
        if (msg.type === 'hello') ws.send(JSON.stringify({ type: 'pair', network, code: codeId }));
        if (msg.type === 'pairing') ws.send(encodeFrame(FrameType.Pair, fromB64u(msg.channel!), exchange.p1()) as Uint8Array<ArrayBuffer>);
      } else {
        resolve(); // P2 arrived
      }
    };
    ws.onclose = () => reject(new Error('closed early'));
  });
  ws.onclose = null;
  return { close: () => ws.close() };
}

test('handshake timeout and idle expiry', async () => {
  const timing = { ...FAST, handshakeTimeoutMs: 200, idleMs: 200 };
  const net = await startNetwork({ member: { timing } });
  try {
    const worker = await net.add('worker');
    const surface = await net.add('surface');
    net.relay.filter = (f) => (f.type === 1 ? 'drop' : 'pass');
    const t0 = Date.now();
    await assert.rejects(worker.send(surface.id, bytesOf('x')), { code: 'timeout' });
    assert.ok(Date.now() - t0 >= 190);
    net.relay.filter = undefined;
    const sIn = inbox(surface);
    await worker.send(surface.id, bytesOf('y'));
    await sIn.next();
    const sessions = (worker as unknown as { sessions: { sessionInfo(p: string): unknown[] } }).sessions;
    assert.equal(sessions.sessionInfo(surface.id).length, 1);
    await until(() => sessions.sessionInfo(surface.id).length === 0, 'idle session to be forgotten', 2000);
  } finally {
    await net.close();
  }
});

test('a member connecting with a roster it is not on, or an invalid one, is refused locally', async () => {
  const net = await startNetwork();
  try {
    const stranger = createIdentity();
    assert.throws(() => new Member({ identity: stranger, roster: net.primary.roster }), { code: 'invalid' });
    const bad = { ...net.primary.roster, version: 99 } as Roster;
    assert.throws(() => new Member({ identity: net.primary.identity, roster: bad }), { code: 'invalid' });
  } finally {
    await net.close();
  }
});

test('a member offline while the roster changed is brought up to date at registration', async () => {
  const net = await startNetwork();
  try {
    const worker = await net.add('worker');
    const identity = worker.identity;
    const stale = worker.roster;
    worker.close();
    await until(() => !net.relay.isConnected(net.primary.id, identity.id), 'worker offline');
    const surface = await net.add('surface');
    assert.equal(net.primary.roster.version, 3);
    // It presents v2; the relay answers registered with v3, which the member accepts.
    const back = new Member({ identity, roster: stale, timing: FAST });
    const seen: number[] = [];
    back.on('roster', (r) => seen.push(r.version));
    await back.waitConnected();
    assert.equal(back.roster.version, 3);
    assert.deepEqual(seen, [3]);
    const sIn = inbox(surface);
    await back.send(surface.id, bytesOf('caught up'));
    assert.equal(textOf((await sIn.next())[0]!.bytes), 'caught up');
    back.close();
  } finally {
    await net.close();
  }
});

test('a member revoked while offline is closed 4008 at registration and stays revoked', async () => {
  const net = await startNetwork();
  try {
    const worker = await net.add('worker');
    const identity = worker.identity;
    const stale = worker.roster;
    worker.close();
    await until(() => !net.relay.isConnected(net.primary.id, identity.id), 'worker offline');
    net.primary.revoke(identity.id);
    const back = new Member({ identity, roster: stale, timing: FAST });
    await assert.rejects(back.waitConnected(), { code: 'revoked' });
    assert.equal(back.state, 'revoked');
    assert.equal(back.roster.version, 2);
    back.close();
  } finally {
    await net.close();
  }
});
