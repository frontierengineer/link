// The client against the in-process test relay: real WebSockets, real
// pairing, real sessions.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canonicalize, createIdentity, createNetwork, createNetworkSeed, MAX_ROSTER_BYTES, Member, primaryOf, memberFromIdentity, networkKeyFromSeed, nodeIdFromEd25519, pair, Primary, RateLimitedError, RosterFullError, rosterSize, signRoster, type Roster } from '../src/index.js';
import { b64u, fromB64u, randomBytes } from '../src/bytes.js';
import { encodeFrame, FrameType } from '../src/frames.js';
import { NewcomerExchange } from '../src/pairing.js';
import { FAST, bytesOf, inbox, startNetwork, textOf, until } from './support/network.js';
import { TestRelay } from './support/relay.js';

test('primary, pairing alice and bob, sessions both ways', async () => {
  const net = await startNetwork();
  try {
    const { primary } = net;
    assert.equal(primary.state, 'connected');
    const alice = await net.add();
    assert.equal(alice.roster.version, 2);
    const bob = await net.add();
    assert.equal(bob.roster.version, 3);
    await until(() => alice.roster.version === 3, 'alice to receive roster v3');
    assert.ok(primary.roster.members.some((m) => m.id === bob.id));
    assert.equal(primary.roster.primary, primary.id);

    const wIn = inbox(alice);
    const sIn = inbox(bob);
    const pIn = inbox(primary);
    await alice.send(bob.id, bytesOf('hello bob'));
    const [m1] = await sIn.next();
    assert.equal(m1!.from, alice.id);
    assert.equal(textOf(m1!.bytes), 'hello bob');
    await bob.send(alice.id, bytesOf('hello alice'));
    assert.equal(textOf((await wIn.next())[0]!.bytes), 'hello alice');
    await primary.send(alice.id, bytesOf('from primary'));
    assert.equal(textOf((await wIn.next())[0]!.bytes), 'from primary');
    await bob.send(primary.id, bytesOf('to primary'));
    assert.equal(textOf((await pIn.next())[0]!.bytes), 'to primary');
  } finally {
    await net.close();
  }
});

test('large messages fragment and reassemble, up to 64 MiB, with credit flow control', async () => {
  const net = await startNetwork();
  try {
    const alice = await net.add();
    const bob = await net.add();
    const sIn = inbox(bob);
    const big = new Uint8Array(5 * 1024 * 1024 + 3);
    for (let i = 0; i < big.length; i++) big[i] = (i * 31 + 7) & 0xff;
    await alice.send(bob.id, big);
    const [got] = await sIn.next(1, 20000);
    assert.equal(got!.bytes.length, big.length);
    assert.deepEqual(got!.bytes, big);
    // Every data frame stays under Noise's 65535-byte message limit.
    const frames = net.relay.frameLog.filter((f) => f.from === alice.id && f.type === 3);
    assert.ok(frames.length >= 80);
    assert.ok(frames.every((f) => f.size <= 18 + 4 + 65535));

    const max = new Uint8Array(64 * 1024 * 1024);
    max[max.length - 1] = 0xab;
    await bob.send(alice.id, new Uint8Array(0));
    const wIn = inbox(alice);
    await bob.send(alice.id, max);
    const [whole] = await wIn.next(2, 120000).then((m) => m.slice(1));
    assert.equal(whole!.bytes.length, max.length);
    assert.equal(whole!.bytes[max.length - 1], 0xab);
    await assert.rejects(bob.send(alice.id, new Uint8Array(64 * 1024 * 1024 + 1)), { code: 'invalid' });
  } finally {
    await net.close();
  }
});

test('a sender waits for credit while the receiver does not consume', async () => {
  // Fragments of a message in progress are credited at once only while the
  // application has nothing waiting; complete messages are credited when taken.
  // Every session starts with 1 MiB of credit each way.
  const net = await startNetwork();
  try {
    const alice = await net.add();
    const bob = await net.add();
    const reader = bob.messages;
    const msgs = [1, 2, 3].map((n) => new Uint8Array(800 * 1024).fill(n));
    await alice.send(bob.id, msgs[0]!);
    await alice.send(bob.id, msgs[1]!);
    let cDone = false;
    const cSent = alice.send(bob.id, msgs[2]!).then(() => (cDone = true));
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
  const timing = { ...FAST, rekeyIntervalMs: 150, retireGraceMs: 300 };
  const net = await startNetwork({ member: { timing } });
  try {
    const alice = await net.add();
    const bob = await net.add();
    const sIn = inbox(bob);
    const sessions = (alice as unknown as { sessions: { sessionInfo(p: string): { localIndex: number; initiator: boolean; current: boolean }[] } }).sessions;
    await alice.send(bob.id, bytesOf('0'));
    const first = sessions.sessionInfo(bob.id).find((s) => s.current)!;
    assert.equal(first.initiator, true);
    for (let i = 1; i < 40; i++) {
      await alice.send(bob.id, bytesOf(String(i)));
      await new Promise((r) => setTimeout(r, 15));
    }
    const got = await sIn.next(40, 10000);
    assert.deepEqual(got.map((m) => textOf(m.bytes)), Array.from({ length: 40 }, (_, i) => String(i)));
    const now = sessions.sessionInfo(bob.id).find((s) => s.current)!;
    assert.notEqual(now.localIndex, first.localIndex, 'a rekey replaced the session');
    // Handshake-inits from alice: the first plus at least two rekeys.
    const inits = net.relay.frameLog.filter((f) => f.from === alice.id && f.to === bob.id && f.type === 1);
    assert.ok(inits.length >= 3, `expected rekeys, saw ${inits.length} handshakes`);
    // The retired session is forgotten after its grace period.
    await until(() => sessions.sessionInfo(bob.id).length === 1, 'retired sessions to expire');
  } finally {
    await net.close();
  }
});

test('rekey after a message count, and both directions survive it', async () => {
  const timing = { ...FAST, rekeyMessages: 5 };
  const net = await startNetwork({ member: { timing } });
  try {
    const alice = await net.add();
    const bob = await net.add();
    const sIn = inbox(bob);
    const wIn = inbox(alice);
    for (let i = 0; i < 30; i++) {
      await alice.send(bob.id, bytesOf(`w${i}`));
      await bob.send(alice.id, bytesOf(`s${i}`));
      // Let frames cross the relay, as real traffic would.
      await new Promise((r) => setTimeout(r, 5));
    }
    assert.deepEqual((await sIn.next(30)).map((m) => textOf(m.bytes)), Array.from({ length: 30 }, (_, i) => `w${i}`));
    assert.deepEqual((await wIn.next(30)).map((m) => textOf(m.bytes)), Array.from({ length: 30 }, (_, i) => `s${i}`));
    const inits = net.relay.frameLog.filter((f) => f.from === alice.id && f.type === 1);
    assert.ok(inits.length >= 5, `expected several rekeys, saw ${inits.length}`);
  } finally {
    await net.close();
  }
});

test('revocation: the member is closed 4008 into a terminal state; the others drop it', async () => {
  const net = await startNetwork();
  try {
    const alice = await net.add();
    const bob = await net.add();
    const wIn = inbox(alice);
    await bob.send(alice.id, bytesOf('before'));
    await wIn.next();
    const states: string[] = [];
    bob.on('state', (s) => states.push(s));
    const r = net.primary.revoke(bob.id);
    assert.equal(r.version, 4);
    await until(() => bob.state === 'revoked', 'bob revoked');
    await until(() => alice.roster.version === 4, 'alice roster v4');
    assert.equal(net.relay.isConnected(net.primary.network, bob.id), false);
    await assert.rejects(bob.send(alice.id, bytesOf('after')), { code: 'revoked' });
    await assert.rejects(alice.send(bob.id, bytesOf('to revoked')), { code: 'invalid' });
    await assert.rejects(bob.waitConnected(), { code: 'revoked' });
    // Terminal: no reconnect attempts follow.
    const closes = net.relay.closes.length;
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(net.relay.closes.length, closes);
    assert.equal(bob.state, 'revoked');
    assert.deepEqual(states.slice(-1), ['revoked']);
  } finally {
    await net.close();
  }
});

test('a member refuses a node that is not on its roster', async () => {
  // The relay does not enforce the pushed roster here, so the revoked bob
  // stays connected and not yet aware of its removal.
  const net = await startNetwork({ relay: { enforceRoster: false } });
  try {
    const alice = await net.add();
    const bob = await net.add();
    net.primary.revoke(bob.id);
    await until(() => alice.roster.version === 4, 'alice roster v4');
    assert.equal(bob.state, 'connected');
    const err = await bob.send(alice.id, bytesOf('let me in')).then(
      () => undefined,
      (e: unknown) => e,
    );
    assert.equal((err as { code?: string }).code, 'refused');
    assert.equal((err as { reason?: number }).reason, 1);
    assert.ok(net.relay.frameLog.some((f) => f.from === alice.id && f.to === bob.id && f.type === 5));
  } finally {
    await net.close();
  }
});

test('resign: the primary publishes a roster without the member, which ends revoked', async () => {
  const net = await startNetwork();
  try {
    const alice = await net.add();
    const bob = await net.add();
    await bob.resign();
    assert.equal(bob.state, 'revoked');
    await until(() => net.primary.roster.version === 4, 'primary roster v4');
    assert.equal(net.primary.roster.members.some((m) => m.id === bob.id), false);
    await until(() => alice.roster.version === 4, 'alice roster v4');
  } finally {
    await net.close();
  }
});

test('roster sync: a member that missed a push learns the roster from a handshake and roster-request', async () => {
  const net = await startNetwork();
  try {
    const alice = await net.add();
    // Block the primary's frames to alice: the push of v3 is lost.
    net.relay.filter = (f) => (f.from === net.primary.id && f.to === alice.id ? 'unreachable' : 'pass');
    const bob = await net.add();
    await until(() => net.primary.roster.version === 3, 'primary v3');
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(alice.roster.version, 2, 'the push was blocked');
    net.relay.filter = undefined;
    // Alice refuses the unknown bob, but its handshake payload says
    // v3, so alice asks the primary for the roster.
    await assert.rejects(bob.send(alice.id, bytesOf('hi')), { code: 'refused' });
    await until(() => alice.roster.version === 3, 'alice to sync to v3');
    const wIn = inbox(alice);
    await bob.send(alice.id, bytesOf('hi again'));
    assert.equal(textOf((await wIn.next())[0]!.bytes), 'hi again');

    // And explicitly: roster-request / roster.
    net.relay.filter = (f) => (f.from === net.primary.id && f.to === alice.id ? 'unreachable' : 'pass');
    net.primary.revoke(bob.id);
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(alice.roster.version, 3);
    net.relay.filter = undefined;
    assert.equal(await alice.syncRoster(), true);
    assert.equal(alice.roster.version, 4);
    assert.equal(await alice.syncRoster(), false);
  } finally {
    await net.close();
  }
});

test('a send to a peer that is not connected fails at once with Unreachable', async () => {
  const net = await startNetwork();
  try {
    const alice = await net.add();
    const absent = createIdentity();
    const code = net.primary.openPairingCode();
    await pair({ link: code.link, identity: absent });
    await until(() => alice.roster.members.some((m) => m.id === absent.id), 'alice roster lists carol');
    const started = Date.now();
    await assert.rejects(alice.send(absent.id, bytesOf('x')), { code: 'unreachable' });
    assert.ok(Date.now() - started < 1000);
    await assert.rejects(alice.send(createIdentity().id, bytesOf('x')), { code: 'invalid' });
  } finally {
    await net.close();
  }
});

test('a peer that goes away mid-session: its sessions end and the next send fails Unreachable', async () => {
  const net = await startNetwork();
  try {
    const alice = await net.add();
    const bob = await net.add();
    const sIn = inbox(bob);
    await alice.send(bob.id, bytesOf('1'));
    await sIn.next();
    const sessions = (alice as unknown as { sessions: { sessionInfo(p: string): { localIndex: number; current: boolean }[] } }).sessions;
    // The relay now reports bob absent.
    net.relay.filter = (f) => (f.to === bob.id ? 'unreachable' : 'pass');
    await alice.send(bob.id, bytesOf('in flight')); // already handed off; answered unreachable
    await until(() => sessions.sessionInfo(bob.id).length === 0, 'the session to end');
    await assert.rejects(alice.send(bob.id, bytesOf('x')), { code: 'unreachable' });
    net.relay.filter = undefined;
    await alice.send(bob.id, bytesOf('2'));
    assert.equal(textOf((await sIn.next())[0]!.bytes), '2');
  } finally {
    await net.close();
  }
});

test('a peer that lost its session state answers reset; the sender drops the session and handshakes again', async () => {
  const net = await startNetwork();
  try {
    const alice = await net.add();
    const bob = await net.add();
    const sIn = inbox(bob);
    await alice.send(bob.id, bytesOf('1'));
    await sIn.next();
    const sessions = (alice as unknown as { sessions: { sessionInfo(p: string): { localIndex: number; current: boolean }[] } }).sessions;
    const before = sessions.sessionInfo(bob.id)[0]!.localIndex;
    // Bob's connection drops; it forgets its sessions and reconnects.
    net.relay.dropNode(net.primary.network, bob.id);
    await until(() => bob.state === 'disconnected', 'bob disconnected');
    await until(() => bob.state === 'connected', 'bob reconnected');
    // A frame on the stale session is lost and answered with reset.
    await alice.send(bob.id, bytesOf('lost'));
    await until(() => net.relay.frameLog.some((f) => f.from === bob.id && f.to === alice.id && f.type === 7), 'a reset frame');
    await until(() => sessions.sessionInfo(bob.id).length === 0, 'alice to drop the session');
    await alice.send(bob.id, bytesOf('2'));
    assert.equal(textOf((await sIn.next())[0]!.bytes), '2');
    assert.notEqual(sessions.sessionInfo(bob.id)[0]!.localIndex, before);
    assert.ok(!sIn.messages.some((m) => textOf(m.bytes) === 'lost'));
  } finally {
    await net.close();
  }
});

test('a responder expires a session older than the rekey interval plus 30 s and answers reset', async () => {
  const net = await startNetwork();
  try {
    // The initiator would rekey only after an hour; the responder's lifetime is 100 + 50 ms.
    const alice = await net.add({ timing: { ...FAST, rekeyIntervalMs: 3_600_000 } });
    const bob = await net.add({ timing: { ...FAST, rekeyIntervalMs: 100, retireGraceMs: 50 } });
    const sIn = inbox(bob);
    await alice.send(bob.id, bytesOf('fresh'));
    await sIn.next();
    await new Promise((r) => setTimeout(r, 200));
    await alice.send(bob.id, bytesOf('expired'));
    await until(() => net.relay.frameLog.some((f) => f.from === bob.id && f.type === 7), 'a reset frame');
    await new Promise((r) => setTimeout(r, 50));
    await alice.send(bob.id, bytesOf('renewed'));
    assert.equal(textOf((await sIn.next())[0]!.bytes), 'renewed');
    const inits = net.relay.frameLog.filter((f) => f.from === alice.id && f.to === bob.id && f.type === 1);
    assert.equal(inits.length, 2);
  } finally {
    await net.close();
  }
});

test('extra credit: a larger creditWindow is granted on top of the initial 1 MiB', async () => {
  const net = await startNetwork();
  try {
    const alice = await net.add();
    const bob = await net.add({ creditWindow: 4 * 1024 * 1024 });
    const sIn = inbox(bob);
    await alice.send(bob.id, bytesOf('x'));
    await sIn.next();
    const sessions = (alice as unknown as { sessions: { sessionInfo(p: string): { sendCredit: number }[] } }).sessions;
    // 1 MiB initial + 3 MiB extra, less nothing outstanding (the 1 byte came back on consumption).
    await until(() => sessions.sessionInfo(bob.id)[0]!.sendCredit === 4 * 1024 * 1024, 'credit of 4 MiB');
    const wSessions = (bob as unknown as { sessions: { sessionInfo(p: string): { sendCredit: number }[] } }).sessions;
    assert.equal(wSessions.sessionInfo(alice.id)[0]!.sendCredit, 1024 * 1024);
    assert.throws(() => new Member({ identity: createIdentity(), roster: net.primary.roster, creditWindow: 1000 }), { code: 'invalid' });
  } finally {
    await net.close();
  }
});

test('4005: a second copy of an identity replaces the first, which stops for good', async () => {
  const net = await startNetwork();
  try {
    const alice = await net.add();
    const states: string[] = [];
    alice.on('state', (s) => states.push(s));
    const copy = await Member.connect({ identity: alice.identity, roster: alice.roster, timing: FAST });
    await until(() => alice.state === 'replaced', 'the first copy replaced');
    await assert.rejects(alice.send(net.primary.id, bytesOf('x')), { code: 'replaced' });
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(alice.state, 'replaced');
    assert.equal(copy.state, 'connected');
    assert.deepEqual(states, ['replaced']);
    copy.close();
  } finally {
    await net.close();
  }
});

test('reconnect with backoff after a drop; 4009 members moved and re-resolves the relay', async () => {
  const net = await startNetwork();
  try {
    const lookups: string[] = [];
    const alice = await net.add({
      resolveRelay: async (network) => {
        lookups.push(network);
        return undefined;
      },
    });
    const states: string[] = [];
    alice.on('state', (s) => states.push(s));
    net.relay.dropNode(net.primary.network, alice.id);
    await until(() => states.includes('disconnected') && alice.state === 'connected', 'reconnect after drop');
    const moved: string[] = [];
    alice.on('moved', (m) => moved.push(m.network));
    net.relay.closeNode(net.primary.network, alice.id, 4009);
    await until(() => moved.length === 1 && alice.state === 'connected', 'reconnect after 4009');
    assert.deepEqual(moved, [net.primary.network]);
    assert.deepEqual(lookups, [net.primary.network]);
  } finally {
    await net.close();
  }
});

test("shaping: a member holds the relay's last notice, raises an event on each change, and ignores malformed ones", async () => {
  const net = await startNetwork({ relay: { features: ['control', 'shaping'] } });
  try {
    const alice = await net.add();
    const seen: { rateBps: number; slowed: boolean }[] = [];
    alice.on('shaping', (s) => seen.push(s));
    assert.deepEqual(alice.shaping, { rateBps: 0, slowed: false }, 'unshaped before any notice');
    net.relay.shape(net.primary.network, { rateBps: 1_048_576, slowed: false });
    await until(() => seen.length === 1, 'the rate');
    net.relay.shape(net.primary.network, { rateBps: 16384, slowed: true });
    await until(() => seen.length === 2, 'the trickle');
    assert.deepEqual(alice.shaping, { rateBps: 16384, slowed: true });
    assert.deepEqual(net.primary.shaping, { rateBps: 16384, slowed: true });
    // The same again changes nothing; malformed notices are ignored.
    net.relay.shape(net.primary.network, { rateBps: 16384, slowed: true });
    net.relay.shape(net.primary.network, { rateBps: -1, slowed: false });
    net.relay.shape(net.primary.network, { rateBps: 1.5, slowed: false });
    net.relay.shape(net.primary.network, { rateBps: 5, slowed: 'no' });
    net.relay.shape(net.primary.network, { raw: '{"type":"shaping","rateBps":1e2,"slowed":false}' });
    net.relay.shape(net.primary.network, { rateBps: 0, slowed: false });
    await until(() => seen.length === 3, 'the lift');
    assert.deepEqual(seen, [
      { rateBps: 1_048_576, slowed: false },
      { rateBps: 16384, slowed: true },
      { rateBps: 0, slowed: false },
    ]);
    // Messages still flow, paced or not.
    net.relay.shape(net.primary.network, { rateBps: 1_000_000, slowed: false });
    const pIn = inbox(net.primary);
    await alice.send(net.primary.id, new Uint8Array(300_000));
    assert.equal((await pIn.next())[0]!.bytes.length, 300_000);
  } finally {
    await net.close();
  }
});

test('shaping: a relay without the feature leaves a member unshaped, whatever it held before', async () => {
  const net = await startNetwork({ relay: { features: ['control'] } });
  try {
    const alice = await net.add();
    net.relay.shape(net.primary.network, { rateBps: 16384, slowed: true });
    await until(() => alice.shaping.slowed, 'a notice from a relay that never says it sends them');
    net.relay.closeNode(net.primary.network, alice.id, 1001);
    await until(() => alice.state === 'connected' && !alice.shaping.slowed, 'unshaped at the next registration');
    assert.deepEqual(alice.shaping, { rateBps: 0, slowed: false });
  } finally {
    await net.close();
  }
});

test('usage: the primary asks, the relay answers network totals, and refuses asks over its budget', async () => {
  const net = await startNetwork();
  try {
    const alice = await net.add();
    await alice.send(net.primary.id, bytesOf('some bytes'));
    const u = await net.primary.usage();
    assert.equal(u.network.connections, 2);
    assert.ok(u.network.bytesHour > 0);
    assert.deepEqual(Object.keys(u), ['network']);
    // One per 10 s with no burst: a second ask at once is refused.
    await assert.rejects(net.primary.usage(), (e: unknown) => e instanceof RateLimitedError && e.code === 'rate-limited');
    // A member that is not the primary is forbidden.
    const errors: { code: string; id?: string }[] = [];
    alice.on('relayError', (e) => errors.push(e));
    assert.ok((alice as unknown as { relay: { sendControl(m: object): boolean } }).relay.sendControl({ type: 'usage', id: 'x' }));
    await until(() => errors.length === 1, 'the forbidden answer');
    assert.deepEqual(errors[0], { code: 'forbidden', id: 'x' });
  } finally {
    await net.close();
  }
});

test('pairing: wrong codes burn after five, expired and unknown codes fail, absent primary is unreachable', async () => {
  const net = await startNetwork();
  try {
    const code = net.primary.openPairingCode();
    const link = new URL(code.link.replace('frontier://', 'http://'));
    const wrong = { network: net.primary.network, code: code.code === 'AAAA-AAAA' ? 'BBBB-BBBB' : 'AAAA-AAAA', codeId: code.codeId, relay: net.relay.url };
    assert.equal(link.searchParams.get('i'), code.codeId);
    for (let i = 0; i < 5; i++) {
      await assert.rejects(pair({ link: wrong, identity: createIdentity() }), { code: 'pairing' });
    }
    // Burned: even the right code fails now.
    await assert.rejects(pair({ link: code.link, identity: createIdentity() }), { code: 'pairing' });

    const short = net.primary.openPairingCode({ lifetimeMs: 50 });
    await new Promise((r) => setTimeout(r, 80));
    await assert.rejects(pair({ link: short.link, identity: createIdentity() }), { code: 'pairing' });

    // A used code admits one node only.
    const once = net.primary.openPairingCode();
    const first = await pair({ link: once.link, identity: createIdentity() });
    assert.equal(first.roster.version, 2);
    await assert.rejects(pair({ link: once.link, identity: createIdentity() }), { code: 'pairing' });

    const failed: string[] = [];
    net.primary.on('pairingFailed', (f) => failed.push(f.reason));
    const after = net.primary.openPairingCode();
    net.primary.close();
    await until(() => !net.relay.isConnected(net.primary.network, net.primary.id), 'primary gone');
    await assert.rejects(pair({ link: after.link, identity: createIdentity() }), { code: 'unreachable' });
  } finally {
    await net.close();
  }
});

test('pairing: a chosen code pairs in any spelling, burns like any code, and must be a valid code', async () => {
  const net = await startNetwork();
  try {
    // "falcon42": O and L read as 0 and 1 on both sides, so the spoken word works as typed.
    const chosen = net.primary.openPairingCode({ code: 'falcon42' });
    assert.equal(chosen.code, 'FA1C-0N42');
    const target = { network: net.primary.network, codeId: chosen.codeId, relay: net.relay.url };
    const ok = await pair({ link: { ...target, code: 'FALCON-42' }, identity: createIdentity() });
    assert.equal(ok.roster.version, 2);

    const again = net.primary.openPairingCode({ code: 'falcon42' });
    const wrong = { network: net.primary.network, codeId: again.codeId, relay: net.relay.url, code: 'falcon43' };
    for (let i = 0; i < 5; i++) {
      await assert.rejects(pair({ link: wrong, identity: createIdentity() }), { code: 'pairing' });
    }
    await assert.rejects(pair({ link: again.link, identity: createIdentity() }), { code: 'pairing' });

    for (const bad of ['short', 'toolongcode', 'UUUUUUUU', '']) {
      assert.throws(() => net.primary.openPairingCode({ code: bad }), { code: 'invalid' });
    }
  } finally {
    await net.close();
  }
});

test('slots: a failed confirmation keeps its slot, an attempt in flight holds one, a dropped attempt refunds it', async () => {
  const net = await startNetwork();
  try {
    const code = net.primary.openPairingCode();
    const wrong = { network: net.primary.network, code: code.code === 'AAAA-AAAA' ? 'BBBB-BBBB' : 'AAAA-AAAA', codeId: code.codeId, relay: net.relay.url };
    for (let i = 0; i < 4; i++) await assert.rejects(pair({ link: wrong, identity: createIdentity() }), { code: 'pairing' });
    // A fifth attempt reaches the primary (P1, P2) and then stalls: it holds the last slot.
    const stalled = await startStalledAttempt(net.relay.url, net.primary.network, code.codeId);
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
    const alice = await net.add();
    const bob = await net.add();
    net.relay.filter = (f) => (f.type === 1 ? 'drop' : 'pass');
    const t0 = Date.now();
    await assert.rejects(alice.send(bob.id, bytesOf('x')), { code: 'timeout' });
    assert.ok(Date.now() - t0 >= 190);
    net.relay.filter = undefined;
    const sIn = inbox(bob);
    await alice.send(bob.id, bytesOf('y'));
    await sIn.next();
    const sessions = (alice as unknown as { sessions: { sessionInfo(p: string): unknown[] } }).sessions;
    assert.equal(sessions.sessionInfo(bob.id).length, 1);
    await until(() => sessions.sessionInfo(bob.id).length === 0, 'idle session to be forgotten', 2000);
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
    const alice = await net.add();
    const identity = alice.identity;
    const stale = alice.roster;
    alice.close();
    await until(() => !net.relay.isConnected(net.primary.network, identity.id), 'alice offline');
    const bob = await net.add();
    assert.equal(net.primary.roster.version, 3);
    // It presents v2; the relay answers registered with v3, which the member accepts.
    const back = new Member({ identity, roster: stale, timing: FAST });
    const seen: number[] = [];
    back.on('roster', (r) => seen.push(r.version));
    await back.waitConnected();
    assert.equal(back.roster.version, 3);
    assert.deepEqual(seen, [3]);
    const sIn = inbox(bob);
    await back.send(bob.id, bytesOf('caught up'));
    assert.equal(textOf((await sIn.next())[0]!.bytes), 'caught up');
    back.close();
  } finally {
    await net.close();
  }
});

test('a member revoked while offline is closed 4008 at registration and stays revoked', async () => {
  const net = await startNetwork();
  try {
    const alice = await net.add();
    const identity = alice.identity;
    const stale = alice.roster;
    alice.close();
    await until(() => !net.relay.isConnected(net.primary.network, identity.id), 'alice offline');
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

test('a responder keeps an expired session while a message is still crossing it, in either direction', async () => {
  // Found against the Go relay: a message still in flight when the responder's session
  // passed rekeyIntervalMs + retireGraceMs was answered with reset half-way and lost.
  // Section 7.2: keys are kept longer while a message is still crossing a session.
  const net = await startNetwork();
  try {
    let skew = 0;
    const alice = await net.add({ timing: { ...FAST, rekeyIntervalMs: 3_600_000 } });
    const bob = await net.add({
      timing: { ...FAST, rekeyIntervalMs: 1000, retireGraceMs: 500 },
      monotonicNow: () => performance.now() + skew,
    });
    const sessions = (m: Member) => (m as unknown as { sessions: { sessionInfo(p: string): { localIndex: number }[] } }).sessions;

    // Alice to bob: bob holds one message unread, so the second stalls on
    // credit half-way; bob's clock then passes the session's lifetime.
    const sReader = bob.messages;
    const first = new Uint8Array(700 * 1024).fill(1);
    const second = new Uint8Array(2 * 1024 * 1024).fill(2);
    await alice.send(bob.id, first);
    let done = false;
    const sent = alice.send(bob.id, second).then(() => (done = true));
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(done, false, 'the second message stalls on credit');
    const index = sessions(alice).sessionInfo(bob.id)[0]!.localIndex;
    skew = 10_000;
    assert.deepEqual((await sReader.next()).value!.bytes, first);
    await sent;
    assert.deepEqual((await sReader.next()).value!.bytes, second);
    assert.equal(sessions(alice).sessionInfo(bob.id)[0]!.localIndex, index, 'the same session carried it');

    // A responder sending: the credit that lets it finish arrives on its old session,
    // which it must not reset while its own message is still crossing.
    let backSkew = 0;
    const back = await net.add({
      timing: { ...FAST, rekeyIntervalMs: 1000, retireGraceMs: 500 },
      monotonicNow: () => performance.now() + backSkew,
    });
    const wReader = alice.messages;
    await alice.send(back.id, new Uint8Array(1)); // alice initiates; back is the responder
    await back.messages.next();
    await back.send(alice.id, first);
    let backDone = false;
    const backSent = back.send(alice.id, second).then(() => (backDone = true));
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(backDone, false, 'the reply stalls on credit');
    backSkew = 10_000;
    assert.deepEqual((await wReader.next()).value!.bytes, first);
    await backSent;
    assert.deepEqual((await wReader.next()).value!.bytes, second);
  } finally {
    await net.close();
  }
});

test('a roster near 65000 bytes travels in one session message; the primary refuses a member beyond it', async () => {
  // Section 3 (spec 71b8288): a roster's JCS encoding, signature included, is at most 65000
  // bytes, so it always fits one session message; a primary refuses to add a member beyond.
  const relay = await TestRelay.start();
  const id = createIdentity();
  const networkSeed = createNetworkSeed();
  const net = networkKeyFromSeed(networkSeed);
  const fake = () => {
    const pub = randomBytes(32);
    return { id: nodeIdFromEd25519(pub), ed25519: b64u(pub), x25519: b64u(randomBytes(32)) };
  };
  const sign = (members: ReturnType<typeof fake>[]) =>
    signRoster({ network: net.id, version: 1, issuedAt: Date.now(), relay: relay.url, networkKey: b64u(net.ed25519.pub), primary: id.id, members: [memberFromIdentity(id), ...members] }, net);
  // Every entry has the same length, so the room left is a whole number of entries.
  const entry = canonicalize(fake()).length + 1;
  const base = rosterSize(sign([fake()]));
  const fakes = Array.from({ length: Math.floor((MAX_ROSTER_BYTES - base) / entry) - 1 }, fake); // room for two more
  const roster = sign(fakes);
  const primary = await Primary.connect({ identity: id, roster, networkSeed, timing: FAST });
  const failures: string[] = [];
  primary.on('pairingFailed', (f) => failures.push(f.reason));
  const codes = { alice: primary.openPairingCode(), bob: primary.openPairingCode(), carol: primary.openPairingCode() };
  const joined: Member[] = [];
  try {
    const wId = createIdentity();
    const alice = await Member.connect({ identity: wId, roster: (await pair({ link: codes.alice.link, identity: wId })).roster, timing: FAST });
    joined.push(alice);
    const pIn = inbox(primary);
    await alice.send(primary.id, bytesOf('hello'));
    await pIn.next();

    // The last member that fits: v3 is just under the limit and reaches alice in a session.
    await pair({ link: codes.bob.link, identity: createIdentity() });
    assert.equal(primary.roster.version, 3);
    const size = rosterSize(primary.roster);
    assert.ok(size <= MAX_ROSTER_BYTES && size > MAX_ROSTER_BYTES - entry, `v3 is ${size} bytes`);
    await until(() => alice.roster.version === 3, 'alice to receive v3 in a session');
    const data = relay.frameLog.filter((f) => f.type === FrameType.Data || f.type === FrameType.Control);
    assert.ok(data.some((f) => f.type === FrameType.Control && f.size > 60_000), 'the roster went as control');
    assert.ok(data.every((f) => f.size <= 18 + 4 + 65535), 'no Noise message over 65535 bytes');

    // No room left: a new code is refused at once, and a code opened earlier fails at P5.
    assert.throws(() => primary.openPairingCode(), (e: unknown) => e instanceof RosterFullError && e.code === 'roster-full');
    await assert.rejects(pair({ link: codes.carol.link, identity: createIdentity() }), { code: 'pairing' });
    assert.equal(failures.length, 1);
    assert.match(failures[0]!, /over the 65000-byte limit/);
    assert.equal(primary.roster.version, 3);

    // A session message over one Noise message is refused before it is encrypted, so the
    // session stays usable.
    const sessions = (primary as unknown as { sessions: { sendControl(p: string, m: { type: 'roster'; json: string }): Promise<void> } }).sessions;
    await assert.rejects(sessions.sendControl(alice.id, { type: 'roster', json: 'x'.repeat(70_000) }), { code: 'invalid' });
    const wIn = inbox(alice);
    await primary.send(alice.id, bytesOf('still here'));
    assert.equal(textOf((await wIn.next())[0]!.bytes), 'still here');
  } finally {
    for (const m of joined) m.close();
    primary.close();
    await relay.stop();
  }
});

test('a responder that sends on an expired session lets a message still arriving on it finish', async () => {
  // Section 7.2 (spec 71b8288): expiry yields to a message in flight. The responder's own
  // send used to end the expired session at once, so the rest of a message still arriving
  // on it was answered with reset and lost.
  const net = await startNetwork();
  try {
    let skew = 0;
    const alice = await net.add({ timing: { ...FAST, rekeyIntervalMs: 3_600_000 } });
    const bob = await net.add({ timing: { ...FAST, rekeyIntervalMs: 1000, retireGraceMs: 500 }, monotonicNow: () => performance.now() + skew });
    const sReader = bob.messages;
    const wIn = inbox(alice);
    const first = new Uint8Array(700 * 1024).fill(1);
    const second = new Uint8Array(2 * 1024 * 1024).fill(2);
    await alice.send(bob.id, first);
    let done = false;
    const sent = alice.send(bob.id, second).then(() => (done = true));
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(done, false, 'the second message is part-way across, stalled on credit');
    skew = 10_000;
    await bob.send(alice.id, bytesOf('a reply on a new session'));
    assert.equal(textOf((await wIn.next())[0]!.bytes), 'a reply on a new session');
    assert.deepEqual((await sReader.next()).value!.bytes, first);
    await sent;
    assert.deepEqual((await sReader.next()).value!.bytes, second);
  } finally {
    await net.close();
  }
});

test('traffic: each member counts its own messages and frames per peer, matching what the relay saw', async () => {
  const net = await startNetwork();
  try {
    const alice = await net.add();
    const pIn = inbox(net.primary);
    alice.resetTraffic();
    net.primary.resetTraffic();
    const from = net.relay.frameLog.length;
    for (const n of [10, 2000, 70_000]) await alice.send(net.primary.id, new Uint8Array(n));
    await pIn.next(3);
    await until(() => net.relay.frameLog.slice(from).some((f) => f.from === net.primary.id && f.type === FrameType.Control), 'credit back');
    const w = alice.traffic();
    const p = net.primary.traffic();
    const toPrimary = net.relay.frameLog.slice(from).filter((f) => f.from === alice.id);
    const toAlice = net.relay.frameLog.slice(from).filter((f) => f.from === net.primary.id);
    assert.deepEqual(w.peers[net.primary.id]!.sent, {
      messages: 3,
      bytes: 72_010,
      frames: toPrimary.length,
      frameBytes: toPrimary.reduce((a, f) => a + f.size, 0),
    });
    assert.deepEqual(w.total.sent, w.peers[net.primary.id]!.sent);
    assert.deepEqual(p.peers[alice.id]!.received.messages, 3);
    assert.deepEqual(p.peers[alice.id]!.received.bytes, 72_010);
    assert.equal(p.peers[alice.id]!.received.frameBytes, toPrimary.reduce((a, f) => a + f.size, 0));
    assert.equal(w.peers[net.primary.id]!.received.frameBytes, toAlice.reduce((a, f) => a + f.size, 0));
    assert.equal(w.relay.sent, 0, 'reset after registering');
    await net.primary.usage();
    assert.ok(net.primary.traffic().relay.sent > 0 && net.primary.traffic().relay.received > 0);
  } finally {
    await net.close();
  }
});

test('control frames: 0x08 only to a relay that lists control; otherwise the same messages go as 0x03', async () => {
  for (const features of [['control'], [] as string[]]) {
    const net = await startNetwork({ relay: { features } });
    try {
      const alice = await net.add();
      const pIn = inbox(net.primary);
      for (let i = 0; i < 3; i++) await alice.send(net.primary.id, new Uint8Array(40_000));
      await pIn.next(3);
      // The primary returns credit, and pushes the roster, as session control.
      await until(() => net.relay.frameLog.some((f) => f.from === net.primary.id && f.to === alice.id && f.type !== FrameType.HandshakeResp), 'credit');
      const types = new Set(net.relay.frameLog.filter((f) => f.from === net.primary.id).map((f) => f.type));
      if (features.length) assert.ok(types.has(FrameType.Control), 'control used');
      else assert.ok(!types.has(FrameType.Control), 'never 0x08 without the feature');
      const wIn = inbox(alice);
      await net.primary.send(alice.id, bytesOf('both ways'));
      assert.equal(textOf((await wIn.next())[0]!.bytes), 'both ways');
    } finally {
      await net.close();
    }
  }
});

test('a node started with the network seed claims the primary; the former primary is demoted in place and stays connected', async () => {
  const net = await startNetwork();
  try {
    const alice = await net.add();
    const bob = await net.add();
    const former = net.primary;
    const formerStates: string[] = [];
    const formerCloses: number[] = [];
    former.on('state', (s) => formerStates.push(s));
    former.on('disconnect', (d) => formerCloses.push(d.code));
    // A pairing code open on the former primary, to see it closed by the demotion.
    const stale = former.openPairingCode();

    // The application gives alice the network seed and starts it with it.
    const identity = alice.identity;
    const roster = alice.roster;
    alice.close();
    const claimant = await Member.connect({ identity, roster, networkSeed: net.networkSeed, timing: FAST });
    net.members.push(claimant);
    assert.ok(claimant.isPrimary);
    const claimed = claimant.roster;
    assert.equal(claimed.version, roster.version + 1);
    assert.equal(primaryOf(claimed).id, identity.id);
    assert.deepEqual(claimed.members, roster.members, 'nothing else changed: the former primary is an ordinary member');
    assert.equal(claimed.network, roster.network);
    assert.equal(claimed.networkKey, roster.networkKey);

    // The former primary learns it and stops being the primary, on the same connection.
    await until(() => former.roster.version === claimed.version, 'the former primary to take the new roster');
    assert.equal(former.isPrimary, false);
    assert.equal(former.state, 'connected');
    assert.deepEqual(formerStates, []);
    assert.deepEqual(formerCloses, []);
    assert.throws(() => former.openPairingCode(), { code: 'invalid' });
    assert.throws(() => former.revoke(bob.id), { code: 'invalid' });
    await assert.rejects(former.usage(), { code: 'invalid' });
    await assert.rejects(pair({ link: stale.link, identity: createIdentity(), timeoutMs: 3000 }), { code: 'pairing' });

    // Everyone still talks to everyone.
    const toFormer = inbox(former);
    const toClaimant = inbox(claimant);
    await claimant.send(former.id, bytesOf('to the former primary'));
    await former.send(claimant.id, bytesOf('to the new primary'));
    await bob.send(former.id, bytesOf('from bob'));
    assert.deepEqual((await toFormer.next(2)).map((m) => textOf(m.bytes)).sort(), ['from bob', 'to the former primary']);
    assert.equal(textOf((await toClaimant.next())[0]!.bytes), 'to the new primary');

    // The new primary does the primary's work: usage, pairing, revocation.
    const u = await claimant.usage();
    assert.ok(u.network.connections >= 3);
    const code = claimant.openPairingCode();
    assert.deepEqual(Object.keys(code).sort(), ['code', 'codeId', 'expiresAt', 'link']);
    const seen: { member: string; codeId: string }[] = [];
    claimant.on('paired', (e) => seen.push({ member: e.member.id, codeId: e.codeId }));
    const newcomer = createIdentity();
    const { roster: withNewcomer } = await pair({ link: code.link, identity: newcomer });
    assert.equal(primaryOf(withNewcomer).id, identity.id);
    // The primary names the code that admitted the node: an application labels its members by code.
    await until(() => seen.length === 1, 'the paired event');
    assert.deepEqual(seen, [{ member: newcomer.id, codeId: code.codeId }]);
    const revoked = claimant.revoke(bob.id);
    assert.ok(!revoked.members.some((m) => m.id === bob.id));
    await until(() => bob.state === 'revoked', 'bob revoked by the new primary');
    await until(() => former.roster.version === revoked.version, 'the former primary to learn the revocation');
    assert.equal(former.state, 'connected');
    assert.deepEqual(formerCloses, []);
  } finally {
    await net.close();
  }
});

test("a network seed must be the roster's, and the primary needs one", () => {
  const id = createIdentity();
  const { roster } = createNetwork({ identity: id, relay: 'ws://127.0.0.1:9/v1' });
  assert.throws(() => new Member({ identity: id, roster, networkSeed: createNetworkSeed() }), { code: 'invalid' });
  assert.throws(() => new Primary({ identity: id, roster }), { code: 'invalid' });
});
