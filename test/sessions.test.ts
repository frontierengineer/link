// Sessions through the real relay: fragmentation and credit, rekeying, reset after a peer
// loses its state, unreachable peers, and a copy of an identity replacing the first.

import { before, test } from 'node:test';
import assert from 'node:assert/strict';
import { createIdentity, Member, pair } from '@frontierengineer/link-client';
import { relayBinary } from './support/relay.js';
import { bytesOf, FAST, inbox, sessionsOf, sleep, startNet, textOf, until } from './support/net.js';

before(() => {
  relayBinary();
});

function pattern(n: number, seed: number): Uint8Array {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (i * 131 + seed) & 0xff;
  return b;
}

test('a message of several MiB is fragmented, relayed and reassembled whole', async () => {
  const net = await startNet();
  try {
    const worker = await net.add('worker');
    const surface = await net.add('surface');
    const sIn = inbox(surface);
    const wIn = inbox(worker);
    const big = pattern(6 * 1024 * 1024 + 17, 3);
    await worker.send(surface.id, big);
    const [got] = await sIn.next(1, 60_000);
    assert.equal(got!.from, worker.id);
    assert.equal(got!.bytes.length, big.length);
    assert.ok(Buffer.from(got!.bytes).equals(Buffer.from(big)));
    // A fragment carries at most 65517 bytes, so at least 97 data frames went through.
    assert.ok(sessionsOf(worker).sessionInfo(surface.id)[0]!.sent >= Math.ceil(big.length / 65517));
    // And back the other way, on the same session.
    const back = pattern(3 * 1024 * 1024, 9);
    await surface.send(worker.id, back);
    assert.ok(Buffer.from((await wIn.next(1, 60_000))[0]!.bytes).equals(Buffer.from(back)));
  } finally {
    await net.close();
  }
});

test('credit: a sender waits while the receiving application takes nothing, and resumes as it reads', async () => {
  const net = await startNet();
  try {
    const worker = await net.add('worker');
    const surface = await net.add('surface');
    const reader = surface.messages;
    const msgs = [1, 2, 3].map((n) => new Uint8Array(700 * 1024).fill(n));
    // The first arrives while the application holds nothing, so its fragments are credited
    // back at once; the second arrives behind an unread message and is not; the third needs
    // more credit than is left and waits.
    await worker.send(surface.id, msgs[0]!);
    await worker.send(surface.id, msgs[1]!);
    let thirdDone = false;
    const third = worker.send(surface.id, msgs[2]!).then(() => (thirdDone = true));
    await sleep(500);
    assert.equal(thirdDone, false, 'the third message waits for credit');
    assert.equal(sessionsOf(worker).sessionInfo(surface.id)[0]!.sendCredit, 0, 'the whole window is in flight');
    assert.deepEqual((await reader.next()).value!.bytes, msgs[0]);
    await sleep(300);
    assert.equal(thirdDone, false, 'one message is still unread');
    assert.deepEqual((await reader.next()).value!.bytes, msgs[1]);
    await third;
    assert.deepEqual((await reader.next()).value!.bytes, msgs[2]);
    // Everything was taken: the full window is back with the sender.
    await until(() => sessionsOf(worker).sessionInfo(surface.id)[0]!.sendCredit === 1024 * 1024, 'all credit returned');
  } finally {
    await net.close();
  }
});

test('a larger creditWindow is granted as extra credit over the relay', async () => {
  const net = await startNet();
  try {
    const worker = await net.add('worker');
    const surface = await net.add('surface', { creditWindow: 8 * 1024 * 1024 });
    const sIn = inbox(surface);
    await worker.send(surface.id, bytesOf('x'));
    await sIn.next();
    await until(() => sessionsOf(worker).sessionInfo(surface.id)[0]?.sendCredit === 8 * 1024 * 1024, 'an 8 MiB window');
  } finally {
    await net.close();
  }
});

test('rekey on a timer: new sessions replace old ones while messages keep flowing in order', async () => {
  // The grace is the time a rekey handshake has before the responder expires the old
  // session; well above a loaded machine's round trip, as 30 s is above a real one.
  const timing = { ...FAST, rekeyIntervalMs: 250, retireGraceMs: 1000 };
  const net = await startNet({ member: { timing } });
  try {
    const worker = await net.add('worker');
    const surface = await net.add('surface');
    const sIn = inbox(surface);
    const wIn = inbox(worker);
    const indices = new Set<number>();
    for (let i = 0; i < 60; i++) {
      await worker.send(surface.id, bytesOf(`w${i}`));
      await surface.send(worker.id, bytesOf(`s${i}`));
      const cur = sessionsOf(worker).sessionInfo(surface.id).find((s) => s.current);
      if (cur) indices.add(cur.localIndex);
      await sleep(20);
    }
    assert.deepEqual((await sIn.next(60)).map((m) => textOf(m.bytes)), Array.from({ length: 60 }, (_, i) => `w${i}`));
    assert.deepEqual((await wIn.next(60)).map((m) => textOf(m.bytes)), Array.from({ length: 60 }, (_, i) => `s${i}`));
    assert.ok(indices.size >= 3, `expected at least two rekeys, saw ${indices.size} sessions`);
    // A rekey in the middle of a large message never splits it.
    const big = pattern(3 * 1024 * 1024, 5);
    await worker.send(surface.id, big);
    assert.ok(Buffer.from((await sIn.next(1, 30_000))[0]!.bytes).equals(Buffer.from(big)));
    await until(() => sessionsOf(worker).sessionInfo(surface.id).length <= 2, 'retired sessions to be forgotten', 15_000);
  } finally {
    await net.close();
  }
});

test('rekey after a message count', async () => {
  const net = await startNet({ member: { timing: { ...FAST, rekeyMessages: 4 } } });
  try {
    const worker = await net.add('worker');
    const surface = await net.add('surface');
    const sIn = inbox(surface);
    const indices = new Set<number>();
    for (let i = 0; i < 30; i++) {
      await worker.send(surface.id, bytesOf(String(i)));
      indices.add(sessionsOf(worker).sessionInfo(surface.id).find((s) => s.current)!.localIndex);
      await sleep(5);
    }
    assert.deepEqual((await sIn.next(30)).map((m) => textOf(m.bytes)), Array.from({ length: 30 }, (_, i) => String(i)));
    assert.ok(indices.size >= 4, `expected several rekeys, saw ${indices.size} sessions`);
  } finally {
    await net.close();
  }
});

test('reset: a peer that lost its state answers reset; the sender handshakes again', async () => {
  const net = await startNet();
  try {
    const worker = await net.add('worker');
    const surface = await net.add('surface');
    let sIn = inbox(surface);
    await worker.send(surface.id, bytesOf('one'));
    await sIn.next();
    const before = sessionsOf(worker).sessionInfo(surface.id)[0]!.localIndex;

    // The surface restarts: same identity and roster, no sessions. The relay replaces its
    // connection (4005 to the old copy, which is closed already).
    const { identity } = surface;
    const roster = surface.roster;
    surface.close();
    await sleep(100);
    const fresh = await Member.connect({ identity, roster, timing: FAST });
    net.members.push(fresh);
    sIn = inbox(fresh);

    // The worker still holds its session; its frame names an index the fresh copy does not.
    await worker.send(surface.id, bytesOf('lost'));
    await until(() => sessionsOf(worker).sessionInfo(surface.id).length === 0, 'the worker to drop the session on reset');
    await worker.send(surface.id, bytesOf('two'));
    assert.equal(textOf((await sIn.next())[0]!.bytes), 'two');
    assert.notEqual(sessionsOf(worker).sessionInfo(surface.id)[0]!.localIndex, before);
    assert.ok(!sIn.messages.some((m) => textOf(m.bytes) === 'lost'), 'the message in the reset frame is lost');
  } finally {
    await net.close();
  }
});

test('a responder expires a session past the rekey interval plus grace and answers reset', async () => {
  const net = await startNet();
  try {
    const worker = await net.add('worker', { timing: { ...FAST, rekeyIntervalMs: 3_600_000 } });
    const surface = await net.add('surface', { timing: { ...FAST, rekeyIntervalMs: 150, retireGraceMs: 100 } });
    const sIn = inbox(surface);
    await worker.send(surface.id, bytesOf('fresh'));
    await sIn.next();
    const first = sessionsOf(worker).sessionInfo(surface.id)[0]!.localIndex;
    await sleep(400);
    await worker.send(surface.id, bytesOf('expired'));
    await until(() => sessionsOf(worker).sessionInfo(surface.id).length === 0, 'the reset to arrive');
    await worker.send(surface.id, bytesOf('renewed'));
    assert.equal(textOf((await sIn.next())[0]!.bytes), 'renewed');
    assert.notEqual(sessionsOf(worker).sessionInfo(surface.id)[0]!.localIndex, first);
  } finally {
    await net.close();
  }
});

test('unreachable: a send to a member that is not connected fails at once; nothing is queued', async () => {
  const net = await startNet();
  try {
    const worker = await net.add('worker');
    const absent = createIdentity();
    await pair({ link: net.primary.openPairingCode('mcp').link, identity: absent });
    await until(() => worker.roster.members.some((m) => m.id === absent.id), 'the worker to learn of the mcp');
    const started = Date.now();
    await assert.rejects(worker.send(absent.id, bytesOf('x')), { code: 'unreachable' });
    assert.ok(Date.now() - started < 1000, 'at once');
    await assert.rejects(worker.send(createIdentity().id, bytesOf('x')), { code: 'invalid' });

    // A peer that leaves mid-session: the next send learns it from the relay.
    const surface = await net.add('surface');
    const sIn = inbox(surface);
    await worker.send(surface.id, bytesOf('1'));
    await sIn.next();
    surface.close();
    await sleep(100);
    await worker.send(surface.id, bytesOf('handed to the relay')).catch(() => undefined);
    await until(() => sessionsOf(worker).sessionInfo(surface.id).length === 0, 'the session to end on unreachable');
    await assert.rejects(worker.send(surface.id, bytesOf('x')), { code: 'unreachable' });
  } finally {
    await net.close();
  }
});

test('4005: a second copy of an identity replaces the first, which stops for good', async () => {
  const net = await startNet();
  try {
    const worker = await net.add('worker');
    const surface = await net.add('surface');
    const states: string[] = [];
    const codes: number[] = [];
    worker.on('state', (s) => states.push(s));
    worker.on('disconnect', (d) => codes.push(d.code));
    const copy = await Member.connect({ identity: worker.identity, roster: worker.roster, timing: FAST });
    net.members.push(copy);
    await until(() => worker.state === 'replaced', 'the first copy to be replaced');
    assert.deepEqual(codes, [4005]);
    await assert.rejects(worker.send(surface.id, bytesOf('x')), { code: 'replaced' });
    await assert.rejects(worker.waitConnected(), { code: 'replaced' });
    await sleep(400);
    assert.deepEqual(states, ['replaced'], 'no reconnect after 4005');
    assert.equal(copy.state, 'connected', 'the copy keeps its connection');
    const sIn = inbox(surface);
    await copy.send(surface.id, bytesOf('from the copy'));
    const [m] = await sIn.next();
    assert.equal(m!.from, worker.id);
    assert.equal(textOf(m!.bytes), 'from the copy');
  } finally {
    await net.close();
  }
});
