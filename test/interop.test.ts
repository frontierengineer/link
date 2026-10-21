// The same scenarios for every combination of implementations: drivers (drivers/PROTOCOL.md)
// of the TypeScript, Go and Rust clients, side by side on the real relay. A cast names the
// implementation of the primary (p) and of two other nodes (a and b); casts cover every
// ordered pair of a and b, each implementation as primary, and networks of all three.

import { before, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import type { PeerTraffic, Roster } from '@frontierengineer/link-client';
import { relayBinary } from './support/relay.js';
import {
  b64,
  driverAvailability,
  FAST,
  generated,
  IMPLS,
  nodeIdOf,
  requiredDrivers,
  rosterAtLeast,
  scene,
  selectedDrivers,
  sha256hex,
  sleep,
  textB64,
  textOf,
  until,
  type Driver,
  type Impl,
  type MessageEvent,
  type Node,
  type SessionInfo,
} from './support/driver.js';

before(() => {
  relayBinary();
});

// ── Which drivers run ──

const required = requiredDrivers();
const selected = selectedDrivers();
const available: Impl[] = [];
for (const impl of IMPLS) {
  if (!selected.includes(impl)) {
    test(`the ${impl} driver is available`, { skip: `LINK_DRIVERS=${selected.join(',')} leaves it out` }, () => undefined);
    continue;
  }
  const a = driverAvailability(impl);
  if (a.ok) available.push(impl);
  else if (required.includes(impl)) {
    test(`the ${impl} driver is available`, () => {
      throw new Error(`LINK_REQUIRE_DRIVERS names ${impl}, but ${a.reason}`);
    });
  } else test(`the ${impl} driver is available`, { skip: `${a.reason} (LINK_REQUIRE_DRIVERS=${impl} makes this a failure)` }, () => undefined);
}

interface Cast {
  p: Impl;
  a: Impl;
  b: Impl;
}

/**
 * Every ordered pair (a, b) once. When a and b are the same, the primary is the next
 * implementation round; when they differ, it is the third when there is one (so with three
 * implementations six casts are networks of all three), else b. Each implementation is then
 * primary, a and b equally often (three times each of nine casts with three implementations,
 * twice each of four with two), and with one implementation the single cast is all of it.
 */
function casts(impls: Impl[]): Cast[] {
  const out: Cast[] = [];
  for (const a of impls) {
    for (const b of impls) {
      const p = a === b ? impls[(impls.indexOf(a) + 1) % impls.length]! : (impls.find((x) => x !== a && x !== b) ?? b);
      out.push({ p, a, b });
    }
  }
  return out;
}

const CASTS = casts(available);
const TIMEOUT = 180_000;

function each(name: string, body: (c: Cast) => Promise<void>): void {
  for (const c of CASTS) test(`${name} [primary ${c.p}, a ${c.a}, b ${c.b}]`, { timeout: TIMEOUT }, () => body(c));
}

// ── Helpers ──

const randomNodeId = () => nodeIdOf(randomBytes(32).toString('base64'));
const lacks = (r: Roster, id: string) => !r.members.some((m) => m.id === id);

/** The texts of the next `n` messages `d` received from `from` since `since`. */
async function texts(d: Driver, from: string, n: number, since = 0, timeoutMs?: number): Promise<(string | undefined)[]> {
  return (await d.messages(n, { from, since, ...(timeoutMs !== undefined ? { timeoutMs } : {}) })).map(textOf);
}

function assertGenerated(m: Pick<MessageEvent, 'size' | 'sha256' | 'bytes'>, size: number, fill: number): void {
  const want = generated(size, fill);
  assert.equal(m.size, size);
  assert.equal(m.sha256, sha256hex(want));
  if (size <= 65536) assert.equal(m.bytes, b64(want), 'bytes carried up to 64 KiB');
  else assert.equal(m.bytes, undefined, 'no bytes over 64 KiB');
}

/** A send that must be refused with `code`. */
async function refusedWith(p: Promise<unknown>, code: string): Promise<void> {
  await assert.rejects(p, (e: { code?: string }) => {
    assert.equal(e.code, code, String(e));
    return true;
  });
}

/** a's current session with b, once b holds its other half: indices crossed, one initiator. */
async function sessionsAgree(a: Node, b: Node): Promise<SessionInfo> {
  let found: SessionInfo | undefined;
  await until(
    async () => {
      const mine = (await a.d.sessions(b.id)).find((x) => x.current);
      if (!mine) return false;
      const theirs = await b.d.sessions(a.id);
      const half = theirs.find((x) => x.localIndex === mine.remoteIndex && x.remoteIndex === mine.localIndex);
      if (!half || half.initiator === mine.initiator) return false;
      found = mine;
      return true;
    },
    `${a.d.label} and ${b.d.label} to hold the two halves of one session`,
  );
  return found!;
}

const DATA_FRAME = 40; // header 18, receiver index 4, type and flags 2, tag 16: plus the payload
const INIT_FRAME = 134; // header 18, sender index 4, Noise IK message 1 with a 16-byte payload (version and stamp): 112
const RESP_FRAME = 82; // header 18, two indices 8, Noise IK message 2 with an 8-byte payload: 56

/**
 * The handshakes `t` (what one node sent one peer) started, when everything else it sent was
 * `messages` messages of `size` bytes, one data frame each, plus answers to the peer's
 * handshakes: the sizes are fixed by the protocol, so the counts follow from frames and bytes.
 */
function handshakesStarted(t: PeerTraffic['sent'], messages: number, size: number): number {
  assert.equal(t.messages, messages);
  const others = t.frames - messages;
  const extra = t.frameBytes - messages * (DATA_FRAME + size);
  const inits = (extra - RESP_FRAME * others) / (INIT_FRAME - RESP_FRAME);
  assert.ok(Number.isInteger(inits) && inits >= 0 && inits <= others, `${t.frames} frames of ${t.frameBytes} bytes are not ${messages} messages of ${size} bytes and handshakes`);
  return inits;
}

// ── Scenarios ──

each('pairing by link and by code fields; the roster reaches everyone; messages every way', ({ p, a, b }) =>
  scene({}, async (s) => {
    const P = await s.primary(p);
    const A = await s.add(a, 'a');
    assert.equal(A.roster.version, 2);
    assert.equal(A.pinnedNetworkKey, P.roster.networkKey);
    await P.d.waitFor('paired', (e) => e.node === A.id && typeof e.codeId === 'string' && e.version === 2);

    // The second node pairs from the code's parts, typed as a person might: lower case, o for 0, l for 1.
    const code = await P.d.openPairingCode();
    assert.match(code.code, /^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);
    assert.deepEqual(Object.keys(code).sort(), ['code', 'codeId', 'expiresAt', 'link']);
    assert.ok(code.expiresAt > Date.now() + 14 * 60_000, 'a code lives 15 minutes');
    assert.ok(code.link.startsWith('frontier://pair?v=1&'), code.link);
    const bd = await s.spawn(b, 'b');
    const typed = code.code.toLowerCase().replace(/0/g, 'o').replace(/1/g, 'l');
    const r = await bd.pair({ network: P.roster.network, code: typed, codeId: code.codeId, relay: s.relay.url });
    assert.equal(r.roster.version, 3);
    assert.equal(r.pinnedNetworkKey, P.roster.networkKey);
    const entry = r.roster.members.find((m) => m.id === bd.id);
    assert.ok(entry);
    assert.deepEqual(Object.keys(entry).sort(), ['ed25519', 'id', 'x25519'], 'a member is its id and keys, nothing else');
    assert.equal(entry.ed25519, bd.ed25519, 'listed with its own key, in the roster\'s form');
    assert.equal(r.roster.primary, P.id);
    const B: Node = { d: bd, impl: b, id: bd.id, seed: bd.seed, roster: r.roster, pinnedNetworkKey: r.pinnedNetworkKey };
    await s.join(B);
    // The primary names the code that admitted it, so an application can label it by code.
    await P.d.waitFor('paired', (e) => e.node === B.id && e.codeId === code.codeId && e.version === 3);
    // The primary pushed v3 to the first member over their session.
    const pushed = await A.d.waitFor('roster', (e) => e.roster.version === 3);
    assert.ok(pushed.roster.members.some((m) => m.id === B.id));

    const all = [P, A, B];
    const since = all.map((n) => n.d.mark());
    for (const x of all) for (const y of all) if (x !== y) await x.d.send(y.id, { bytes: textB64(`${x.d.label} to ${y.d.label}`) });
    for (const [i, y] of all.entries()) {
      for (const x of all) if (x !== y) assert.deepEqual(await texts(y.d, x.id, 1, since[i]), [`${x.d.label} to ${y.d.label}`]);
    }
  }),
);

each('a wrong code fails and counts, five burn the code; expired and cancelled codes fail', ({ p, a, b }) =>
  scene({}, async (s) => {
    const P = await s.primary(p);
    const ad = await s.spawn(a, 'a');
    const bd = await s.spawn(b, 'b');
    const wrong = (c: { code: string; codeId: string }) => ({
      network: P.roster.network,
      code: c.code === 'AAAA-AAAA' ? 'BBBB-BBBB' : 'AAAA-AAAA',
      codeId: c.codeId,
      relay: s.relay.url,
    });

    // One failed confirmation keeps the code: the right code still pairs.
    const code = await P.d.openPairingCode();
    await refusedWith(ad.pair(wrong(code)), 'pairing');
    assert.equal((await P.d.waitFor('pairingFailed', (e) => e.codeId === code.codeId)).reason, 'wrong-code');
    assert.equal((await ad.pair({ link: code.link })).roster.version, 2);

    // Five burn it.
    const burn = await P.d.openPairingCode();
    for (let i = 0; i < 5; i++) await refusedWith(bd.pair(wrong(burn)), 'pairing');
    await until(() => P.d.seen('pairingFailed').filter((e) => e.codeId === burn.codeId).length === 5, 'five failures at the primary');
    assert.deepEqual(P.d.seen('pairingFailed').filter((e) => e.codeId === burn.codeId).map((e) => e.reason), Array(5).fill('wrong-code'));
    await refusedWith(bd.pair({ link: burn.link }), 'pairing');
    await until(() => P.d.seen('pairingFailed').filter((e) => e.codeId === burn.codeId).length === 6, 'the burned code refused');
    assert.equal(P.d.seen('pairingFailed').filter((e) => e.codeId === burn.codeId)[5]!.reason, 'unknown-code');

    // An expired code, and a cancelled one.
    const short = await P.d.openPairingCode({ lifetimeMs: 300 });
    await sleep(600);
    await refusedWith(bd.pair({ link: short.link }), 'pairing');
    assert.equal((await P.d.waitFor('pairingFailed', (e) => e.codeId === short.codeId)).reason, 'unknown-code');
    const cancelled = await P.d.openPairingCode();
    await P.d.cancelPairingCode(cancelled.codeId);
    await refusedWith(bd.pair({ link: cancelled.link }), 'pairing');
    assert.equal((await P.d.waitFor('pairingFailed', (e) => e.codeId === cancelled.codeId)).reason, 'unknown-code');

    // None of that admitted anyone; a fresh code does.
    assert.equal((await P.d.state()).roster.version, 2);
    const fresh = await P.d.openPairingCode();
    assert.equal((await bd.pair({ link: fresh.link })).roster.version, 3);
  }),
);

each('small messages both ways arrive whole and in order', ({ p, a, b }) =>
  scene({}, async (s) => {
    const P = await s.primary(p);
    const A = await s.add(a, 'a');
    const B = await s.add(b, 'b');
    const N = 20;
    const size = (i: number) => (i * 211) % 1500; // the first is empty
    const since = [P, A, B].map((n) => n.d.mark());
    for (let i = 0; i < N; i++) {
      // Both forms of payload: bytes given, and bytes generated.
      await A.d.send(B.id, { bytes: b64(generated(size(i), i)) });
      await B.d.send(A.id, { size: size(i), fill: i + 100 });
      if (i % 4 === 0) {
        await P.d.send(A.id, { size: size(i), fill: i + 200 });
        await A.d.send(P.id, { size: size(i), fill: i + 300 });
      }
    }
    const check = async (d: Driver, from: string, sinceIdx: number, fills: number[]) => {
      const got = await d.messages(fills.length, { from, since: sinceIdx });
      fills.forEach((fill, k) => assertGenerated(got[k]!, size(fill % 100), fill));
    };
    const idx = Array.from({ length: N }, (_, i) => i);
    const every4 = idx.filter((i) => i % 4 === 0);
    await check(B.d, A.id, since[2]!, idx);
    await check(A.d, B.id, since[1]!, idx.map((i) => i + 100));
    await check(A.d, P.id, since[1]!, every4.map((i) => i + 200));
    await check(P.d, A.id, since[0]!, every4.map((i) => i + 300));
  }),
);

each('several-MiB messages both ways at once, checked by sha256', ({ p, a, b }) =>
  scene({}, async (s) => {
    await s.primary(p);
    const A = await s.add(a, 'a');
    const B = await s.add(b, 'b');
    const big = 6 * 1024 * 1024 + 17;
    const back = 3 * 1024 * 1024;
    await Promise.all([A.d.send(B.id, { size: big, fill: 3 }, 120_000), B.d.send(A.id, { size: back, fill: 9 }, 120_000)]);
    assertGenerated((await B.d.messages(1, { from: A.id, timeoutMs: 60_000 }))[0]!, big, 3);
    assertGenerated((await A.d.messages(1, { from: B.id, timeoutMs: 60_000 }))[0]!, back, 9);
    // And again on the same sessions, one way then the other.
    await A.d.send(B.id, { size: back, fill: 11 }, 120_000);
    assertGenerated((await B.d.messages(2, { from: A.id, timeoutMs: 60_000 }))[1]!, back, 11);
  }),
);

each('flow control: a receiver that takes nothing holds its credit, the sender stalls, take releases it', ({ p, a, b }) =>
  scene({}, async (s) => {
    await s.primary(p);
    const A = await s.add(a, 'a');
    const B = await s.add(b, 'b', { autoTake: false });
    const size = 700 * 1024;
    const since = B.d.mark();
    // The first arrives while the receiver holds nothing, so its fragments are credited as they
    // come; the second arrives behind an untaken message and is not; the third needs more
    // credit than is left of the 1 MiB window and waits.
    await A.d.send(B.id, { size, fill: 1 });
    await A.d.send(B.id, { size, fill: 2 });
    let third = false;
    const sending = A.d.send(B.id, { size, fill: 3 }).then(() => (third = true));
    const arrived = await B.d.messages(2, { from: A.id, since });
    assertGenerated(arrived[0]!, size, 1);
    assertGenerated(arrived[1]!, size, 2);
    await sleep(500);
    assert.equal(third, false, 'the third message waits for credit');
    assert.equal(B.d.seen('message', since).length, 2, 'nothing more arrived');

    assertGenerated((await B.d.take(1))[0]!, size, 1);
    await sleep(400);
    assert.equal(third, false, 'one message is still untaken');
    assertGenerated((await B.d.take(1))[0]!, size, 2);
    await sending;
    assertGenerated((await B.d.messages(3, { from: A.id, since }))[2]!, size, 3);
    assertGenerated((await B.d.take(1))[0]!, size, 3);

    // A take that runs out of time takes nothing: the next message is there for the next take.
    await refusedWith(B.d.take(2, 300), 'timeout');
    await A.d.send(B.id, { bytes: textB64('four') });
    const [four] = await B.d.take(1, 10_000);
    assert.equal(Buffer.from(four!.bytes!, 'base64').toString(), 'four');
  }),
);

each('rekeying on a timer: handshakes repeat while traffic continues both ways', ({ p, a, b }) =>
  // A responder expires a session older than the interval plus the grace (2.25 s here), so a
  // missing rekey loses a message as well as showing in the sessions and the handshake count.
  // Paced by the protocol: one message at a time, each received before the next, until at least
  // MIN messages (over 3 s) went and a's current session changed three times, within 30 s.
  scene({ timing: { ...FAST, rekeyIntervalMs: 250, retireGraceMs: 2000 } }, async (s) => {
    await s.primary(p);
    const A = await s.add(a, 'a');
    const B = await s.add(b, 'b');
    await A.d.resetTraffic();
    let since = B.d.mark();
    const MIN = 40;
    const used: number[] = [];
    const deadline = Date.now() + 30_000;
    let n = 0;
    while (n < MIN || used.length < 4) {
      if (Date.now() > deadline) assert.fail(`a used sessions ${used.join(', ')} over ${n} messages and 30 s`);
      await A.d.send(B.id, { size: 10, fill: n % 256 });
      n++;
      await B.d.messages(n, { from: A.id, since, timeoutMs: 20_000 });
      const cur = (await A.d.sessions(B.id)).find((x) => x.current);
      if (cur && cur.localIndex !== used[used.length - 1]) used.push(cur.localIndex);
      await sleep(80);
    }
    assert.equal(new Set(used).size, used.length, `a returned to an old session: ${used.join(', ')}`);
    const got = await B.d.messages(n, { from: A.id, since });
    got.forEach((m, i) => assertGenerated(m, 10, i % 256));
    // One handshake to start, then one per rekey at least.
    const inits = handshakesStarted((await A.d.traffic()).peers[B.id]!.sent, n, 10);
    assert.ok(inits >= 4, `${inits} handshakes over ${n} messages at a 250 ms rekey interval`);
    assert.equal((await sessionsAgree(A, B)).initiator, true, 'a, which sent first, initiates');

    // Both ways at once, with a message of several MiB crossing a rekey whole.
    const N = 30;
    since = B.d.mark();
    const sinceA = A.d.mark();
    for (let i = 0; i < N; i++) {
      await Promise.all([A.d.send(B.id, { bytes: textB64(`a${i}`) }), B.d.send(A.id, { bytes: textB64(`b${i}`) })]);
      await sleep(20);
    }
    await A.d.send(B.id, { size: 3 * 1024 * 1024, fill: 5 }, 120_000);
    await A.d.send(B.id, { bytes: textB64('after') });
    const toB = await B.d.messages(N + 2, { from: A.id, since, timeoutMs: 30_000 });
    assert.deepEqual(toB.slice(0, N).map(textOf), Array.from({ length: N }, (_, i) => `a${i}`));
    assertGenerated(toB[N]!, 3 * 1024 * 1024, 5);
    assert.equal(textOf(toB[N + 1]!), 'after');
    assert.deepEqual(await texts(A.d, B.id, N, sinceA, 30_000), Array.from({ length: N }, (_, i) => `b${i}`));
    await sessionsAgree(A, B);
    // Replaced sessions are forgotten once their grace has passed.
    await until(async () => (await A.d.sessions(B.id)).length <= 2 && (await B.d.sessions(A.id)).length <= 2, 'replaced sessions to be forgotten', 15_000);
  }),
);

each('rekeying after a message count: handshakes repeat while traffic continues', ({ p, a, b }) =>
  // Paced by the protocol, not the clock: each round sends one message at a time, each received
  // before the next, until a's current session changes. A rekey is due once a session carried 4
  // transport messages, so a round needs 4 or 5 messages (a client may check when it sends next)
  // plus however long the handshake takes; 8 messages and 20 s bound it however loaded the machine.
  scene({ timing: { ...FAST, rekeyMessages: 4 } }, async (s) => {
    await s.primary(p);
    const A = await s.add(a, 'a');
    const B = await s.add(b, 'b');
    await A.d.resetTraffic();
    const since = B.d.mark();
    let n = 0;
    const sendOne = async () => {
      await A.d.send(B.id, { size: 10, fill: n });
      n++;
      await B.d.messages(n, { from: A.id, since, timeoutMs: 20_000 });
    };
    const current = async () => (await A.d.sessions(B.id)).find((x) => x.current)?.localIndex;
    await sendOne();
    const used = [await current()];
    assert.notEqual(used[0], undefined, 'a holds a session after its first message');
    const ROUNDS = 3;
    for (let round = 0; round < ROUNDS; round++) {
      const before = used[used.length - 1];
      const deadline = Date.now() + 20_000;
      let sent = 0;
      let now = before;
      while (now === before) {
        if (sent < 8) {
          await sendOne();
          sent++;
        } else if (Date.now() > deadline) {
          assert.fail(`round ${round + 1}: a still uses session ${before} after ${sent} messages and 20 s`);
        } else await sleep(20);
        now = await current();
      }
      used.push(now);
    }
    assert.equal(new Set(used).size, ROUNDS + 1, `a used sessions ${used.join(', ')}`);
    const got = await B.d.messages(n, { from: A.id, since });
    got.forEach((m, i) => assertGenerated(m, 10, i));
    // One handshake to start, then one per rekey at least.
    const inits = handshakesStarted((await A.d.traffic()).peers[B.id]!.sent, n, 10);
    assert.ok(inits >= ROUNDS + 1, `${inits} handshakes for ${n} messages at a rekey every 4`);
    await sessionsAgree(A, B);
    // And back the other way, across further rekeys.
    const sinceA = A.d.mark();
    const N = 30;
    for (let i = 0; i < N; i++) await B.d.send(A.id, { bytes: textB64(String(i)) });
    assert.deepEqual(await texts(A.d, B.id, N, sinceA, 20_000), Array.from({ length: N }, (_, i) => String(i)));
    await sessionsAgree(A, B);
  }),
);

each('reset: a peer restarted from its seed has no sessions; it answers reset and the sender handshakes again', ({ p, a, b }) =>
  scene({}, async (s) => {
    await s.primary(p);
    const A = await s.add(a, 'a');
    const B = await s.add(b, 'b');
    await A.d.send(B.id, { bytes: textB64('one') });
    assert.deepEqual(await texts(B.d, A.id, 1), ['one']);
    const first = await sessionsAgree(A, B);

    // B restarts: the same seed and roster, no sessions.
    const { roster } = await B.d.state();
    await B.d.shutdown();
    const B2: Node = { ...B, d: await s.spawn(b, 'b restarted', B.seed) };
    assert.equal(B2.d.id, B.id, 'the same seed is the same node');
    await s.join(B2, { roster });
    assert.deepEqual(await B2.d.sessions(), [], 'a restart holds no sessions');

    // A still holds its session: its frame names an index B2 does not hold, and B2 answers
    // reset (a bare frame of 22 bytes), the only frame it sends A.
    await A.d.resetTraffic();
    await A.d.send(B.id, { bytes: textB64('lost') });
    await until(async () => ((await A.d.traffic()).peers[B.id]?.received.frames ?? 0) >= 1, 'the reset to reach the sender');
    const r = (await A.d.traffic()).peers[B.id]!.received;
    assert.deepEqual([r.frames, r.frameBytes, r.messages], [1, 22, 0]);
    await until(async () => (await A.d.sessions(B.id)).length === 0, 'the sender to drop the session on reset');
    await A.d.send(B.id, { bytes: textB64('two') });
    assert.deepEqual(await texts(B2.d, A.id, 1), ['two']);
    assert.notEqual((await sessionsAgree(A, B2)).localIndex, first.localIndex, 'a new session');
    assert.equal(B2.d.seen('message').length, 1, 'the message in the reset frame is lost');
  }),
);

each('unreachable: a send to a member that is not connected fails at once; so does one to a peer that left', ({ p, a, b }) =>
  scene({}, async (s) => {
    await s.primary(p);
    const A = await s.add(a, 'a');
    const X = await s.pairOnly(b, 'absent');
    await rosterAtLeast(A.d, X.roster.version);
    const started = Date.now();
    await refusedWith(A.d.send(X.id, { bytes: textB64('x') }), 'unreachable');
    assert.ok(Date.now() - started < 1000, 'at once');
    await refusedWith(A.d.send(randomNodeId(), { bytes: textB64('x') }), 'invalid');
    // A node whose relay never answers: connect gives up with timeout, and close stops it.
    await refusedWith(
      X.d.connect({ role: 'member', roster: X.roster, relayUrl: 'ws://127.0.0.1:9/v1', timing: FAST, timeoutMs: 300 }),
      'timeout',
    );
    await X.d.close();
    assert.equal((await X.d.state()).state, 'closed');

    // A peer that leaves mid-session: the relay answers the next frame unreachable.
    const B = await s.add(b, 'b');
    await A.d.send(B.id, { bytes: textB64('1') });
    assert.deepEqual(await texts(B.d, A.id, 1), ['1']);
    await B.d.close();
    await until(
      async () => {
        try {
          await A.d.send(B.id, { bytes: textB64('handed to the relay') });
          return false;
        } catch (e) {
          if ((e as { code?: string }).code === 'unreachable') return true;
          throw e;
        }
      },
      'a send to fail unreachable',
      5000,
      50,
    );
  }),
);

each('refused: a member whose roster lacks the sender refuses it, then catches up from the primary', ({ p, a, b }) =>
  // The relay forgets an idle network; the first member back presents an old roster and the
  // relay knows no better. Only the member itself can catch up.
  scene({ env: { LINK_NETWORK_TTL: '500ms' } }, async (s) => {
    const P = await s.primary(p);
    const A = await s.add(a, 'a'); // v2
    await A.d.shutdown();
    const B = await s.add(b, 'b'); // v3, which A never saw
    const pRoster = (await P.d.state()).roster;
    await B.d.shutdown();
    await P.d.shutdown();
    await sleep(1500);

    const A2: Node = { ...A, d: await s.spawn(a, 'a again', A.seed) };
    await s.join(A2);
    assert.equal((await A2.d.state()).roster.version, 2, 'the relay had nothing newer');
    const B2: Node = { ...B, d: await s.spawn(b, 'b again', B.seed) };
    await s.join(B2);
    assert.equal((await A2.d.state()).state, 'connected', 'v3 still lists A');

    await assert.rejects(B2.d.send(A.id, { bytes: textB64('do you know me?') }), { code: 'refused', reason: 1 });
    assert.equal((await A2.d.state()).roster.version, 2, 'the primary is away, so A cannot catch up yet');

    const P2 = await s.spawn(p, 'primary again', P.seed);
    await P2.connect({ role: 'primary', roster: pRoster, networkSeed: P.networkSeed, timing: FAST });
    assert.equal((await A2.d.syncRoster()).version, 3);
    const since = A2.d.mark();
    await B2.d.send(A.id, { bytes: textB64('now you do') });
    assert.deepEqual(await texts(A2.d, B.id, 1, since), ['now you do']);
  }),
);

each('a new primary: a node started with the network seed claims it; the former primary is demoted in place, still connected', ({ p, a, b }) =>
  scene({}, async (s) => {
    const P = await s.primary(p);
    const A = await s.add(a, 'a');
    const B = await s.add(b, 'b');
    const held = (await A.d.state()).roster;
    const since = P.d.mark();

    // The test, as the application, gives a's node the network seed and starts it with it.
    await A.d.close();
    await A.d.connect({ role: 'primary', roster: held, networkSeed: P.networkSeed, timing: FAST });
    const claimed = (await A.d.state()).roster;
    assert.equal((await A.d.state()).primary, true);
    assert.equal(claimed.version, held.version + 1);
    assert.equal(claimed.primary, A.id);
    assert.deepEqual(claimed.members, held.members, 'nothing else changed: the former primary is an ordinary member');
    assert.equal(claimed.network, P.roster.network);
    assert.equal(claimed.networkKey, P.roster.networkKey);

    // The former primary takes it and stops being the primary, on the same connection.
    await P.d.waitFor('roster', (e) => e.roster.version === claimed.version, 10_000, since);
    await B.d.waitFor('roster', (e) => e.roster.version === claimed.version);
    const st = await P.d.state();
    assert.equal(st.state, 'connected');
    assert.equal(st.primary, false);
    await refusedWith(P.d.openPairingCode(), 'invalid');
    await refusedWith(P.d.revoke(B.id), 'invalid');
    await refusedWith(P.d.usage(), 'invalid');

    // Everyone still talks to everyone.
    await A.d.send(P.id, { bytes: textB64('to the former primary') });
    assert.deepEqual(await texts(P.d, A.id, 1, since), ['to the former primary']);
    await P.d.send(A.id, { bytes: textB64('to the new primary') });
    assert.deepEqual(await texts(A.d, P.id, 1), ['to the new primary']);
    await B.d.send(P.id, { bytes: textB64('from b') });
    assert.deepEqual(await texts(P.d, B.id, 1, since), ['from b']);

    // The new primary does the primary's work: usage, pairing, revocation.
    assert.ok((await A.d.usage()).network.connections >= 3);
    const cd = await s.spawn(p, 'c');
    const code = await A.d.openPairingCode();
    const { roster: withC } = await cd.pair({ link: code.link });
    assert.equal(withC.primary, A.id);
    await cd.connect({ role: 'member', roster: withC, timing: FAST });
    const r = await A.d.revoke(B.id);
    assert.ok(lacks(r, B.id));
    await B.d.waitFor('state', (e) => e.state === 'revoked', 10_000);
    await P.d.waitFor('roster', (e) => e.roster.version === r.version, 10_000, since);

    // Nobody was disconnected by the change: the former primary saw no close and no state change.
    assert.deepEqual(P.d.seen('disconnect', since), []);
    assert.deepEqual(P.d.seen('state', since), []);
    assert.equal((await P.d.state()).state, 'connected');
  }),
);

each('revocation: the revoked node ends revoked for good; the others stop accepting it', ({ p, a, b }) =>
  scene({}, async (s) => {
    const P = await s.primary(p);
    const A = await s.add(a, 'a');
    const B = await s.add(b, 'b');
    await B.d.send(A.id, { bytes: textB64('before') });
    assert.deepEqual(await texts(A.d, B.id, 1), ['before']);
    await A.d.send(B.id, { bytes: textB64('a session both ways') });
    assert.deepEqual(await texts(B.d, A.id, 1), ['a session both ways']);

    const since = B.d.mark();
    const r = await P.d.revoke(B.id);
    assert.equal(r.version, 4);
    assert.ok(lacks(r, B.id));
    await B.d.waitFor('state', (e) => e.state === 'revoked', 10_000, since);
    await A.d.waitFor('roster', (e) => e.roster.version === 4);
    await refusedWith(A.d.send(B.id, { bytes: textB64('to the revoked') }), 'invalid');
    await refusedWith(P.d.send(B.id, { bytes: textB64('to the revoked') }), 'invalid');
    await refusedWith(B.d.send(A.id, { bytes: textB64('from the revoked') }), 'revoked');
    await refusedWith(B.d.waitConnected(), 'revoked');
    await sleep(400);
    assert.deepEqual(B.d.seen('disconnect', since).map((e) => e.code), [4008], 'closed 4008, and no reconnect');
    assert.deepEqual(B.d.seen('state', since).map((e) => e.state), ['revoked']);
    assert.equal((await B.d.state()).state, 'revoked');

    // A copy of the revoked identity, of another implementation, with its old roster, is
    // turned away at registration.
    const again = await s.spawn(p, 'b copy', B.seed);
    await again.start({ role: 'member', roster: B.roster, pinnedNetworkKey: B.pinnedNetworkKey, timing: FAST });
    await refusedWith(again.waitConnected(10_000), 'revoked');
  }),
);

each('resignation: the primary publishes a roster without the member, which the relay then closes', ({ p, a, b }) =>
  scene({}, async (s) => {
    const P = await s.primary(p);
    const A = await s.add(a, 'a');
    const B = await s.add(b, 'b');
    const since = B.d.mark();
    await B.d.resign();
    assert.equal((await B.d.state()).state, 'revoked');
    assert.deepEqual(B.d.seen('disconnect', since).map((e) => e.code), [4008]);
    const pr = (await P.d.state()).roster;
    assert.equal(pr.version, 4);
    assert.ok(lacks(pr, B.id));
    await A.d.waitFor('roster', (e) => e.roster.version === 4);
    await refusedWith(A.d.send(B.id, { bytes: textB64('x') }), 'invalid');
  }),
);

each('a revocation spreads member to member while the primary is offline', ({ p, a, b }) =>
  // a carries the revocation, b learns it, and x (of p's implementation) is revoked.
  scene({ env: { LINK_NETWORK_TTL: '300ms' } }, async (s) => {
    const P = await s.primary(p);
    const W = await s.pairOnly(a, 'a');
    const T = await s.pairOnly(b, 'b');
    const X = await s.pairOnly(p, 'x');
    const before = (await P.d.state()).roster; // v4, as X and T hold it
    await s.join(W, { roster: before });
    const after = await P.d.revoke(X.id);
    await rosterAtLeast(W.d, after.version);
    const wRoster = (await W.d.state()).roster;
    assert.equal(wRoster.version, after.version);
    // Everyone goes; the relay forgets the network.
    await W.d.shutdown();
    await P.d.shutdown();
    await sleep(800);

    // b and the revoked x come back first, both on the roster from before: a relay that knows
    // nothing newer lets them in, and they talk.
    await s.join(T, { roster: before });
    await s.join(X, { roster: before });
    await T.d.send(X.id, { bytes: textB64('before') });
    assert.deepEqual(await texts(X.d, T.id, 1), ['before']);

    // a comes back with the revocation. The primary is still away: b learns it from a alone,
    // then refuses x by itself.
    const W2: Node = { ...W, d: await s.spawn(a, 'a again', W.seed) };
    await s.join(W2, { roster: wRoster });
    await T.d.send(W.id, { bytes: textB64('hello') });
    assert.deepEqual(await texts(W2.d, T.id, 1), ['hello']);
    await until(async () => (await T.d.state()).roster.version === after.version, 'b to learn the revocation from a');
    await refusedWith(T.d.send(X.id, { bytes: textB64('after') }), 'invalid');
  }),
);

each('replacement: a second copy of an identity, of another implementation, replaces the first (4005)', ({ p, a, b }) =>
  scene({}, async (s) => {
    await s.primary(p);
    const A = await s.add(a, 'a');
    const B = await s.add(b, 'b');
    const since = A.d.mark();
    const copy: Node = { ...A, d: await s.spawn(p, 'a copy', A.seed) };
    await s.join(copy);
    await A.d.waitFor('state', (e) => e.state === 'replaced', 10_000, since);
    assert.deepEqual(A.d.seen('disconnect', since).map((e) => e.code), [4005]);
    await refusedWith(A.d.send(B.id, { bytes: textB64('x') }), 'replaced');
    await refusedWith(A.d.waitConnected(), 'replaced');
    await sleep(400);
    assert.deepEqual(A.d.seen('state', since).map((e) => e.state), ['replaced'], 'no reconnect after 4005');
    assert.equal((await copy.d.state()).state, 'connected', 'the copy keeps its connection');
    const sinceB = B.d.mark();
    await copy.d.send(B.id, { bytes: textB64('from the copy') });
    assert.deepEqual(await texts(B.d, A.id, 1, sinceB), ['from the copy']);
  }),
);

each('usage: the primary reads the network totals and limits; asks beyond the budget are refused', ({ p, a, b }) => {
  const limits = { rateBps: 50_000_000, quotaBytesHour: 100_000_000, trickleBps: 200_000 };
  const env = {
    LINK_RATE_BPS: String(limits.rateBps),
    LINK_QUOTA_BYTES_HOUR: String(limits.quotaBytesHour),
    LINK_TRICKLE_BPS: String(limits.trickleBps),
  };
  return scene({ env }, async (s) => {
    const P = await s.primary(p);
    const A = await s.add(a, 'a');
    const B = await s.add(b, 'b');
    await s.pairOnly(a, 'never connected');
    const before = await P.d.usage();
    // Totals only: the relay keeps no per-member figures.
    assert.deepEqual(Object.keys(before), ['network']);
    assert.deepEqual(Object.keys(before.network).sort(), ['bytesHour', 'connections', 'limits', 'quotaUsed', 'slowed']);
    assert.equal(before.network.connections, 3);
    assert.deepEqual(before.network.limits, limits);
    assert.equal(before.network.slowed, false);

    const payload = 300_000;
    await A.d.send(B.id, { size: payload, fill: 1 });
    await B.d.messages(1, { from: A.id });
    const after = await P.d.usage();
    assert.ok(after.network.bytesHour - before.network.bytesHour >= payload, `${before.network.bytesHour} then ${after.network.bytesHour}`);
    assert.ok(after.network.quotaUsed > 0 && after.network.quotaUsed < 1, `quotaUsed ${after.network.quotaUsed}`);
    assert.equal(after.network.slowed, false);

    // Three asks at once, then one per 10 s: of four more at once, at least one is refused.
    const asks = await Promise.allSettled([1, 2, 3, 4].map(() => P.d.usage()));
    const refused = asks.filter((r) => r.status === 'rejected');
    assert.ok(refused.length >= 1, 'over the budget');
    for (const r of refused) assert.equal((r.reason as { code?: string }).code, 'rate-limited');
  });
});

each('traffic: what the sender counts sent, the receiver counts received', ({ p, a, b }) =>
  scene({}, async (s) => {
    await s.primary(p);
    const A = await s.add(a, 'a');
    const B = await s.add(b, 'b');
    // A first exchange, so the counts below are of an established session only.
    await A.d.send(B.id, { bytes: textB64('hello') });
    await B.d.messages(1, { from: A.id });
    await sleep(400);
    await Promise.all([A.d.resetTraffic(), B.d.resetTraffic()]);
    const sizes = [300_000, 10, 70_000];
    for (const [i, size] of sizes.entries()) await A.d.send(B.id, { size, fill: i });
    await B.d.send(A.id, { size: 5000, fill: 9 });
    await B.d.messages(1 + sizes.length, { from: A.id });
    await A.d.messages(1, { from: B.id });

    // Credit goes back in batches, within 250 ms: wait until the counts agree, and stay so.
    const views = async () => {
      const [ta, tb] = await Promise.all([A.d.traffic(), B.d.traffic()]);
      return { ta, tb, ab: ta.peers[B.id], ba: tb.peers[A.id] };
    };
    const agree = async () => {
      const { ab, ba } = await views();
      return ab !== undefined && ba !== undefined && JSON.stringify([ab.sent, ab.received]) === JSON.stringify([ba.received, ba.sent]);
    };
    await until(async () => (await agree()) && (await sleep(300), await agree()), 'the two sides to agree', 10_000, 50);
    const { ta, tb, ab, ba } = await views();
    assert.deepEqual(ab!.sent, ba!.received);
    assert.deepEqual(ab!.received, ba!.sent);
    assert.equal(ab!.sent.messages, sizes.length);
    assert.equal(ab!.sent.bytes, sizes.reduce((x, y) => x + y, 0));
    assert.equal(ba!.sent.messages, 1);
    assert.equal(ba!.sent.bytes, 5000);
    for (const t of [ab!.sent, ba!.sent]) {
      assert.ok(t.frameBytes > t.bytes && t.frameBytes < t.bytes * 1.01 + 200 * t.frames, `${t.frameBytes} frame bytes for ${t.bytes}`);
    }
    // Only these two talked since the reset: the totals are this one peer.
    assert.deepEqual(ta.total, ab);
    assert.deepEqual(tb.total, ba);
    assert.equal(typeof ta.since, 'number');
    assert.equal(typeof ta.relay.sent, 'number');
    assert.equal(typeof ta.relay.received, 'number');
  }),
);

// The lifecycle and the error codes PROTOCOL.md gives every driver, once per implementation.
for (const impl of available) {
  test(`the driver lifecycle and its error codes [${impl}]`, { timeout: TIMEOUT }, () =>
    scene({}, async (s) => {
      // Before an identity: nothing but identity; an unknown command is internal.
      const bare = s.bare(impl, 'bare');
      await refusedWith(bare.state(), 'invalid');
      await refusedWith(bare.createNetwork(s.relay.url), 'invalid');
      await refusedWith(bare.pair({ link: 'frontier://pair?v=1' }), 'invalid');
      await refusedWith(bare.call('noSuchCommand'), 'internal');
      // identity may be called again; a seed always gives the same node.
      const first = await bare.identity();
      assert.equal((await bare.identity(first.seed)).node, first.node);
      assert.notEqual((await bare.identity()).node, first.node);
      await refusedWith(bare.state(), 'invalid');

      const P = await s.primary(impl);
      const M = await s.add(impl, 'm');
      // Primary only, and member only.
      await refusedWith(M.d.openPairingCode(), 'invalid');
      await refusedWith(M.d.cancelPairingCode('AAAAAAAAAAA'), 'invalid');
      await refusedWith(M.d.revoke(P.id), 'invalid');
      await refusedWith(M.d.usage(), 'invalid');
      await refusedWith(P.d.resign(), 'invalid');
      assert.equal((await P.d.syncRoster()).version, (await P.d.state()).roster.version);
      await refusedWith(P.d.revoke(P.id), 'invalid');
      await refusedWith(P.d.revoke(randomNodeId()), 'invalid');
      await refusedWith(P.d.openPairingCode({ code: 'ABC' }), 'invalid');
      // Arguments a node refuses.
      await refusedWith(M.d.take(1), 'invalid');
      await refusedWith(M.d.send(M.id, { bytes: textB64('me') }), 'invalid');
      await refusedWith(M.d.send(P.id, { size: 64 * 1024 * 1024 + 1, fill: 0 }), 'invalid');
      await refusedWith(M.d.connect({ role: 'member', roster: M.roster, timing: FAST }), 'invalid');
      await refusedWith(M.d.start({ role: 'member', roster: M.roster, timing: FAST }), 'invalid');
      const q = await s.spawn(impl, 'q');
      const roster = (await P.d.state()).roster;
      await refusedWith(q.connect({ role: 'member', roster, timing: FAST }), 'invalid'); // not on it
      await refusedWith(q.connect({ role: 'primary', roster: M.roster, timing: FAST }), 'invalid');
      const copy = await s.spawn(impl, 'm copy', M.seed);
      await refusedWith(copy.connect({ role: 'primary', roster: M.roster, timing: FAST }), 'invalid'); // no network seed
      await refusedWith(copy.connect({ role: 'member', roster: M.roster, creditWindow: 1000, timing: FAST }), 'invalid');
      await refusedWith(copy.connect({ role: 'member', roster: M.roster, pinnedNetworkKey: M.d.ed25519, timing: FAST }), 'invalid');
      await refusedWith(copy.state(), 'invalid');
      assert.equal((await M.d.state()).state, 'connected', 'none of that disturbed the member');

      // close, then connect again: a new node, no sessions, traffic counted afresh.
      await M.d.send(P.id, { bytes: textB64('before') });
      await P.d.messages(1, { from: M.id });
      const since = M.d.mark();
      await M.d.close();
      assert.equal((await M.d.state()).state, 'closed');
      await refusedWith(M.d.send(P.id, { bytes: textB64('closed') }), 'closed');
      await M.d.connect({ role: 'member', roster: M.roster, timing: FAST, timeoutMs: 10_000 });
      assert.deepEqual(M.d.seen('state', since).map((e) => e.state), ['closed', 'connecting', 'connected']);
      assert.deepEqual(await M.d.sessions(), []);
      assert.equal((await M.d.traffic()).total.sent.messages, 0);
      const sinceP = P.d.mark();
      await M.d.send(P.id, { bytes: textB64('after') });
      assert.deepEqual(await texts(P.d, M.id, 1, sinceP), ['after']);
    }),
  );
}

// A network of every implementation at once, once with each as primary.
for (const p of available) {
  test(`a mixed network: every node sends to every other [primary ${p}, members ${available.join(' ')}]`, { timeout: TIMEOUT }, () =>
    scene({}, async (s) => {
      const P = await s.primary(p);
      const members = available.length > 1 ? available : [p, p];
      const nodes = [P];
      for (const [i, impl] of members.entries()) nodes.push(await s.add(impl, `m${i}`));
      const since = nodes.map((n) => n.d.mark());
      await Promise.all(
        nodes.map(async (x, i) => {
          for (const [j, y] of nodes.entries()) {
            if (x === y) continue;
            await x.d.send(y.id, { bytes: textB64(`${i}>${j}`) });
            await x.d.send(y.id, { size: 200_000, fill: i * 16 + j });
          }
        }),
      );
      for (const [j, y] of nodes.entries()) {
        for (const [i, x] of nodes.entries()) {
          if (x === y) continue;
          const got = await y.d.messages(2, { from: x.id, since: since[j], timeoutMs: 30_000 });
          assert.equal(textOf(got[0]!), `${i}>${j}`);
          assertGenerated(got[1]!, 200_000, i * 16 + j);
        }
      }
    }),
  );
}
