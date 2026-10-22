// Control is never slowed (spec sections 9 and 11): with the network over its quota and shaped
// at a 16 KB/s trickle, and members sending and receiving several MiB, usage asks and roster
// syncs are answered within 2 s, in both directions, with and without a 4 MiB queue in the
// relay; the relay tells every member when the trickle begins and when it lifts, within 2 s;
// and a second usage ask within 10 s is refused at once. Each scenario runs once per
// implementation as the primary, with the next implementation as the other member.

import { before, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { relayBinary } from './support/relay.js';
import { driverAvailability, FAST, IMPLS, requiredDrivers, scene, selectedDrivers, sleep, type Impl, type Node } from './support/driver.js';

before(() => {
  relayBinary();
});

const required = requiredDrivers();
const available: Impl[] = [];
for (const impl of selectedDrivers()) {
  const a = driverAvailability(impl);
  if (a.ok) available.push(impl);
  else if (required.includes(impl)) {
    test(`the ${impl} driver is available`, () => {
      throw new Error(`LINK_REQUIRE_DRIVERS names ${impl}, but ${a.reason}`);
    });
  }
}

interface Cast {
  p: Impl;
  a: Impl;
}

/** Each implementation as the primary once, the next one as the other member. */
const casts: Cast[] = available.map((p, i) => ({ p, a: available[(i + 1) % available.length]! }));

function each(name: string, body: (c: Cast) => Promise<void>): void {
  for (const c of casts) test(`${name} [p=${c.p} a=${c.a}]`, { timeout: 180_000 }, () => body(c));
}

const TRICKLE = 16384;
const QUOTA = 300_000;
const SIZE = 6 * 1024 * 1024;
/** What every control answer must come within, and every notice. */
const LIMIT_MS = 2000;
/** Long enough that a slow answer is measured, not timed out. */
const timing = { ...FAST, requestTimeoutMs: 60_000 };
const trickled = { LINK_QUOTA_BYTES_HOUR: String(QUOTA), LINK_TRICKLE_BPS: String(TRICKLE) };
const slowed = { rateBps: TRICKLE, slowed: true };

/** Starts a send of `SIZE` bytes that is never awaited: at the trickle it would take minutes. */
function bulk(from: Node, to: Node, fill: number): void {
  void from.d.send(to.id, { size: SIZE, fill }, 600_000).catch(() => undefined);
}

/** Waits for `n` to be told `want` (an event after `since`), which must have arrived at most
 * LIMIT_MS after `began`; returns how long after `began` it arrived. */
async function told(n: Node, want: { rateBps: number; slowed: boolean }, since: number, began: number): Promise<number> {
  const left = Math.max(1, began + LIMIT_MS - Date.now());
  const e = await n.d.waitFor('shaping', (e) => e.rateBps === want.rateBps && e.slowed === want.slowed, left, since);
  const took = n.d.eventTimes[n.d.events.indexOf(e)]! - began;
  assert.ok(took <= LIMIT_MS, `${n.d.label} was told ${JSON.stringify(want)} ${took} ms after`);
  const st = await n.d.state();
  assert.deepEqual(st.shaping, want, `${n.d.label}'s shaping property`);
  return took;
}

/** How long `f` took, failing past LIMIT_MS. */
async function quick<T>(what: string, f: () => Promise<T>): Promise<T> {
  const began = Date.now();
  const r = await f();
  const took = Date.now() - began;
  process.stderr.write(`[shaping] ${what}: ${took} ms\n`);
  assert.ok(took < LIMIT_MS, `${what} took ${took} ms`);
  return r;
}

/** The primary's usage ask within LIMIT_MS, reporting the network slowed; then a second ask at
 * once, refused rate_limited, also within LIMIT_MS. */
async function usageAnswered(P: Node): Promise<void> {
  const u = await quick(`${P.d.label}'s usage ask`, () => P.d.usage());
  assert.equal(u.network.slowed, true);
  assert.deepEqual(u.network.limits, { rateBps: 0, quotaBytesHour: QUOTA, trickleBps: TRICKLE });
  await quick(`${P.d.label}'s second ask, refused`, () =>
    P.d.usage().then(
      () => assert.fail('a second ask within 10 s was answered'),
      (e: { code?: string }) => assert.equal(e.code, 'rate-limited'),
    ),
  );
}

/** Asks twice, 10 s apart, while the transfers run. */
async function usageTwice(P: Node, between?: () => Promise<void>): Promise<void> {
  await usageAnswered(P);
  const next = Date.now() + 10_500;
  await between?.();
  await sleep(Math.max(0, next - Date.now()));
  await usageAnswered(P);
}

for (const queue of [undefined, '4194304']) {
  const env = queue ? { ...trickled, LINK_QUEUE_BYTES: queue } : trickled;
  const named = queue ? ` (LINK_QUEUE_BYTES=${queue})` : '';

  each(`a primary sending 6 MiB at a 16 KB/s trickle is told at once and has usage answered within 2 s${named}`, ({ p, a }) =>
    scene({ env, timing }, async (s) => {
      const P = await s.primary(p);
      const A = await s.add(a, 'a');
      const marks = [P.d.mark(), A.d.mark()];
      const began = Date.now();
      bulk(P, A, 1);
      // The quota is spent within the first moments of the transfer: both are told at once.
      await told(P, slowed, marks[0]!, began);
      await told(A, slowed, marks[1]!, began);
      // Past the relay's one-second grace, the trickle holds.
      await sleep(1500);
      await usageTwice(P);
    }),
  );

  each(`a primary receiving 6 MiB at a 16 KB/s trickle has usage answered within 2 s${named}`, ({ p, a }) =>
    scene({ env, timing }, async (s) => {
      const P = await s.primary(p);
      const A = await s.add(a, 'a');
      const mark = P.d.mark();
      const began = Date.now();
      bulk(A, P, 2);
      await told(P, slowed, mark, began);
      await sleep(1500);
      await usageTwice(P);
    }),
  );
}

each('two members sending 6 MiB each at once at a 16 KB/s trickle: usage and roster syncs within 2 s both ways', ({ p, a }) =>
  scene({ env: { ...trickled, LINK_QUEUE_BYTES: '4194304' }, timing }, async (s) => {
    const P = await s.primary(p);
    const A = await s.add(a, 'a');
    const mark = A.d.mark();
    const began = Date.now();
    bulk(P, A, 3);
    bulk(A, P, 4);
    await told(A, slowed, mark, began);
    await sleep(1500);
    // A member's control (a roster-request to the primary, and its answer) both ways under load.
    const sync = () => quick(`${A.d.label}'s roster sync`, () => A.d.syncRoster()).then(() => undefined);
    await sync();
    await usageTwice(P, sync);
    await sync();
  }),
);

each('the trickle is told to every member within 2 s of the quota being spent, and its lifting within 2 s of the limits changing', ({ p, a }) => {
  const dir = mkdtempSync(join(tmpdir(), 'link-limits-'));
  const file = join(dir, 'limits.json');
  writeFileSync(file, JSON.stringify({ quotaBytesHour: QUOTA, trickleBps: TRICKLE }));
  return scene({ env: { LINK_LIMITS_FILE: file }, timing }, async (s) => {
    const P = await s.primary(p);
    const A = await s.add(a, 'a');
    for (const n of [P, A]) assert.deepEqual((await n.d.state()).shaping, { rateBps: 0, slowed: false }, `${n.d.label} before`);
    const marks = [P.d.mark(), A.d.mark()];
    // 400 kB spend the 300 kB quota; the rest of them goes at the trickle.
    const began = Date.now();
    const sent = A.d.send(P.id, { size: 400_000, fill: 5 }, 60_000);
    const spent = [await told(P, slowed, marks[0]!, began), await told(A, slowed, marks[1]!, began)];
    // The quota lifted: every member is told the trickle no longer holds.
    const lift = [P.d.mark(), A.d.mark()];
    writeFileSync(file, JSON.stringify({ quotaBytesHour: 0, trickleBps: TRICKLE }));
    const reloaded = Date.now();
    await s.relay.reload();
    const lifted = [await told(P, { rateBps: 0, slowed: false }, lift[0]!, reloaded), await told(A, { rateBps: 0, slowed: false }, lift[1]!, reloaded)];
    process.stderr.write(`[shaping] told slowed after ${spent.join(', ')} ms, lifted after ${lifted.join(', ')} ms\n`);
    // Unshaped again, the rest goes at once, and so does another message.
    await sent;
    await A.d.send(P.id, { size: 200_000, fill: 6 });
    await P.d.messages(2, { from: A.id, timeoutMs: 5000 });
  }).finally(() => rmSync(dir, { recursive: true, force: true }));
});

test('every implementation is covered', () => {
  for (const impl of IMPLS) if (required.includes(impl)) assert.ok(available.includes(impl), impl);
});
