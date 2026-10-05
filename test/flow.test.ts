// Flow end to end, the client against the real relay: control is not stuck behind a sender's
// own data under shaping (the client keeps its socket short), usage asks are budgeted, credit
// is batched, and library traffic trips none of the diagnostics.

import { before, test } from 'node:test';
import assert from 'node:assert/strict';
import { RateLimitedError, USAGE_BURST } from '@frontierengineer/link-client';
import { enableDiagnostics } from '@frontierengineer/link-client/diagnostics';
import { relayBinary } from './support/relay.js';
import { bytesOf, FAST, inbox, startNet } from './support/net.js';

before(() => {
  relayBinary();
});

test('a sender that floods a shaped network still has its usage ask answered within seconds', async () => {
  // 64 KiB/s for the whole network. The primary queues 4 MiB of messages; before the client
  // kept its socket short, up to a 1 MiB credit window sat ahead of the ask: 16 s at this rate.
  // Now about 1.5 s of what the receiver takes (a little more just after the relay's burst).
  const net = await startNet({ env: { LINK_RATE_BPS: '65536' }, member: { timing: { ...FAST, requestTimeoutMs: 10_000 } } });
  try {
    const worker = await net.add('worker');
    inbox(worker);
    const sends = Array.from({ length: 64 }, () => net.primary.send(worker.id, new Uint8Array(65536)).catch(() => undefined));
    await new Promise((r) => setTimeout(r, 1500)); // the network is deep in its bucket by now
    const began = Date.now();
    const u = await net.primary.usage();
    const took = Date.now() - began;
    assert.ok(took < 3500, `usage answered after ${took} ms`);
    assert.equal(u.network.limits.rateBps, 65536);
    // The socket stayed short: what was handed over is what the network carried in those
    // seconds plus about two seconds of pace, never the 4 MiB queued or the 1 MiB window.
    const handed = net.primary.traffic().total.sent.frameBytes;
    assert.ok(handed < 1_000_000, `${handed} bytes handed to the socket in ~${(Date.now() - began + 1500) / 1000} s at 64 KiB/s`);
    net.primary.close();
    await Promise.all(sends);
  } finally {
    await net.close();
  }
});

test('usage asks: three at once, then refused with RateLimitedError until the budget refills', async () => {
  const net = await startNet();
  try {
    for (let i = 0; i < USAGE_BURST; i++) await net.primary.usage();
    await assert.rejects(net.primary.usage(), (e: unknown) => e instanceof RateLimitedError && e.code === 'rate-limited');
  } finally {
    await net.close();
  }
});

test('credit is batched: bulk small messages bring back few credit frames', async () => {
  const net = await startNet();
  try {
    const worker = await net.add('worker');
    const surface = await net.add('surface');
    const sIn = inbox(surface);
    worker.resetTraffic();
    surface.resetTraffic();
    const n = 2000;
    for (let i = 0; i < n; i++) await worker.send(surface.id, new Uint8Array(200).fill(i & 0xff));
    await sIn.next(n, 30_000);
    await new Promise((r) => setTimeout(r, 400)); // the last batch's timer
    const back = surface.traffic().peers[worker.id]!.sent;
    assert.equal(back.messages, 0);
    assert.ok(back.frames / n < 0.1, `${back.frames} credit frames for ${n} messages`);
  } finally {
    await net.close();
  }
});

test('diagnostics in count mode: what the library itself sends trips no rule', async () => {
  const net = await startNet();
  try {
    const worker = await net.add('worker');
    const surface = await net.add('surface');
    const members = [net.primary, worker, surface];
    for (const m of members) enableDiagnostics(m, { mode: 'count', sample: 1 });
    const sIn = inbox(surface);
    const wIn = inbox(worker);
    // Raw binary of every size, a few at a time, as an application following the rules sends.
    const random = (n: number) => crypto.getRandomValues(new Uint8Array(n));
    for (let i = 0; i < 20; i++) {
      await worker.send(surface.id, random(i * 3000 + 1));
      await surface.send(worker.id, random(500));
      await new Promise((r) => setTimeout(r, 50));
    }
    await worker.send(surface.id, bytesOf('hello'));
    await sIn.next(21);
    await wIn.next(20);
    await worker.syncRoster();
    await net.primary.usage();
    for (const m of members) {
      const d = m.diagnostics()!;
      assert.deepEqual(
        Object.entries(d.counts).filter(([, c]) => c > 0),
        [],
        `${m.id === net.primary.id ? 'primary' : m.id}: ${JSON.stringify(d.counts)}`,
      );
    }
    assert.ok(surface.diagnostics()!.findings.credits.sentPerMessageReceived < 0.5);
  } finally {
    await net.close();
  }
});
