// The diagnostics entry point: each check on what it must catch and what it must
// not (random bytes, ciphertext, English, identifiers), the modes, onFinding,
// accept, the compression helper, and that the core does no diagnostic work
// unless diagnostics are on.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { DiagnosticFindingError, enableDiagnostics, encodedInJson, entropy, jsonHeader, textEncodedBinary, type Finding } from '../src/diagnostics.js';
import { deflate, inflate, MIN_COMPRESS_BYTES } from '../src/compression.js';
import { DIAGNOSTICS, type CoreStats, type DiagnosticsHook } from '../src/diag-hook.js';
import type { Member } from '../src/member.js';
import { bytesOf, inbox, startNetwork, until } from './support/network.js';

const enc = new TextEncoder();
const rnd = (n: number) => new Uint8Array(randomBytes(n));
const prose =
  'The relay forwards ciphertext it holds no key for. Members agree keys with Noise IK and send messages through it; it counts bytes per network and holds back senders when the network is over its rate. ';
const envelope = (header: object, body = new Uint8Array(0)) => {
  const j = enc.encode(JSON.stringify(header));
  const o = new Uint8Array(4 + j.length + body.length);
  new DataView(o.buffer).setUint32(0, j.length);
  o.set(j, 4);
  o.set(body, 4 + j.length);
  return o;
};
const STATS: CoreStats = { creditsSent: 0, messagesReceived: 0, inflightMaxBytes: 0, socketBacklogMaxBytes: 0, controlBacklogMaxBytes: 0 };

/** A member stand-in that only holds the hook, with a clock the test moves. */
function fake(opts: Parameters<typeof enableDiagnostics>[1] = {}) {
  let t = 1_000_000;
  const m = { timing: { rekeyIntervalMs: 600_000 }, hook: undefined as DiagnosticsHook | undefined } as { timing: object; hook: DiagnosticsHook | undefined };
  (m as unknown as Record<symbol, unknown>)[DIAGNOSTICS] = (h: DiagnosticsHook | undefined) => (m.hook = h);
  const off = enableDiagnostics(m as unknown as Member, { ...opts, now: () => t });
  return {
    get h() {
      return m.hook!;
    },
    at: (ms: number) => (t = ms),
    advance: (ms: number) => (t += ms),
    report: () => m.hook!.report(STATS),
    off,
    attached: () => m.hook !== undefined,
  };
}

// ── The pure checks ──

test('R1: base64, base64url and hex payloads are found; random bytes, English and identifiers are not', () => {
  for (let i = 0; i < 100; i++) {
    const raw = Buffer.from(rnd(48 + i * 37));
    assert.equal(textEncodedBinary(enc.encode(raw.toString('base64'))), 'base64', `base64 #${i}`);
    assert.equal(textEncodedBinary(enc.encode(raw.toString('base64url'))), 'base64', `base64url #${i}`);
    assert.equal(textEncodedBinary(enc.encode(raw.toString('hex'))), 'hex', `hex #${i}`);
  }
  for (let i = 0; i < 200; i++) assert.equal(textEncodedBinary(rnd(64 + i * 50)), null, 'random bytes');
  for (let i = 0; i < 50; i++) assert.equal(textEncodedBinary(enc.encode(prose.repeat(1 + (i % 10)).slice(0, 200 + i * 36))), null, 'English');
  for (let i = 0; i < 50; i++) {
    const urls = Array.from({ length: 20 }, (_, j) => `https://example.com/rooms/amber-falcon-${i}${j}/files/Report_${j}.pdf`).join(' ');
    assert.equal(textEncodedBinary(enc.encode(urls)), null, 'URLs');
  }
  assert.equal(textEncodedBinary(enc.encode('a'.repeat(63))), null, 'under 64 bytes is never judged');
  assert.equal(textEncodedBinary(enc.encode('1234567890'.repeat(10))), null, 'a long number is not hex');
});

test('R1: base64 and hex strings inside JSON are found; ordinary JSON is not', () => {
  for (let i = 0; i < 50; i++) {
    const b64 = enc.encode(JSON.stringify({ t: 'img', id: 'abc', data: Buffer.from(rnd(100 + i * 500)).toString('base64') }));
    const h = jsonHeader(b64)!;
    assert.ok(encodedInJson(b64, h.start, h.len), `base64 #${i}`);
    const hex = enc.encode(JSON.stringify({ t: 'key', k: Buffer.from(rnd(40)).toString('hex') }));
    const hh = jsonHeader(hex)!;
    assert.ok(encodedInJson(hex, hh.start, hh.len), `hex #${i}`);
  }
  const plain = enc.encode(JSON.stringify({ t: 'chat', from: 'amber-falcon-12', text: prose, at: 1790000000000, id: 'k2J9xQ' }));
  const p = jsonHeader(plain)!;
  assert.equal(encodedInJson(plain, p.start, p.len), false);
});

test('R2: JSON headers are found at the start or after a length prefix; binary payloads are not JSON', () => {
  const e = envelope({ t: 'cur', x: 1234.5, y: 2345.6 });
  assert.deepEqual(jsonHeader(e), { start: 4, len: e.length - 4 });
  assert.deepEqual(jsonHeader(enc.encode('{"a":[1,{"b":"}"}]}')), { start: 0, len: 19 });
  let found = 0;
  for (let i = 0; i < 2000; i++) {
    const r = rnd(64 + (i % 900));
    const h = jsonHeader(r);
    if (h && h.len * 4 > r.length) found++;
  }
  assert.equal(found, 0, 'random payloads read as mostly JSON');
});

test('R4: entropy separates text from ciphertext', () => {
  assert.ok(entropy(enc.encode(prose.repeat(20))) < 5);
  assert.ok(entropy(rnd(4096)) > 7.9);
  assert.equal(entropy(new Uint8Array(0)), 0);
});

// ── The hook, on a stand-in member with a moving clock ──

test('R2 hotJsonHeaders: over 10 a second with a large JSON share, and not for a video frame with a small header', () => {
  const d = fake();
  for (let i = 0; i < 25; i++) {
    d.advance(40);
    d.h.send('p', envelope({ t: 'cur', x: i, y: 2 * i, who: 'amber-falcon' }));
  }
  assert.ok(d.report().counts.hotJsonHeaders > 0);
  const v = fake();
  for (let i = 0; i < 25; i++) {
    v.advance(40);
    v.h.send('p', envelope({ t: 'vf', key: false, ts: i }, rnd(4000)));
  }
  assert.equal(v.report().counts.hotJsonHeaders, 0);
});

test('R3 tinyBatchable: tiny pairs within a tick, sustained for 3 s; never for a single keystroke', () => {
  const d = fake();
  for (let i = 0; i < 100; i++) {
    d.advance(40);
    d.h.send('p', new Uint8Array(30)); // cursor
    d.advance(1);
    d.h.send('p', new Uint8Array(60)); // pen, same tick
  }
  assert.ok(d.report().findings.tinyBatchable.count > 0);
  const k = fake();
  for (let i = 0; i < 100; i++) {
    k.advance(300);
    k.h.send('p', new Uint8Array(5));
  }
  assert.equal(k.report().counts.tinyBatchable, 0);
});

test('R4 compressibleUncompressed: large text is flagged and confirmed with deflate-raw; ciphertext is not', async () => {
  const d = fake({ sample: 1 });
  for (let i = 0; i < 40; i++) {
    d.advance(1100);
    d.h.send('p', enc.encode(prose.repeat(30)));
  }
  await until(() => d.report().findings.compressibleUncompressed.confirmed > 0, 'a confirmation');
  const c = d.report().findings.compressibleUncompressed;
  assert.equal(c.sampled, 40);
  assert.equal(c.flagged, 40);
  assert.ok(c.confirmedSavings.every((s) => s > 0.5), `savings ${c.confirmedSavings}`);
  assert.ok(d.report().counts.compressibleUncompressed > 0);
  const r = fake({ sample: 1 });
  for (let i = 0; i < 40; i++) r.h.send('p', rnd(6000));
  assert.equal(r.report().findings.compressibleUncompressed.flagged, 0);
  assert.equal(r.report().counts.compressibleUncompressed, 0);
});

test('R4: the screen samples one large message in sixteen by default', () => {
  const d = fake();
  for (let i = 0; i < 64; i++) d.h.send('p', rnd(2000));
  for (let i = 0; i < 64; i++) d.h.send('p', rnd(500));
  assert.equal(d.report().findings.compressibleUncompressed.sampled, 4);
});

test('R6 backlog: a small message that waited over 2 s is a finding; a large one taking long is not', () => {
  const d = fake();
  d.h.send('p', new Uint8Array(100));
  d.h.sent('p', 100, 2500, false);
  d.h.send('p', new Uint8Array(10_000_000));
  d.h.sent('p', 10_000_000, 9000, false);
  const r = d.report();
  assert.equal(r.findings.backlog.count, 1);
  assert.equal(r.findings.backlog.waitMaxMs, 9000);
  assert.equal(r.findings.backlog.queuedMaxBytes, 10_000_000);
});

test('R7 usageAsks: the third ask in a burst is near the budget, a refusal is a finding', () => {
  const d = fake();
  d.h.event({ kind: 'usageAsk' });
  d.h.event({ kind: 'usageAsk' });
  assert.equal(d.report().counts.usageAsks, 0);
  d.h.event({ kind: 'usageAsk' });
  assert.equal(d.report().findings.usageAsks.nearBudget, 1);
  d.h.event({ kind: 'usageRefused' });
  const u = d.report().findings.usageAsks;
  assert.deepEqual([u.count, u.refused], [3, 1]);
  // Asked once a minute, nothing is found.
  const q = fake();
  for (let i = 0; i < 10; i++) {
    q.advance(60_000);
    q.h.event({ kind: 'usageAsk' });
  }
  assert.equal(q.report().counts.usageAsks, 0);
});

test('R8 sentWhileSlowed: more than the trickle rate after a slowed answer; nothing once no longer slowed', () => {
  const d = fake();
  d.h.event({ kind: 'usage', slowed: true, trickleBps: 16384 });
  d.h.send('p', new Uint8Array(10_000));
  assert.equal(d.report().counts.sentWhileSlowed, 0, 'within the trickle');
  d.h.send('p', new Uint8Array(10_000));
  assert.equal(d.report().counts.sentWhileSlowed, 1);
  d.h.event({ kind: 'usage', slowed: false, trickleBps: 16384 });
  d.h.send('p', new Uint8Array(100_000));
  assert.equal(d.report().counts.sentWhileSlowed, 1);
  assert.equal(d.report().findings.sentWhileSlowed.bytes, 20_000);
});

test('R9 unreachableRetries: more than six a minute to one peer', () => {
  const d = fake();
  for (let i = 0; i < 6; i++) d.h.event({ kind: 'unreachable', peer: 'p' });
  assert.equal(d.report().counts.unreachableRetries, 0);
  d.h.event({ kind: 'unreachable', peer: 'p' });
  assert.equal(d.report().counts.unreachableRetries, 1);
  assert.equal(d.report().findings.unreachableRetries.worstPeerPerMin, 7);
  const slow = fake();
  for (let i = 0; i < 20; i++) {
    slow.advance(15_000);
    slow.h.event({ kind: 'unreachable', peer: 'p' });
  }
  assert.equal(slow.report().counts.unreachableRetries, 0);
});

test('R10 sessionChurn: handshakes beyond the rekey rate, reconnect loops, and any replacement', () => {
  const d = fake();
  for (let i = 0; i < 3; i++) d.h.event({ kind: 'handshake', peer: 'p' });
  assert.equal(d.report().counts.sessionChurn, 0);
  d.h.event({ kind: 'handshake', peer: 'p' });
  assert.equal(d.report().counts.sessionChurn, 1);
  const rekeys = fake();
  for (let i = 0; i < 10; i++) {
    rekeys.advance(600_000);
    rekeys.h.event({ kind: 'handshake', peer: 'p' });
  }
  assert.equal(rekeys.report().counts.sessionChurn, 0, 'one rekey per interval');
  const r = fake();
  for (let i = 0; i < 4; i++) r.h.event({ kind: 'reconnect' });
  assert.equal(r.report().findings.sessionChurn.reconnectsPerMinMax, 4);
  r.h.event({ kind: 'replaced' });
  assert.equal(r.report().findings.sessionChurn.replaced, 1);
  assert.equal(r.report().counts.sessionChurn, 2);
});

// ── Modes, onFinding, accept ──

test('onFinding: once per new kind and again each time its count doubles', () => {
  const seen: Finding[] = [];
  const d = fake({ onFinding: (f) => seen.push(f) });
  const b64 = enc.encode(Buffer.from(rnd(300)).toString('base64'));
  for (let i = 0; i < 9; i++) d.h.send('p', b64);
  assert.deepEqual(seen.map((f) => [f.kind, f.count, f.peer]), [
    ['textEncodedBinary', 1, 'p'],
    ['textEncodedBinary', 2, 'p'],
    ['textEncodedBinary', 4, 'p'],
    ['textEncodedBinary', 8, 'p'],
  ]);
  assert.ok(!JSON.stringify(d.report()).includes(Buffer.from(b64).toString().slice(0, 20)), 'no payload in the report');
});

test('accept: a reason accepts a kind (counted, never told); false mutes it', () => {
  const seen: Finding[] = [];
  const b64 = enc.encode(Buffer.from(rnd(300)).toString('base64'));
  const a = fake({ mode: 'throw', accept: { textEncodedBinary: 'a token the server issues as text' }, onFinding: (f) => seen.push(f) });
  a.h.send('p', b64);
  assert.equal(a.report().counts.textEncodedBinary, 1);
  assert.deepEqual(a.report().accepted, { textEncodedBinary: 'a token the server issues as text' });
  const m = fake({ mode: 'throw', accept: { textEncodedBinary: false }, onFinding: (f) => seen.push(f) });
  m.h.send('p', b64);
  assert.equal(m.report().counts.textEncodedBinary, 0);
  assert.deepEqual(seen, []);
});

test('throw mode: the offending send throws; a finding off the send path fails the next send', () => {
  const d = fake({ mode: 'throw' });
  assert.throws(() => d.h.send('p', enc.encode(Buffer.from(rnd(300)).toString('hex'))), (e: unknown) => e instanceof DiagnosticFindingError && e.finding.kind === 'textEncodedBinary');
  d.h.send('p', new Uint8Array(10));
  d.h.event({ kind: 'replaced' });
  assert.throws(() => d.h.send('p', new Uint8Array(10)), (e: unknown) => e instanceof DiagnosticFindingError && e.finding.kind === 'sessionChurn');
  d.h.send('p', new Uint8Array(10)); // thrown once
});

test('warn mode: one console.warn per kind, with the call site', (t) => {
  const warn = t.mock.method(console, 'warn', () => undefined);
  const d = fake({ mode: 'warn' });
  const b64 = enc.encode(Buffer.from(rnd(300)).toString('base64'));
  for (let i = 0; i < 5; i++) d.h.send('p', b64);
  assert.equal(warn.mock.callCount(), 1);
  assert.match(String(warn.mock.calls[0]!.arguments[0]), /textEncodedBinary[\s\S]*call site[\s\S]*diagnostics\.test\.ts/);
});

test('reset clears the report; disabling removes the hook', () => {
  const d = fake();
  d.h.send('p', enc.encode(Buffer.from(rnd(300)).toString('base64')));
  assert.equal(d.report().counts.textEncodedBinary, 1);
  d.h.reset();
  assert.equal(d.report().counts.textEncodedBinary, 0);
  assert.equal(d.report().sent.messages, 0);
  d.off();
  assert.equal(d.attached(), false);
  assert.throws(() => fake({ sample: 0 }), RangeError);
});

// ── The compression helper (R5) ──

test('compression: deflate and inflate one message; under 1 KiB is refused; inflate stops at its limit', async () => {
  const text = enc.encode(prose.repeat(40));
  const z = await deflate(text);
  assert.ok(z.length < text.length / 4);
  assert.deepEqual(await inflate(z), text);
  await assert.rejects(deflate(new Uint8Array(MIN_COMPRESS_BYTES - 1)), { code: 'invalid' });
  const bomb = await deflate(new Uint8Array(4 * 1024 * 1024));
  assert.ok(bomb.length < 10_000);
  await assert.rejects(inflate(bomb, 1024 * 1024), { code: 'invalid' });
  await assert.rejects(inflate(rnd(100)), { code: 'invalid' });
});

test('R5 compressedNoGain: compressing ciphertext-like bytes is a finding; text is not', async () => {
  const d = fake();
  await deflate(enc.encode(prose.repeat(40)));
  assert.equal(d.report().counts.compressedNoGain, 0);
  await deflate(rnd(8192));
  assert.equal(d.report().counts.compressedNoGain, 1);
  assert.equal(d.report().findings.compressedNoGain.bytes, 8192);
  const hook = d.h;
  d.off();
  await deflate(rnd(8192));
  assert.equal(hook.report(STATS).counts.compressedNoGain, 1, 'not told once disabled');
});

// ── Real members ──

test('real members: throw mode fails the send before anything goes out; off, the member reports nothing', async () => {
  const net = await startNetwork();
  try {
    const worker = await net.add('worker');
    assert.equal(worker.diagnostics(), undefined);
    await worker.send(net.primary.id, bytesOf('one session first'));
    const off = enableDiagnostics(worker, { mode: 'throw' });
    const frames = net.relay.frameLog.length;
    const before = worker.traffic().total.sent.messages;
    await assert.rejects(worker.send(net.primary.id, enc.encode(Buffer.from(rnd(200)).toString('base64'))), DiagnosticFindingError);
    assert.equal(net.relay.frameLog.length, frames, 'nothing reached the relay');
    assert.equal(worker.traffic().total.sent.messages, before);
    await worker.send(net.primary.id, rnd(500));
    const r = worker.diagnostics()!;
    assert.equal(r.mode, 'throw');
    assert.equal(r.counts.textEncodedBinary, 1);
    assert.equal(r.sent.messages, 2);
    off();
    assert.equal(worker.diagnostics(), undefined);
    await worker.send(net.primary.id, enc.encode(Buffer.from(rnd(200)).toString('base64'))); // off: sent as is
  } finally {
    await net.close();
  }
});

test('real members: usage asks, an unreachable peer, and the credit self-check', async () => {
  const net = await startNetwork();
  try {
    const worker = await net.add('worker');
    const gone = await net.add('surface');
    enableDiagnostics(net.primary);
    enableDiagnostics(worker);
    await net.primary.usage();
    await net.primary.usage();
    await net.primary.usage();
    await assert.rejects(net.primary.usage(), { code: 'rate-limited' });
    const u = net.primary.diagnostics()!.findings.usageAsks;
    assert.deepEqual([u.count, u.refused], [4, 1]);
    assert.ok(u.nearBudget >= 1);

    gone.close();
    await until(() => !net.relay.isConnected(net.primary.id, gone.id), 'the surface to leave');
    for (let i = 0; i < 7; i++) await assert.rejects(worker.send(gone.id, bytesOf('anyone?')), { code: 'unreachable' });
    assert.equal(worker.diagnostics()!.counts.unreachableRetries, 1);

    // Bulk small messages: credit comes back in batches. The primary takes what arrives; a
    // receiver that took nothing would stop this sender at its pace, 64 KiB in.
    inbox(net.primary);
    for (let i = 0; i < 500; i++) await worker.send(net.primary.id, new Uint8Array(300));
    await until(() => net.primary.diagnostics()!.findings.credits.messagesReceived >= 500, 'the messages');
    const c = net.primary.diagnostics()!.findings.credits;
    assert.ok(c.sentPerMessageReceived < 0.1, `${c.sent} credits for ${c.messagesReceived} messages`);
  } finally {
    await net.close();
  }
});

test('the core never imports the diagnostics or compression entry points', () => {
  const dir = new URL('../src/', import.meta.url);
  for (const f of readdirSync(dir)) {
    if (f === 'diagnostics.ts' || f === 'compression.ts') continue;
    const src = readFileSync(new URL(f, dir), 'utf8');
    assert.doesNotMatch(src, /from '\.\/(diagnostics|compression)\.js'/, `${f} imports an optional entry point`);
  }
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { exports: Record<string, unknown> };
  assert.deepEqual(Object.keys(pkg.exports), ['.', './diagnostics', './compression']);
});
