// `@frontierengineer/link-client/diagnostics`: checks an application's traffic
// against the rules for apps on Link (client README) while it runs, so a test
// suite can fail on base64 payloads, JSON headers on hot paths, tiny messages
// that should be batched, compressible bytes sent as they are, a backlog in the
// client's own queue, usage asked too often, sending while slowed, retry loops
// and session churn. Off, it costs the core one branch per send and receive;
// a bundle that never imports this module carries none of it.
//
// The report holds sizes, counts, verdicts and peer ids, never payload bytes,
// and stays in the process: nothing is sent to the relay or anywhere else.
// Thresholds and their measured accuracy and cost: link-audit section 6.

import {
  compressionListeners,
  DIAGNOSTICS,
  type CompressionListener,
  type CoreStats,
  type DiagnosticsEvent,
  type DiagnosticsHook,
  type DiagnosticsReport,
  type FindingKind,
} from './diag-hook.js';
import type { Member } from './member.js';

export type { DiagnosticsReport, FindingKind } from './diag-hook.js';

export type DiagnosticsMode = 'count' | 'warn' | 'throw';

export interface Finding {
  kind: FindingKind;
  /** How many times this kind has been found so far. */
  count: number;
  /** The peer involved, when there is one. */
  peer?: string;
  /** What was seen, in words: sizes and rates, never content. */
  detail: string;
}

export interface DiagnosticsOptions {
  /** `count` (default): counters only. `warn`: console.warn once per kind, with the call site.
   * `throw`: the offending send rejects with DiagnosticFindingError before anything is sent; a
   * finding made off the send path (a refused usage ask, churn, compression) fails the next send. */
  mode?: DiagnosticsMode;
  /** The fraction of large messages that get the compressibility screen. Default 1/16. */
  sample?: number;
  /** Per kind: a reason accepts it (still counted, never warned or thrown); `false` mutes it (not counted). */
  accept?: Partial<Record<FindingKind, string | false>>;
  /** Called once per new kind, and again each time its count doubles. */
  onFinding?: (f: Finding) => void;
  /** Clock in milliseconds, for tests. */
  now?: () => number;
}

/** What `throw` mode fails a send with. */
export class DiagnosticFindingError extends Error {
  constructor(readonly finding: Finding) {
    super(`link diagnostics: ${finding.kind}: ${finding.detail}`);
    this.name = 'DiagnosticFindingError';
  }
}

// ── Thresholds (section 6 of the audit; the README's rules) ──

/** R1: messages this long or longer are screened for text-encoded binary, over at most SCAN bytes. */
const ENCODED_MIN = 64;
const ENCODED_SCAN = 256;
/** R1: base64 or hex runs inside JSON, over at most this much of the JSON. */
const JSON_SCAN = 4096;
/** R2: more than this many messages a second to one peer, each more than a quarter JSON header. */
const HOT_RATE = 10;
/** R3: messages under TINY bytes to one peer, less than TINY_GAP_MS apart, above TINY_RATE a second for TINY_SPAN_MS. */
const TINY = 128;
const TINY_GAP_MS = 40;
const TINY_RATE = 5;
const TINY_SPAN_MS = 3000;
/** R4: messages over COMPRESS_MIN bytes, screened by order-0 entropy over at most COMPRESS_SAMPLE bytes. */
const COMPRESS_MIN = 1024;
const COMPRESS_SAMPLE = 4096;
const ENTROPY_COMPRESSIBLE = 7.0;
/** R4: a real deflate of a flagged message at most once a second, over at most this much of it. */
const CONFIRM_EVERY_MS = 1000;
const CONFIRM_MAX = 65536;
/** R4: warn once what could be saved passes this share of bytes sent. */
const SAVABLE_SHARE = 0.05;
/** R5: the compression helper should save at least this. */
const MIN_GAIN = 0.1;
/** R6: a message this small that waited longer than this to be handed over sat in a backlog. */
const BACKLOG_SMALL = 65536;
const BACKLOG_WAIT_MS = 2000;
/** R7: the relay's usage budget (section 4.3), and the share of it that counts as near. */
const USAGE_BURST = 3;
const USAGE_INTERVAL_MS = 10_000;
const USAGE_NEAR = 0.8;
/** R9: unreachable failures to one peer within a minute. */
const UNREACHABLE_PER_MIN = 6;
/** R10: handshakes this side starts with one peer within one rekey interval, and reconnects a minute. */
const HANDSHAKES_PER_INTERVAL = 3;
const RECONNECTS_PER_MIN = 3;

const ALL_KINDS: FindingKind[] = [
  'textEncodedBinary',
  'base64InJson',
  'hotJsonHeaders',
  'tinyBatchable',
  'compressibleUncompressed',
  'compressedNoGain',
  'backlog',
  'usageAsks',
  'sentWhileSlowed',
  'unreachableRetries',
  'sessionChurn',
];

// ── The per-message checks (pure; exported for the tests) ──

const B64 = new Uint8Array(256);
for (const c of 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_') B64[c.charCodeAt(0)] = 1;
const HEX = new Uint8Array(256);
for (const c of '0123456789abcdefABCDEF') HEX[c.charCodeAt(0)] = 1;

const isDigit = (x: number) => x >= 48 && x <= 57;
const isUpper = (x: number) => x >= 65 && x <= 90;
const isLower = (x: number) => x >= 97 && x <= 122;

/** R1: the whole message is base64, base64url or hex text (judged on its first 256 bytes). */
export function textEncodedBinary(b: Uint8Array): 'base64' | 'hex' | null {
  if (b.length < ENCODED_MIN) return null;
  const n = Math.min(b.length, ENCODED_SCAN);
  let in64 = 0;
  let inHex = 0;
  let digits = 0;
  let upper = 0;
  let lower = 0;
  for (let i = 0; i < n; i++) {
    const x = b[i]!;
    in64 += B64[x]!;
    inHex += HEX[x]!;
    if (isDigit(x)) digits++;
    else if (isUpper(x)) upper++;
    else if (isLower(x)) lower++;
  }
  // Encoded binary mixes the classes evenly; words and identifiers rarely do at these ratios.
  if (inHex === n && digits > n * 0.05 && digits < n) return 'hex';
  if (in64 === n && digits > n * 0.05 && upper > n * 0.15 && lower > n * 0.15) return 'base64';
  return null;
}

/** R2: a JSON header at the start, or after a length prefix of up to 4 bytes: where it starts and how long it is. */
export function jsonHeader(b: Uint8Array): { start: number; len: number } | null {
  for (const start of [0, 1, 2, 4]) {
    if (start >= b.length) break;
    const c = b[start];
    if (c !== 0x7b && c !== 0x5b) continue;
    const len = jsonEnd(b, start);
    if (len > 0) return { start, len };
  }
  return null;
}

/** Bytes JSON may hold outside its strings: whitespace, structure, numbers, true, false, null. */
const JSON_BARE = new Uint8Array(256);
for (const c of ' \t\r\n{}[],:0123456789-+.eEtrufalsn') JSON_BARE[c.charCodeAt(0)] = 1;

function jsonEnd(b: Uint8Array, start: number): number {
  let depth = 0;
  let inStr = false;
  const end = Math.min(b.length, start + 65536);
  for (let i = start; i < end; i++) {
    const x = b[i]!;
    if (inStr) {
      if (x === 92) i++;
      else if (x === 34) inStr = false;
      else if (x < 32) return 0;
      continue;
    }
    if (x === 34) inStr = true;
    else if (x === 0x7b || x === 0x5b) depth++;
    else if (x === 0x7d || x === 0x5d) {
      if (--depth === 0) return i + 1 - start;
    } else if (!JSON_BARE[x]) return 0; // a byte JSON cannot hold here: binary, not JSON
  }
  return 0;
}

/** R1: a long base64 or hex string inside JSON: a mixed run of 64 or more closed by a quote, or of 128 or more. */
export function encodedInJson(b: Uint8Array, start: number, len: number): boolean {
  const end = Math.min(start + len, start + JSON_SCAN, b.length);
  let run = 0;
  let hexRun = 0;
  let d = 0;
  let u = 0;
  let l = 0;
  let hd = 0;
  let hl = 0;
  for (let i = start; i < end; i++) {
    const x = b[i]!;
    const closes = i + 1 < end && b[i + 1] === 34;
    if (B64[x]) {
      run++;
      if (isDigit(x)) d++;
      else if (isUpper(x)) u++;
      else if (isLower(x)) l++;
      if (run >= 64 && d > 3 && u > 8 && l > 8 && (closes || run >= 128)) return true;
    } else {
      run = d = u = l = 0;
    }
    if (HEX[x]) {
      hexRun++;
      if (isDigit(x)) hd++;
      else hl++;
      if (hexRun >= 64 && hd > 8 && hl > 8 && (closes || hexRun >= 128)) return true;
    } else {
      hexRun = hd = hl = 0;
    }
  }
  return false;
}

const hist = new Uint32Array(256);

/** R4: order-0 entropy in bits per byte over at most the first 4 KiB. */
export function entropy(b: Uint8Array): number {
  const n = Math.min(b.length, COMPRESS_SAMPLE);
  if (n === 0) return 0;
  hist.fill(0);
  for (let i = 0; i < n; i++) hist[b[i]!]!++;
  let e = 0;
  for (let i = 0; i < 256; i++) {
    const c = hist[i]!;
    if (c) {
      const p = c / n;
      e -= p * Math.log2(p);
    }
  }
  return e;
}

// ── The hook ──

interface PeerState {
  // R2
  winStart: number;
  winCount: number;
  // R3
  lastAt: number;
  lastSize: number;
  tinyStart: number;
  tinyCount: number;
  tinyLastPair: number;
  // R9, R10: timestamps within the window
  unreachable: number[];
  handshakes: number[];
}

/**
 * Turns diagnostics on for `member` and returns a function that turns them off. Read the report
 * with `member.diagnostics()`; clear it with `member.resetDiagnostics()`.
 */
export function enableDiagnostics(member: Member, opts: DiagnosticsOptions = {}): () => void {
  const d = new Diagnostics(member, opts);
  const listener: CompressionListener = (inBytes, outBytes) => d.compressed(inBytes, outBytes);
  compressionListeners().add(listener);
  member[DIAGNOSTICS](d);
  return () => {
    compressionListeners().delete(listener);
    member[DIAGNOSTICS](undefined);
  };
}

class Diagnostics implements DiagnosticsHook {
  private readonly mode: DiagnosticsMode;
  private readonly every: number;
  private readonly accept: Partial<Record<FindingKind, string | false>>;
  private readonly onFinding: ((f: Finding) => void) | undefined;
  private readonly now: () => number;
  private readonly rekeyMs: number;
  private r!: DiagnosticsReport;
  private warned!: Set<FindingKind>;
  private peers!: Map<string, PeerState>;
  private pending: Finding | undefined;
  private sampleTick = 0;
  private lastConfirm = -Infinity;
  private savings!: number;
  private queued = 0;
  private usageTat = 0;
  private reconnects: number[] = [];
  private slowed: { since: number; bytes: number; trickle: number } | undefined;

  constructor(member: Member, o: DiagnosticsOptions) {
    this.mode = o.mode ?? 'count';
    const sample = o.sample ?? 1 / 16;
    if (!(sample > 0 && sample <= 1)) throw new RangeError('sample must be in (0, 1]');
    this.every = Math.max(1, Math.round(1 / sample));
    this.accept = { ...o.accept };
    this.onFinding = o.onFinding;
    this.now = o.now ?? Date.now;
    this.rekeyMs = (member as unknown as { timing?: { rekeyIntervalMs?: number } }).timing?.rekeyIntervalMs ?? 600_000;
    this.reset();
  }

  reset(): void {
    const accepted: Partial<Record<FindingKind, string>> = {};
    for (const k of ALL_KINDS) {
      const a = this.accept[k];
      if (typeof a === 'string') accepted[k] = a;
    }
    this.r = {
      mode: this.mode,
      sent: { messages: 0, bytes: 0 },
      received: { messages: 0, bytes: 0 },
      counts: Object.fromEntries(ALL_KINDS.map((k) => [k, 0])) as Record<FindingKind, number>,
      findings: {
        textEncodedBinary: { count: 0, bytes: 0, firstAt: null },
        base64InJson: { count: 0, bytes: 0, firstAt: null },
        hotJsonHeaders: { count: 0, jsonBytes: 0 },
        tinyBatchable: { count: 0 },
        compressibleUncompressed: { sampled: 0, flagged: 0, confirmed: 0, confirmedSavings: [], estSavableBytes: 0 },
        compressedNoGain: { count: 0, bytes: 0 },
        backlog: { count: 0, inflightMaxBytes: 0, socketBacklogMaxBytes: 0, controlBacklogMaxBytes: 0, queuedMaxBytes: 0, waitMaxMs: 0 },
        usageAsks: { count: 0, refused: 0, nearBudget: 0 },
        sentWhileSlowed: { count: 0, bytes: 0 },
        unreachableRetries: { count: 0, worstPeerPerMin: 0 },
        sessionChurn: { count: 0, handshakes: 0, perPeerPerIntervalMax: 0, reconnects: 0, reconnectsPerMinMax: 0, replaced: 0 },
        credits: { sent: 0, messagesReceived: 0, sentPerMessageReceived: 0 },
      },
      accepted,
    };
    this.warned = new Set();
    this.peers = new Map();
    this.pending = undefined;
    this.savings = 0;
    this.reconnects = [];
    this.slowed = undefined;
  }

  report(stats: CoreStats): DiagnosticsReport {
    const f = this.r.findings;
    const b = f.backlog;
    b.inflightMaxBytes = stats.inflightMaxBytes;
    b.socketBacklogMaxBytes = stats.socketBacklogMaxBytes;
    b.controlBacklogMaxBytes = stats.controlBacklogMaxBytes;
    const sent = stats.creditsSent;
    const got = stats.messagesReceived;
    f.credits = { sent, messagesReceived: got, sentPerMessageReceived: got === 0 ? 0 : sent / got };
    return structuredCloneReport(this.r);
  }

  // ── The send path: synchronous, may throw in `throw` mode ──

  send(peer: string, bytes: Uint8Array): void {
    const now = this.now();
    const size = bytes.length;
    this.r.sent.messages++;
    this.r.sent.bytes += size;
    this.queued += size;
    if (this.queued > this.r.findings.backlog.queuedMaxBytes) this.r.findings.backlog.queuedMaxBytes = this.queued;
    let found: Finding | undefined;
    const take = (x: Finding | undefined) => (found ??= x);

    // R1: encoded binary, whole or inside JSON.
    const enc = textEncodedBinary(bytes);
    const f = this.r.findings;
    if (enc) {
      f.textEncodedBinary.bytes += size;
      f.textEncodedBinary.firstAt ??= now;
      take(this.find('textEncodedBinary', peer, `a ${size}-byte message is ${enc} text: send the raw bytes (+33% for base64, +100% for hex)`));
    }
    const header = enc ? null : jsonHeader(bytes);
    const json = header?.len ?? 0;
    if (header) {
      if (encodedInJson(bytes, header.start, header.len)) {
        f.base64InJson.bytes += size;
        f.base64InJson.firstAt ??= now;
        take(this.find('base64InJson', peer, `a ${size}-byte JSON message carries a long base64 or hex string: send the bytes after a binary header`));
      }
    }

    // R2 and R3: per-peer rates.
    const ps = this.peer(peer, now);
    if (now - ps.winStart >= 1000) {
      ps.winStart = now;
      ps.winCount = 0;
    }
    ps.winCount++;
    if (ps.winCount > HOT_RATE && json * 4 > size) {
      f.hotJsonHeaders.jsonBytes += json;
      take(this.find('hotJsonHeaders', peer, `${ps.winCount} messages in a second to one peer, ${json} of ${size} bytes JSON header: use a small binary header`));
    }
    if (size < TINY && ps.lastSize < TINY && now - ps.lastAt < TINY_GAP_MS) {
      if (now - ps.tinyLastPair > 1000) {
        ps.tinyStart = now;
        ps.tinyCount = 0;
      }
      ps.tinyLastPair = now;
      ps.tinyCount++;
      const span = now - ps.tinyStart;
      if (span >= TINY_SPAN_MS && (ps.tinyCount * 1000) / span > TINY_RATE) {
        ps.tinyStart = now;
        ps.tinyCount = 0;
        take(this.find('tinyBatchable', peer, `tiny messages to one peer under ${TINY_GAP_MS} ms apart for ${TINY_SPAN_MS / 1000} s: merge each tick's messages into one`));
      }
    }
    ps.lastAt = now;
    ps.lastSize = size;

    // R4: sampled compressibility screen, confirmed off the send path.
    if (size > COMPRESS_MIN && ++this.sampleTick % this.every === 0) {
      const c = f.compressibleUncompressed;
      c.sampled++;
      const h = entropy(bytes);
      if (h < ENTROPY_COMPRESSIBLE) {
        c.flagged++;
        // Until a real deflate says otherwise, entropy bounds what order-0 coding alone saves.
        const saving = c.confirmed > 0 ? this.savings / c.confirmed : (8 - h) / 8;
        c.estSavableBytes += Math.round(size * this.every * saving);
        this.confirm(bytes, now);
        if (c.estSavableBytes > this.r.sent.bytes * SAVABLE_SHARE) {
          take(this.find('compressibleUncompressed', peer, `${size}-byte messages at ${h.toFixed(1)} bits per byte go uncompressed; about ${c.estSavableBytes} bytes could be saved`));
        }
      }
    }

    // R8: sending while the network is slowed, beyond its whole trickle rate.
    const sl = this.slowed;
    if (sl) {
      sl.bytes += size;
      f.sentWhileSlowed.bytes += size;
      const allowed = sl.trickle * Math.max(1, (now - sl.since) / 1000);
      if (sl.trickle > 0 && sl.bytes > allowed) {
        take(this.find('sentWhileSlowed', peer, `${sl.bytes} bytes sent since usage said slowed, over the network's ${sl.trickle} B/s trickle: drop video, keep audio`));
      }
    }

    const pending = this.pending;
    this.pending = undefined;
    const thrown = found ?? pending;
    if (this.mode === 'throw' && thrown) throw new DiagnosticFindingError(thrown);
  }

  sent(_peer: string, size: number, waitedMs: number, failed: boolean): void {
    this.queued -= size;
    const b = this.r.findings.backlog;
    if (waitedMs > b.waitMaxMs) b.waitMaxMs = waitedMs;
    if (!failed && size <= BACKLOG_SMALL && waitedMs > BACKLOG_WAIT_MS) {
      this.later(this.find('backlog', _peer, `a ${size}-byte message waited ${Math.round(waitedMs)} ms to be handed over: shed load (skip to the next keyframe) instead of queueing`));
    }
  }

  received(_peer: string, bytes: Uint8Array): void {
    this.r.received.messages++;
    this.r.received.bytes += bytes.length;
  }

  // ── Events off the send path: recorded, thrown at the next send in `throw` mode ──

  event(e: DiagnosticsEvent): void {
    const now = this.now();
    const f = this.r.findings;
    switch (e.kind) {
      case 'unreachable': {
        f.unreachableRetries.count++;
        const ps = this.peer(e.peer, now);
        ps.unreachable = ps.unreachable.filter((t) => now - t < 60_000);
        ps.unreachable.push(now);
        const n = ps.unreachable.length;
        if (n > f.unreachableRetries.worstPeerPerMin) f.unreachableRetries.worstPeerPerMin = n;
        if (n > UNREACHABLE_PER_MIN) this.later(this.find('unreachableRetries', e.peer, `${n} sends to an unreachable peer within a minute: wait for it to come back instead of retrying`));
        return;
      }
      case 'handshake': {
        const sc = f.sessionChurn;
        sc.handshakes++;
        const ps = this.peer(e.peer, now);
        ps.handshakes = ps.handshakes.filter((t) => now - t < this.rekeyMs);
        ps.handshakes.push(now);
        const n = ps.handshakes.length;
        if (n > sc.perPeerPerIntervalMax) sc.perPeerPerIntervalMax = n;
        if (n > HANDSHAKES_PER_INTERVAL) this.later(this.find('sessionChurn', e.peer, `${n} handshakes with one peer within one rekey interval: keep one member per identity and let sessions live`));
        return;
      }
      case 'reconnect': {
        const sc = f.sessionChurn;
        sc.reconnects++;
        this.reconnects = this.reconnects.filter((t) => now - t < 60_000);
        this.reconnects.push(now);
        const n = this.reconnects.length;
        if (n > sc.reconnectsPerMinMax) sc.reconnectsPerMinMax = n;
        if (n > RECONNECTS_PER_MIN) this.later(this.find('sessionChurn', undefined, `${n} reconnects within a minute`));
        return;
      }
      case 'replaced':
        f.sessionChurn.replaced++;
        this.later(this.find('sessionChurn', undefined, 'replaced by another copy of this identity (4005): run one live member per identity'));
        return;
      case 'usageAsk': {
        const u = f.usageAsks;
        u.count++;
        // A mirror of the relay's budget: USAGE_BURST at once, then one per USAGE_INTERVAL_MS.
        this.usageTat = Math.max(this.usageTat, now) + USAGE_INTERVAL_MS;
        if ((this.usageTat - now) / (USAGE_BURST * USAGE_INTERVAL_MS) >= USAGE_NEAR) {
          u.nearBudget++;
          this.later(this.find('usageAsks', undefined, `usage asked ${u.count} times; this ask used 80% or more of the relay's budget (${USAGE_BURST}, then one per ${USAGE_INTERVAL_MS / 1000} s): ask rarely and keep the answer`));
        }
        return;
      }
      case 'usageRefused':
        f.usageAsks.refused++;
        this.later(this.find('usageAsks', undefined, 'the relay refused a usage ask over its budget'));
        return;
      case 'usage':
        if (e.slowed) this.slowed ??= { since: now, bytes: 0, trickle: e.trickleBps };
        else this.slowed = undefined;
        return;
    }
  }

  /** R5: a `deflate` from the compression entry point. */
  compressed(inBytes: number, outBytes: number): void {
    if (outBytes > inBytes * (1 - MIN_GAIN)) {
      this.r.findings.compressedNoGain.bytes += inBytes;
      this.later(this.find('compressedNoGain', undefined, `deflate saved ${(100 * (1 - outBytes / inBytes)).toFixed(1)}% of ${inBytes} bytes: do not compress media, audio or compressed content`));
    }
  }

  // ── Internals ──

  private peer(id: string, now: number): PeerState {
    let p = this.peers.get(id);
    if (!p) {
      p = { winStart: now, winCount: 0, lastAt: -Infinity, lastSize: Infinity, tinyStart: now, tinyCount: 0, tinyLastPair: -Infinity, unreachable: [], handshakes: [] };
      this.peers.set(id, p);
    }
    return p;
  }

  /** Counts a finding; tells onFinding and warns as the mode says; returns it when it should be thrown. */
  private find(kind: FindingKind, peer: string | undefined, detail: string): Finding | undefined {
    const a = this.accept[kind];
    if (a === false) return undefined;
    const count = ++this.r.counts[kind];
    // Where a kind's own `count` means its findings, it follows; usage asks and unreachable
    // failures count every event, and compressibility counts its samples instead.
    if (kind !== 'usageAsks' && kind !== 'unreachableRetries' && kind !== 'compressibleUncompressed') {
      (this.r.findings[kind] as { count: number }).count = count;
    }
    if (typeof a === 'string') return undefined;
    const finding: Finding = peer === undefined ? { kind, count, detail } : { kind, count, peer, detail };
    if ((count & (count - 1)) === 0) {
      try {
        this.onFinding?.(finding);
      } catch {
        // The application's hook must not break its own send.
      }
    }
    if (this.mode === 'warn' && !this.warned.has(kind)) {
      this.warned.add(kind);
      console.warn(`link diagnostics: ${kind}: ${detail}\n${new Error('call site').stack ?? ''}`);
    }
    return this.mode === 'throw' ? finding : undefined;
  }

  /** A finding made off the send path fails the next send in `throw` mode. */
  private later(f: Finding | undefined): void {
    if (f) this.pending ??= f;
  }

  /** R4: deflates a flagged message off the send path, at most once a second, where CompressionStream exists. */
  private confirm(bytes: Uint8Array, now: number): void {
    if (now - this.lastConfirm < CONFIRM_EVERY_MS || typeof CompressionStream !== 'function') return;
    this.lastConfirm = now;
    const copy = bytes.slice(0, CONFIRM_MAX);
    const c = this.r.findings.compressibleUncompressed;
    const r = this.r;
    void deflatedSize(copy).then(
      (out) => {
        if (this.r !== r) return; // reset meanwhile
        const saving = 1 - out / copy.length;
        c.confirmed++;
        this.savings += saving;
        if (c.confirmedSavings.length < 64) c.confirmedSavings.push(Math.round(saving * 1000) / 1000);
      },
      () => undefined,
    );
  }
}

async function deflatedSize(b: Uint8Array): Promise<number> {
  const cs = new CompressionStream('deflate-raw');
  const w = cs.writable.getWriter();
  w.write(b as Uint8Array<ArrayBuffer>).catch(() => undefined);
  w.close().catch(() => undefined);
  const reader = cs.readable.getReader();
  let n = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return n;
    n += value.length;
  }
}

function structuredCloneReport(r: DiagnosticsReport): DiagnosticsReport {
  return JSON.parse(JSON.stringify(r)) as DiagnosticsReport;
}
