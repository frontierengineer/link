// Drivers (drivers/PROTOCOL.md): one node of any implementation as a child process, steered
// over stdio. Commands are async calls that reject with the driver's error code; events are
// kept in order for `waitFor`; shutting down fails the test if the driver broke the protocol
// or exited non-zero.

import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import type { Roster, RosterMember, Timing, TrafficReport, UsageReport } from '@frontierengineer/link-client';
import { startRelay, type RelayProcess } from './relay.js';

const testDir = join(dirname(fileURLToPath(import.meta.url)), '..');
const root = join(testDir, '..');

export type Impl = 'ts' | 'go' | 'rust';
export const IMPLS: readonly Impl[] = ['ts', 'go', 'rust'];

// ── Finding drivers ──

export type Availability = { ok: true; argv: string[] } | { ok: false; reason: string };

/** Splits a command line on whitespace, honouring single and double quotes. */
export function splitCommand(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let quote: string | undefined;
  let any = false;
  for (const ch of line) {
    if (quote) {
      if (ch === quote) quote = undefined;
      else cur += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
      any = true;
    } else if (/\s/.test(ch)) {
      if (any || cur) out.push(cur);
      cur = '';
      any = false;
    } else cur += ch;
  }
  if (quote) throw new Error(`unterminated quote in ${line}`);
  if (any || cur) out.push(cur);
  return out;
}

/** Runs a build; its stdout, or why it failed. */
function build(what: string, cmd: string, args: string[], cwd: string): { ok: true; stdout: string } | { ok: false; reason: string } {
  try {
    return { ok: true, stdout: execFileSync(cmd, args, { cwd, stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }) };
  } catch (e) {
    const err = e as { stderr?: string; stdout?: string; message: string };
    const out = `${err.stderr ?? ''}`.trim() || `${err.stdout ?? ''}`.trim();
    return { ok: false, reason: `${what} failed: ${out || err.message}` };
  }
}

const found = new Map<Impl, Availability>();

/**
 * How to run a driver of `impl`: its LINK_DRIVER_<IMPL> command line when set, else the
 * default of PROTOCOL.md's "Running a driver", built once per process.
 */
export function driverAvailability(impl: Impl): Availability {
  const known = found.get(impl);
  if (known) return known;
  const a = locate(impl);
  found.set(impl, a);
  return a;
}

function locate(impl: Impl): Availability {
  const given = process.env[`LINK_DRIVER_${impl.toUpperCase()}`];
  if (given) return { ok: true, argv: splitCommand(given) };
  switch (impl) {
    case 'ts':
      return { ok: true, argv: [process.execPath, '--import', 'tsx', join('drivers', 'typescript.ts')] };
    case 'go': {
      const src = join(root, 'client-go');
      if (!existsSync(join(src, 'cmd', 'link-driver'))) return { ok: false, reason: 'client-go/cmd/link-driver does not exist' };
      const dir = mkdtempSync(join(tmpdir(), 'link-driver-go-'));
      process.on('exit', () => rmSync(dir, { recursive: true, force: true }));
      const out = join(dir, process.platform === 'win32' ? 'link-driver.exe' : 'link-driver');
      const b = build('go build ./cmd/link-driver', 'go', ['build', '-o', out, './cmd/link-driver'], src);
      return b.ok ? { ok: true, argv: [out] } : b;
    }
    case 'rust': {
      const src = join(root, 'client-rust');
      if (!existsSync(src)) return { ok: false, reason: 'client-rust does not exist' };
      const b = build('cargo build --release --bin link-driver', 'cargo', ['build', '--release', '--bin', 'link-driver', '--message-format=json'], src);
      if (!b.ok) return b;
      // Where cargo put the binary (CARGO_TARGET_DIR, a workspace): its compiler-artifact message says.
      let bin: string | undefined;
      for (const line of b.stdout.split('\n')) {
        try {
          const m = JSON.parse(line) as { reason?: string; target?: { name?: string }; executable?: string | null };
          if (m.reason === 'compiler-artifact' && m.target?.name === 'link-driver' && m.executable) bin = m.executable;
        } catch {
          // not a JSON message
        }
      }
      return bin ? { ok: true, argv: [bin] } : { ok: false, reason: 'cargo built no link-driver executable' };
    }
  }
}

function implList(variable: string): Impl[] | undefined {
  const given = process.env[variable];
  if (given === undefined) return undefined;
  const names = given
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  for (const n of names) if (!IMPLS.includes(n as Impl)) throw new Error(`${variable} names ${n}; known: ${IMPLS.join(', ')}`);
  return names as Impl[];
}

/** The implementations LINK_REQUIRE_DRIVERS names: each must be available, or the suite fails. */
export function requiredDrivers(): Impl[] {
  return implList('LINK_REQUIRE_DRIVERS') ?? [];
}

/** The implementations LINK_DRIVERS names (all of them when unset): the others do not run. */
export function selectedDrivers(): Impl[] {
  const selected = implList('LINK_DRIVERS') ?? [...IMPLS];
  for (const r of requiredDrivers()) if (!selected.includes(r)) throw new Error(`LINK_REQUIRE_DRIVERS names ${r}, which LINK_DRIVERS leaves out`);
  return selected;
}

// ── The protocol's types ──

export type NodeState = 'connecting' | 'connected' | 'disconnected' | 'revoked' | 'replaced' | 'closed';

export interface MessageEvent {
  event: 'message';
  from: string;
  size: number;
  sha256: string;
  bytes?: string;
}

export type DriverEvent =
  | { event: 'state'; state: NodeState }
  | { event: 'roster'; roster: Roster }
  | { event: 'disconnect'; code: number; reason: string }
  | MessageEvent
  | { event: 'moved'; network: string }
  | { event: 'paired'; node: string; codeId: string; version: number }
  | { event: 'pairingFailed'; codeId: string; reason: string }
  | { event: 'relayError'; code: string; message: string }
  | { event: 'shaping'; rateBps: number; slowed: boolean };

export type EventName = DriverEvent['event'];
export type EventOf<K extends EventName> = Extract<DriverEvent, { event: K }>;

export interface ConnectOptions {
  role: 'member' | 'primary';
  roster: Roster;
  /** Base64: the network seed, for a node to be the primary (spec section 3.1). */
  networkSeed?: string;
  pinnedNetworkKey?: string;
  relayUrl?: string;
  creditWindow?: number;
  timing?: Partial<Timing>;
  autoTake?: boolean;
  /** `connect` only. */
  timeoutMs?: number;
}

export interface SessionInfo {
  peer: string;
  localIndex: number;
  remoteIndex: number;
  initiator: boolean;
  current: boolean;
}

export interface PairArgs {
  link?: string;
  network?: string;
  code?: string;
  /** None for the default code. */
  codeId?: string;
  relay?: string;
  timeoutMs?: number;
}

export interface PairingCodeResult {
  code: string;
  codeId: string;
  link: string;
  expiresAt: number;
}

/** A command the driver answered `ok: false`; `code` is the client's error code. */
export class DriverError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly cmd: string,
    /** For `refused`: the refusal's reason byte. */
    readonly reason?: number,
  ) {
    super(`${cmd}: ${code}: ${message}`);
    this.name = 'DriverError';
  }
}

/** `size` bytes where byte i is (fill + i * 31) mod 256, as the drivers generate them. */
export function generated(size: number, fill: number): Uint8Array {
  const b = new Uint8Array(size);
  for (let i = 0; i < size; i++) b[i] = (fill + i * 31) & 0xff;
  return b;
}

export const sha256hex = (b: Uint8Array) => createHash('sha256').update(b).digest('hex');
export const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');
export const textB64 = (s: string) => b64(new TextEncoder().encode(s));
export const textOf = (m: MessageEvent) => (m.bytes === undefined ? undefined : Buffer.from(m.bytes, 'base64').toString('utf8'));

/** The node id of an Ed25519 public key (base64url, or base64): b32(SHA-256(key)[0..16]). */
export function nodeIdOf(ed25519: string): string {
  const pub = Buffer.from(ed25519, 'base64');
  if (pub.length !== 32) throw new Error(`ed25519 ${ed25519} is not 32 bytes`);
  const h = createHash('sha256').update(pub).digest().subarray(0, 16);
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  let out = '';
  let bits = 0;
  let acc = 0;
  for (const byte of h) {
    acc = ((acc << 8) | byte) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(acc >> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += alphabet[(acc << (5 - bits)) & 31];
  return out;
}

const COMMAND_TIMEOUT_MS = 60_000;

// ── One driver ──

export class Driver {
  /** Every event so far, in order. */
  readonly events: DriverEvent[] = [];
  /** When each of `events` arrived (Date.now()), at the same index. */
  readonly eventTimes: number[] = [];
  /** What the driver wrote to stderr. */
  readonly stderr: string[] = [];
  /** stdout lines outside the protocol; any fails the test at shutdown. */
  readonly violations: string[] = [];
  /** Set by `identity`. */
  id = '';
  seed = '';
  ed25519 = '';
  x25519 = '';
  private readonly child: ChildProcess;
  private nextId = 1;
  private readonly pending = new Map<number, { cmd: string; resolve: (v: Record<string, unknown>) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> }>();
  private readonly waiters = new Set<() => void>();
  /** Commands the harness gave up on: a late reply to one is not a protocol violation. */
  private readonly abandoned = new Set<number>();
  private exitCode: number | null | undefined;
  private exitSignal: NodeJS.Signals | null = null;
  private readonly exited: Promise<void>;
  private stopping = false;

  constructor(
    readonly impl: Impl,
    readonly label: string,
    argv: string[],
  ) {
    const [cmd, ...args] = argv;
    this.child = spawn(cmd!, args, { cwd: testDir, stdio: ['pipe', 'pipe', 'pipe'] });
    const reap = () => this.child.kill('SIGKILL');
    process.on('exit', reap);
    this.exited = new Promise((resolve) => {
      this.child.on('exit', (code, signal) => {
        process.off('exit', reap);
        this.exitCode = code;
        this.exitSignal = signal;
        const why = new DriverError('exited', `the driver exited (${code ?? signal}) with the command outstanding`, 'driver');
        for (const p of this.pending.values()) {
          clearTimeout(p.timer);
          p.reject(why);
        }
        this.pending.clear();
        this.wake();
        resolve();
      });
      this.child.on('error', (e) => {
        this.stderr.push(`[harness] could not run ${argv.join(' ')}: ${e.message}\n`);
        if (this.exitCode === undefined) {
          this.exitCode = -1;
          for (const p of this.pending.values()) p.reject(e);
          this.pending.clear();
          this.wake();
          resolve();
        }
      });
    });
    this.child.stdin!.on('error', () => undefined);
    this.child.stderr!.setEncoding('utf8');
    this.child.stderr!.on('data', (c: string) => this.stderr.push(c));
    createInterface({ input: this.child.stdout!, crlfDelay: Infinity }).on('line', (l) => this.onLine(l));
  }

  private onLine(line: string): void {
    let msg: Record<string, unknown>;
    try {
      msg = JSON.parse(line) as Record<string, unknown>;
      if (typeof msg !== 'object' || msg === null || Array.isArray(msg)) throw new Error('not an object');
    } catch {
      this.violations.push(line);
      return;
    }
    if (typeof msg.event === 'string') {
      this.events.push(msg as unknown as DriverEvent);
      this.eventTimes.push(Date.now());
      this.wake();
      return;
    }
    if (typeof msg.id === 'number' && this.abandoned.delete(msg.id)) return;
    const p = typeof msg.id === 'number' ? this.pending.get(msg.id) : undefined;
    if (!p || typeof msg.ok !== 'boolean') {
      this.violations.push(line);
      return;
    }
    this.pending.delete(msg.id as number);
    clearTimeout(p.timer);
    if (msg.ok) {
      const { id: _id, ok: _ok, ...result } = msg;
      p.resolve(result);
    } else {
      const err = msg.error as { code?: unknown; message?: unknown; reason?: unknown } | undefined;
      if (typeof err?.code !== 'string' || typeof err.message !== 'string') this.violations.push(line);
      if (err?.code === 'refused' && typeof err.reason !== 'number') this.violations.push(line);
      p.reject(new DriverError(String(err?.code), String(err?.message ?? ''), p.cmd, typeof err?.reason === 'number' ? err.reason : undefined));
    }
  }

  private wake(): void {
    for (const w of [...this.waiters]) w();
  }

  /** Sends one command; resolves with its result, rejects with a DriverError. */
  call<T = Record<string, unknown>>(cmd: string, args: Record<string, unknown> = {}, timeoutMs = COMMAND_TIMEOUT_MS): Promise<T> {
    if (this.exitCode !== undefined) return Promise.reject(new DriverError('exited', `the driver has exited (${this.exitCode ?? this.exitSignal})`, cmd));
    const id = this.nextId++;
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        this.abandoned.add(id);
        reject(new DriverError('harness-timeout', `no reply in ${timeoutMs} ms`, cmd));
      }, timeoutMs);
      this.pending.set(id, { cmd, resolve: resolve as (v: Record<string, unknown>) => void, reject, timer });
      this.child.stdin!.write(`${JSON.stringify({ ...args, id, cmd })}\n`);
    });
  }

  /** Index of the next event: pass it as `since` to wait only for what comes after now. */
  mark(): number {
    return this.events.length;
  }

  /** Events named `name` from `since` on. */
  seen<K extends EventName>(name: K, since = 0): EventOf<K>[] {
    return this.events.slice(since).filter((e): e is EventOf<K> => e.event === name);
  }

  /**
   * The first event named `name` at or after index `since` (default: from the start) that
   * satisfies `predicate`, waiting up to `timeoutMs` for it.
   */
  waitFor<K extends EventName>(name: K, predicate: (e: EventOf<K>) => boolean = () => true, timeoutMs = 10_000, since = 0): Promise<EventOf<K>> {
    return new Promise((resolve, reject) => {
      let scanned = since;
      const check = (): boolean => {
        for (; scanned < this.events.length; scanned++) {
          const e = this.events[scanned]!;
          if (e.event === name && predicate(e as EventOf<K>)) {
            done();
            resolve(e as EventOf<K>);
            return true;
          }
        }
        if (this.exitCode !== undefined) {
          done();
          reject(new Error(`${this.label}: the driver exited while waiting for ${name}`));
          return true;
        }
        return false;
      };
      const timer = setTimeout(() => {
        done();
        reject(new Error(`${this.label}: timed out after ${timeoutMs} ms waiting for a ${name} event`));
      }, timeoutMs);
      const done = () => {
        clearTimeout(timer);
        this.waiters.delete(waiter);
      };
      const waiter = () => void check();
      this.waiters.add(waiter);
      check();
    });
  }

  /** The next `n` message events from `from` (any sender when absent) at or after `since`. */
  async messages(n: number, opts: { from?: string; since?: number; timeoutMs?: number } = {}): Promise<MessageEvent[]> {
    const deadline = Date.now() + (opts.timeoutMs ?? 10_000);
    const pick = () => this.seen('message', opts.since).filter((m) => opts.from === undefined || m.from === opts.from);
    while (pick().length < n) {
      const left = deadline - Date.now();
      if (left <= 0) throw new Error(`${this.label}: ${pick().length} of ${n} messages arrived`);
      const count = pick().length;
      await this.waitFor('message', () => pick().length > count, left, opts.since).catch(() => undefined);
    }
    return pick().slice(0, n);
  }

  // ── Commands ──

  /**
   * Sets the node's identity. The node id the driver reports is checked against the one its
   * `ed25519` key derives, so a driver cannot get either wrong unnoticed.
   */
  async identity(seed?: string): Promise<{ seed: string; node: string; ed25519: string; x25519: string }> {
    const r = await this.call<{ seed: string; node: string; ed25519: string; x25519: string }>('identity', seed === undefined ? {} : { seed });
    const derived = nodeIdOf(r.ed25519);
    if (r.node !== derived) throw new Error(`${this.label}: identity gave node ${r.node}, but its ed25519 key ${r.ed25519} is node ${derived}`);
    if (/[+/=]/.test(r.ed25519)) throw new Error(`${this.label}: ed25519 ${r.ed25519} is not unpadded base64url`);
    this.id = r.node;
    this.seed = r.seed;
    this.ed25519 = r.ed25519;
    if (!/^[A-Za-z0-9_-]{43}$/.test(r.x25519)) throw new Error(`${this.label}: x25519 ${r.x25519} is not 32 bytes of unpadded base64url`);
    this.x25519 = r.x25519;
    return r;
  }
  /** This node's roster member entry. */
  get member(): RosterMember {
    return { id: this.id, ed25519: this.ed25519, x25519: this.x25519 };
  }
  /** `relay` absent: a network not placed yet (spec section 3.2). `members` are listed beside this node. */
  createNetwork(relay?: string, members?: RosterMember[]): Promise<{ roster: Roster; networkSeed: string; placed: boolean }> {
    return this.call('createNetwork', { ...(relay !== undefined ? { relay } : {}), ...(members !== undefined ? { members } : {}) });
  }
  placeNetwork(args: { roster: Roster; networkSeed: string; relay: string; now?: number }): Promise<{ roster: Roster; placed: boolean }> {
    return this.call('placeNetwork', { ...args });
  }
  pair(args: PairArgs): Promise<{ roster: Roster; pinnedNetworkKey: string }> {
    return this.call('pair', { ...args });
  }
  async connect(opts: ConnectOptions): Promise<void> {
    await this.call('connect', { ...opts });
  }
  async start(opts: Omit<ConnectOptions, 'timeoutMs'>): Promise<void> {
    await this.call('start', { ...opts });
  }
  async waitConnected(timeoutMs?: number): Promise<void> {
    await this.call('waitConnected', timeoutMs === undefined ? {} : { timeoutMs });
  }
  state(): Promise<{ state: NodeState; roster: Roster; primary: boolean; shaping: { rateBps: number; slowed: boolean } }> {
    return this.call('state');
  }
  async send(peer: string, payload: { bytes: string } | { size: number; fill: number }, timeoutMs?: number): Promise<void> {
    await this.call('send', { peer, ...payload }, timeoutMs);
  }
  /** `timeoutMs` is the driver's (`take` fails `timeout`); the harness waits a little longer. */
  async take(count = 1, timeoutMs?: number): Promise<Omit<MessageEvent, 'event'>[]> {
    const args = timeoutMs === undefined ? { count } : { count, timeoutMs };
    return (await this.call<{ messages: Omit<MessageEvent, 'event'>[] }>('take', args, timeoutMs === undefined ? undefined : timeoutMs + 10_000)).messages;
  }
  async sessions(peer?: string): Promise<SessionInfo[]> {
    return (await this.call<{ sessions: SessionInfo[] }>('sessions', peer === undefined ? {} : { peer })).sessions;
  }
  async syncRoster(): Promise<Roster> {
    return (await this.call<{ roster: Roster }>('syncRoster')).roster;
  }
  async resign(): Promise<void> {
    await this.call('resign');
  }
  traffic(): Promise<TrafficReport> {
    return this.call('traffic');
  }
  async resetTraffic(): Promise<void> {
    await this.call('resetTraffic');
  }
  /** Without `separate`, the default code, which closes the default code open before it. */
  openPairingCode(opts: { lifetimeMs?: number; code?: string; separate?: boolean } = {}): Promise<PairingCodeResult> {
    return this.call('openPairingCode', { ...opts });
  }
  /** No `codeId`: the default code. */
  async cancelPairingCode(codeId?: string): Promise<void> {
    await this.call('cancelPairingCode', codeId === undefined ? {} : { codeId });
  }
  async revoke(node: string): Promise<Roster> {
    return (await this.call<{ roster: Roster }>('revoke', { node })).roster;
  }
  usage(): Promise<UsageReport> {
    return this.call('usage');
  }
  async close(): Promise<void> {
    await this.call('close');
  }

  /** The process's exit, once it has ended. */
  get exit(): { code: number | null | undefined; signal: NodeJS.Signals | null } {
    return { code: this.exitCode, signal: this.exitSignal };
  }

  /**
   * Ends the driver: `exit`, then waits for the process. Throws when the driver wrote
   * anything to stdout outside the protocol, or did not exit 0.
   */
  async shutdown(timeoutMs = 10_000): Promise<void> {
    if (!this.stopping) {
      this.stopping = true;
      if (this.exitCode === undefined) {
        await this.call('exit', {}, timeoutMs).catch(() => undefined);
        this.child.stdin!.end();
        const killer = setTimeout(() => this.child.kill('SIGKILL'), timeoutMs);
        await this.exited;
        clearTimeout(killer);
      }
    }
    await this.exited;
    const problems: string[] = [];
    if (this.violations.length > 0) problems.push(`wrote ${this.violations.length} line(s) to stdout outside the protocol:\n  ${this.violations.slice(0, 5).join('\n  ')}`);
    if (this.exitCode !== 0) problems.push(`exited ${this.exitCode ?? this.exitSignal}, not 0`);
    if (problems.length > 0) throw new Error(`${this.label}: ${problems.join('; ')}`);
  }

  /** Kills the process at once, as a crash would. */
  kill(): void {
    this.stopping = true;
    this.child.kill('SIGKILL');
  }
}

// ── Scenes: a relay and the drivers of one test ──

/** Fast reconnects and short request timeouts, as the in-process tests use. */
export const FAST: Partial<Timing> = { backoffInitialMs: 20, backoffMaxMs: 200, requestTimeoutMs: 2000 };

/** One node: a driver with its identity, and the roster it was paired or created with. */
export interface Node {
  d: Driver;
  impl: Impl;
  id: string;
  seed: string;
  roster: Roster;
  pinnedNetworkKey: string;
  /** Base64, for the primary: the network seed the test keeps, as an application would. */
  networkSeed?: string;
}

export interface Scene {
  relay: RelayProcess;
  /** Starts a driver; `seed` gives it that identity, else a random one. */
  spawn(impl: Impl, label: string, seed?: string): Promise<Driver>;
  /** Starts a driver and sends it nothing. */
  bare(impl: Impl, label: string): Driver;
  /** Creates a network with a primary of `impl` and connects it. */
  primary(impl: Impl, opts?: Partial<ConnectOptions>): Promise<Node>;
  /** Pairs a new node of `impl` through the primary, without connecting it. */
  pairOnly(impl: Impl, label: string): Promise<Node>;
  /** Pairs a new node and connects it as a member, and waits for the others to learn of it. */
  add(impl: Impl, label: string, opts?: Partial<ConnectOptions>): Promise<Node>;
  /** Connects a node as a member with its roster (or the one given in `opts`). */
  join(node: Node, opts?: Partial<ConnectOptions>): Promise<void>;
  /** Nodes connected through the scene, the primary first. */
  nodes: Node[];
}

export interface SceneOptions {
  /** LINK_* settings for the relay. */
  env?: Record<string, string>;
  /** Timing for every node the scene connects (FAST when absent). */
  timing?: Partial<Timing>;
}

/**
 * Runs `body` with a fresh relay. Afterwards every driver is shut down and the relay stopped;
 * a driver that broke the protocol or exited non-zero fails the test. When anything fails,
 * every driver's stderr and the relay's log are printed.
 */
export async function scene(opts: SceneOptions, body: (s: Scene) => Promise<void>): Promise<void> {
  const relay = await startRelay(opts.env);
  const drivers: Driver[] = [];
  const timing = opts.timing ?? FAST;
  let primary: Node | undefined;
  const s: Scene = {
    relay,
    nodes: [],
    async spawn(impl, label, seed) {
      const d = s.bare(impl, label);
      await d.identity(seed);
      return d;
    },
    bare(impl, label) {
      const a = driverAvailability(impl);
      if (!a.ok) throw new Error(`no ${impl} driver: ${a.reason}`);
      const d = new Driver(impl, `${label} (${impl})`, a.argv);
      drivers.push(d);
      return d;
    },
    async primary(impl, more = {}) {
      const d = await s.spawn(impl, 'primary');
      const { roster, networkSeed } = await d.createNetwork(relay.url);
      await d.connect({ role: 'primary', roster, networkSeed, timing, ...more });
      primary = { d, impl, id: d.id, seed: d.seed, roster, pinnedNetworkKey: roster.networkKey, networkSeed };
      s.nodes.push(primary);
      return primary;
    },
    async pairOnly(impl, label) {
      if (!primary) throw new Error('no primary yet');
      const d = await s.spawn(impl, label);
      const code = await primary.d.openPairingCode();
      const { roster, pinnedNetworkKey } = await d.pair({ link: code.link });
      return { d, impl, id: d.id, seed: d.seed, roster, pinnedNetworkKey };
    },
    async add(impl, label, more = {}) {
      const n = await s.pairOnly(impl, label);
      const others = s.nodes.filter((o) => o.d.exit.code === undefined);
      await s.join(n, more);
      // The primary pushes the new roster over the others' sessions, which takes a moment: until
      // it lands they do not know the newcomer and would refuse to send to it.
      await Promise.all(others.map((o) => rosterAtLeast(o.d, n.roster.version)));
      return n;
    },
    async join(n, more = {}) {
      await n.d.connect({ role: 'member', roster: n.roster, pinnedNetworkKey: n.pinnedNetworkKey, timing, ...more });
      s.nodes.push(n);
    },
  };
  let failure: unknown;
  try {
    await body(s);
  } catch (e) {
    failure = e;
  }
  const problems: string[] = [];
  await Promise.all(
    drivers.map((d) =>
      d.shutdown().catch((e: Error) => {
        problems.push(e.message);
      }),
    ),
  );
  const code = await relay.stop();
  if (code !== 0) problems.push(`the relay exited ${code}`);
  if (failure !== undefined || problems.length > 0) {
    const parts = drivers.map((d) => `── ${d.label} stderr ──\n${d.stderr.join('') || '(empty)\n'}`);
    parts.push(`── relay log ──\n${relay.log.join('') || '(empty)\n'}`);
    process.stderr.write(`${parts.join('')}\n`);
  }
  if (failure !== undefined) throw failure;
  if (problems.length > 0) throw new Error(problems.join('\n'));
}

/** Waits until `d`, if it is connected, holds a roster of `version` or newer. */
export async function rosterAtLeast(d: Driver, version: number, timeoutMs = 10_000): Promise<void> {
  await until(
    async () => {
      const st = await d.state().catch(() => undefined);
      return st === undefined || st.state !== 'connected' || st.roster.version >= version;
    },
    `${d.label} to hold roster v${version}`,
    timeoutMs,
  );
}

export async function until(cond: () => boolean | Promise<boolean>, what: string, timeoutMs = 10_000, everyMs = 20): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!(await cond())) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await sleep(everyMs);
  }
}

export const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
