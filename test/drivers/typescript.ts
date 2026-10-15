// The TypeScript client's driver: one node of a Link network, steered over stdin and stdout
// as drivers/PROTOCOL.md describes. It is the reference driver: the Go and Rust drivers
// behave as this one does.
//
//   node --import tsx drivers/typescript.ts      (from test/)

import { createHash } from 'node:crypto';
import { createInterface } from 'node:readline';
import {
  createIdentity,
  createNetwork,
  identityFromSeed,
  LinkError,
  Member,
  RefusedError,
  pair,
  Primary,
  type Identity,
  type InboundMessage,
  type MemberOptions,
  type PairingKind,
  type Roster,
  type Timing,
} from '@frontierengineer/link-client';

// Nothing but the protocol goes to stdout, whatever a library logs.
console.log = console.info = console.debug = console.error;

type Json = Record<string, unknown>;

/** A failure the driver reports with a code of its own choosing. */
class DriverFailure extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

const invalid = (message: string) => new DriverFailure('invalid', message);

function write(obj: Json): void {
  process.stdout.write(`${JSON.stringify(obj)}\n`);
}

function event(name: string, body: Json): void {
  write({ event: name, ...body });
}

// ── Arguments ──

function str(args: Json, key: string): string {
  const v = args[key];
  if (typeof v !== 'string') throw invalid(`${key} must be a string`);
  return v;
}

function optStr(args: Json, key: string): string | undefined {
  return args[key] === undefined ? undefined : str(args, key);
}

function optInt(args: Json, key: string): number | undefined {
  const v = args[key];
  if (v === undefined) return undefined;
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 0) throw invalid(`${key} must be a non-negative integer`);
  return v;
}

function base64(args: Json, key: string): Uint8Array {
  const s = str(args, key);
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4 !== 0) throw invalid(`${key} must be standard base64`);
  return new Uint8Array(Buffer.from(s, 'base64'));
}

const TIMING_KEYS = [
  'handshakeTimeoutMs',
  'rekeyIntervalMs',
  'rekeyMessages',
  'retireGraceMs',
  'idleMs',
  'backoffInitialMs',
  'backoffMaxMs',
  'requestTimeoutMs',
] as const;

function timingOf(v: unknown): Partial<Timing> | undefined {
  if (v === undefined) return undefined;
  if (typeof v !== 'object' || v === null) throw invalid('timing must be an object');
  const t: Partial<Timing> = {};
  for (const k of TIMING_KEYS) {
    const n = optInt(v as Json, k);
    if (n !== undefined) t[k] = n;
  }
  return t;
}

/** `size` bytes where byte i is (fill + i * 31) mod 256. */
export function generated(size: number, fill: number): Uint8Array {
  const b = new Uint8Array(size);
  for (let i = 0; i < size; i++) b[i] = (fill + i * 31) & 0xff;
  return b;
}

const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');

function messageBody(m: InboundMessage): Json {
  const body: Json = { from: m.from, size: m.bytes.length, sha256: createHash('sha256').update(m.bytes).digest('hex') };
  if (m.bytes.length <= 65536) body.bytes = b64(m.bytes);
  return body;
}

// ── The node ──

/** The key the client's diagnostics hook is installed under (see the client's diag-hook.ts). */
const DIAGNOSTICS = Symbol.for('@frontierengineer/link-client/diagnostics');

let identity: Identity | undefined;
let node: Member | Primary | undefined;
let autoTake = true;
/** Without autoTake: messages arrived and taken, and the takes waiting for more. */
let arrived = 0;
let taken = 0;
let wakeTakes: (() => void)[] = [];
/** Takes run one after another, so two never count the same waiting messages. */
let takeChain: Promise<unknown> = Promise.resolve();

function wake(): void {
  for (const w of wakeTakes.splice(0)) w();
}

/** The `pairingFailed` reason code for each of the client's reason texts. */
const PAIRING_FAILED: [RegExp, string][] = [
  [/^wrong code$/, 'wrong-code'],
  [/^malformed pairing message/, 'malformed'],
  [/^unknown or expired code$/, 'unknown-code'],
  [/^code already used$/, 'used'],
  [/^no attempts left$/, 'no-attempts'],
  [/^too many attempts at once/, 'no-attempts'],
  [/^the newcomer left$/, 'newcomer-left'],
  [/^pairing timed out$/, 'timeout'],
  [/^the relay connection dropped$/, 'relay-lost'],
  [/ is already a member$/, 'already-member'],
  [/^the roster would be \d+ bytes/, 'roster-full'],
];

function pairingFailedReason(text: string): string {
  const hit = PAIRING_FAILED.find(([re]) => re.test(text));
  if (hit) return hit[1];
  console.error(`driver: no reason code for pairing failure "${text}"`);
  return 'internal';
}

function needIdentity(): Identity {
  if (!identity) throw invalid('no identity: send `identity` first');
  return identity;
}

function needNode(): Member | Primary {
  if (!node) throw invalid('no node: send `connect` or `start` first');
  return node;
}

function needPrimary(): Primary {
  const n = needNode();
  if (!(n instanceof Primary)) throw invalid('only the primary can do this');
  return n;
}

function open(args: Json): Member | Primary {
  const id = needIdentity();
  if (node && node.state !== 'closed') throw invalid('a node is already running: `close` it first');
  const role = str(args, 'role');
  if (role !== 'member' && role !== 'primary') throw invalid('role must be member or primary');
  const roster = args.roster as Roster;
  if (typeof roster !== 'object' || roster === null) throw invalid('roster must be an object');
  if (role === 'primary' && roster.network !== id.id) throw invalid('this identity is not the network primary');
  const opts: MemberOptions = { identity: id, roster };
  const pinnedPrimary = optStr(args, 'pinnedPrimary');
  if (pinnedPrimary !== undefined) opts.pinnedPrimary = pinnedPrimary;
  const relayUrl = optStr(args, 'relayUrl');
  if (relayUrl !== undefined) opts.relayUrl = relayUrl;
  const creditWindow = optInt(args, 'creditWindow');
  if (creditWindow !== undefined) opts.creditWindow = creditWindow;
  const timing = timingOf(args.timing);
  if (timing) opts.timing = timing;
  if (args.autoTake !== undefined && typeof args.autoTake !== 'boolean') throw invalid('autoTake must be a boolean');
  autoTake = args.autoTake !== false;
  arrived = 0;
  taken = 0;

  const n = role === 'primary' ? new Primary(opts) : new Member(opts);
  n.on('state', (state) => {
    event('state', { state });
    wake();
  });
  n.on('roster', (r) => event('roster', { roster: r }));
  n.on('disconnect', (d) => event('disconnect', { code: d.code, reason: d.reason }));
  n.on('moved', (m) => event('moved', { network: m.network }));
  n.on('relayError', (e) => event('relayError', { code: e.code, message: e.message ?? '' }));
  if (n instanceof Primary) {
    n.on('paired', (p) => event('paired', { node: p.member.id, kind: p.member.kind, version: p.roster.version }));
    n.on('pairingFailed', (f) => event('pairingFailed', { codeId: f.codeId, reason: pairingFailedReason(f.reason) }));
  }
  // A message is announced as it arrives, before anything takes it: the client tells its
  // diagnostics hook of every message it delivers, so a minimal hook is the arrival seam.
  (n as unknown as Record<symbol, (hook: unknown) => void>)[DIAGNOSTICS]!({
    send() {},
    sent() {},
    received(from: string, bytes: Uint8Array) {
      event('message', messageBody({ from, bytes }));
      arrived++;
      wake();
    },
    event() {},
    report() {
      throw new Error('the driver keeps no diagnostics');
    },
    reset() {},
  });
  // With autoTake, taking at once is what credits each message back to its sender.
  if (autoTake) n.onMessage(() => undefined);
  node = n;
  return n;
}

// ── Commands ──

const commands: Record<string, (args: Json) => Promise<Json> | Json> = {
  identity(args) {
    identity = args.seed === undefined ? createIdentity() : identityFromSeed(base64(args, 'seed'));
    return { seed: b64(identity.seed), node: identity.id, ed25519: Buffer.from(identity.ed25519.pub).toString('base64url') };
  },

  createNetwork(args) {
    return { roster: createNetwork({ identity: needIdentity(), relay: str(args, 'relay') }) };
  },

  async pair(args) {
    const id = needIdentity();
    const link =
      args.link !== undefined
        ? str(args, 'link')
        : { network: str(args, 'network'), code: str(args, 'code'), codeId: str(args, 'codeId'), relay: str(args, 'relay') };
    const timeoutMs = optInt(args, 'timeoutMs');
    const r = await pair({ link, identity: id, ...(timeoutMs !== undefined ? { timeoutMs } : {}) });
    return { roster: r.roster, pinnedPrimary: r.pinnedPrimary };
  },

  async connect(args) {
    const timeoutMs = optInt(args, 'timeoutMs');
    await open(args).waitConnected(timeoutMs);
    return {};
  },

  start(args) {
    open(args);
    return {};
  },

  async waitConnected(args) {
    await needNode().waitConnected(optInt(args, 'timeoutMs'));
    return {};
  },

  state() {
    const n = needNode();
    return { state: n.state, roster: n.roster };
  },

  async send(args) {
    const n = needNode();
    const peer = str(args, 'peer');
    let bytes: Uint8Array;
    if (args.bytes !== undefined) bytes = base64(args, 'bytes');
    else {
      const size = optInt(args, 'size');
      const fill = optInt(args, 'fill');
      if (size === undefined || fill === undefined) throw invalid('send needs bytes, or size and fill');
      bytes = generated(size, fill);
    }
    await n.send(peer, bytes);
    return {};
  },

  take(args) {
    const n = needNode();
    if (autoTake) throw invalid('take needs autoTake: false');
    const count = optInt(args, 'count') ?? 1;
    const timeoutMs = optInt(args, 'timeoutMs');
    const run = takeChain.then(() => takeWhenWaiting(n, count, timeoutMs));
    takeChain = run.catch(() => undefined);
    return run;
  },

  sessions(args) {
    const n = needNode();
    const only = optStr(args, 'peer');
    // The client keeps its sessions private; the driver reads them for the harness.
    const mgr = (n as unknown as { sessions: SessionsView }).sessions;
    const peers = only !== undefined ? [only] : [...mgr.peers.keys()];
    return {
      sessions: peers.flatMap((peer) =>
        mgr.sessionInfo(peer).map((x) => ({ peer, localIndex: x.localIndex, remoteIndex: x.remoteIndex, initiator: x.initiator, current: x.current })),
      ),
    };
  },

  async syncRoster() {
    const n = needNode();
    await n.syncRoster();
    return { roster: n.roster };
  },

  async resign() {
    await needNode().resign();
    return {};
  },

  traffic() {
    return { ...needNode().traffic() };
  },

  resetTraffic() {
    needNode().resetTraffic();
    return {};
  },

  openPairingCode(args) {
    const kind = str(args, 'kind') as PairingKind;
    const lifetimeMs = optInt(args, 'lifetimeMs');
    const code = optStr(args, 'code');
    return {
      ...needPrimary().openPairingCode(kind, {
        ...(lifetimeMs !== undefined ? { lifetimeMs } : {}),
        ...(code !== undefined ? { code } : {}),
      }),
    };
  },

  cancelPairingCode(args) {
    needPrimary().cancelPairingCode(str(args, 'codeId'));
    return {};
  },

  revoke(args) {
    return { roster: needPrimary().revoke(str(args, 'node')) };
  },

  async usage() {
    return { ...(await needPrimary().usage()) };
  },

  close() {
    node?.close();
    return {};
  },

  exit() {
    return {};
  },
};

interface SessionsView {
  peers: Map<string, unknown>;
  sessionInfo(peer: string): { localIndex: number; remoteIndex: number; initiator: boolean; current: boolean }[];
}

const TERMINAL = new Set(['revoked', 'replaced', 'closed']);

/** Waits until `count` messages are waiting, then takes them; on a timeout takes none. */
async function takeWhenWaiting(n: Member | Primary, count: number, timeoutMs: number | undefined): Promise<Json> {
  const deadline = timeoutMs === undefined ? undefined : Date.now() + timeoutMs;
  while (arrived - taken < count) {
    if (TERMINAL.has(n.state)) throw new LinkError(n.state as 'revoked' | 'replaced' | 'closed', `the node is ${n.state}`);
    const left = deadline === undefined ? undefined : deadline - Date.now();
    if (left !== undefined && left <= 0) throw new LinkError('timeout', `${arrived - taken} of ${count} messages waiting after ${timeoutMs} ms`);
    await new Promise<void>((resolve) => {
      const timer = left === undefined ? undefined : setTimeout(resolve, left);
      wakeTakes.push(() => {
        clearTimeout(timer);
        resolve();
      });
    });
  }
  const it = n.messages;
  const messages: Json[] = [];
  for (let i = 0; i < count; i++) {
    const r = await it.next();
    if (r.done) throw new LinkError('closed', 'the node ended while taking');
    taken++;
    messages.push(messageBody(r.value));
  }
  return { messages };
}

function errorOf(e: unknown): { code: string; message: string; reason?: number } {
  if (e instanceof RefusedError) return { code: e.code, message: e.message, reason: e.reason };
  if (e instanceof LinkError || e instanceof DriverFailure) return { code: e.code, message: e.message };
  return { code: 'internal', message: e instanceof Error ? e.message : String(e) };
}

async function run(line: string): Promise<void> {
  let msg: Json;
  try {
    msg = JSON.parse(line) as Json;
  } catch {
    console.error(`driver: not JSON: ${line}`);
    return;
  }
  const id = msg.id;
  if (typeof msg !== 'object' || msg === null || typeof id !== 'number' || typeof msg.cmd !== 'string') {
    console.error(`driver: not a command: ${line}`);
    return;
  }
  const handler = Object.hasOwn(commands, msg.cmd) ? commands[msg.cmd] : undefined;
  try {
    if (!handler) throw new DriverFailure('internal', `unknown command ${msg.cmd}`);
    // No result field is named `id`; written last all the same, the command's id always wins.
    write({ ...(await handler(msg)), id, ok: true });
  } catch (e) {
    write({ id, ok: false, error: errorOf(e) });
  }
  if (msg.cmd === 'exit') shutdown();
}

let ending = false;
function shutdown(): void {
  if (ending) return;
  ending = true;
  node?.close();
  // stdout is a pipe: let it drain before the process ends.
  process.stdout.write('', () => process.exit(0));
}

process.on('uncaughtException', (e) => {
  console.error('driver: uncaught', e);
  process.exit(1);
});

const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
// Each command runs on its own: a slow one never holds up the next.
lines.on('line', (line) => {
  if (line.trim() !== '') void run(line);
});
lines.on('close', shutdown);
