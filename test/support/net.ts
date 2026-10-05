// Networks of real clients on a real relay: a primary, then members paired through the
// full section 5 exchange. Plus a raw WebSocket for what the client library never sends.

import {
  createIdentity,
  createNetwork,
  Member,
  pair,
  Primary,
  type Identity,
  type InboundMessage,
  type MemberOptions,
  type PairingKind,
  type Timing,
} from '@frontierengineer/link-client';
import { startRelay, type RelayProcess } from './relay.js';

export const FAST: Partial<Timing> = { backoffInitialMs: 20, backoffMaxMs: 200, requestTimeoutMs: 2000 };

export interface Net {
  relay: RelayProcess;
  primary: Primary;
  members: Member[];
  /** Pairs a new node of `kind` and connects it as a member. */
  add(kind: PairingKind, opts?: Partial<MemberOptions>): Promise<Member>;
  /** Pairs a new node and returns its identity and roster without connecting it. */
  pairOnly(kind: PairingKind): Promise<{ identity: Identity; roster: Member['roster'] }>;
  close(): Promise<void>;
}

export async function startNet(
  opts: { env?: Record<string, string>; member?: Partial<MemberOptions> } = {},
): Promise<Net> {
  const relay = await startRelay(opts.env);
  const id = createIdentity();
  const primary = new Primary({
    identity: id,
    roster: createNetwork({ identity: id, relay: relay.url }),
    timing: FAST,
    ...opts.member,
  });
  try {
    await primary.waitConnected(15_000);
  } catch (e) {
    primary.close();
    await relay.stop();
    throw e;
  }
  const members: Member[] = [];
  const net: Net = {
    relay,
    primary,
    members,
    async add(kind, more = {}) {
      const { identity, roster } = await net.pairOnly(kind);
      const m = await Member.connect({ identity, roster, timing: FAST, ...opts.member, ...more });
      // The primary pushes the new roster to the others over their sessions, which takes a
      // moment: until it lands, they do not know the newcomer and would refuse to send to it.
      const others = [primary, ...members].filter((o) => o.state === 'connected');
      members.push(m);
      await until(() => others.every((o) => o.state !== 'connected' || o.roster.version >= roster.version), 'the others to learn the roster');
      return m;
    },
    async pairOnly(kind) {
      const identity = createIdentity();
      const code = primary.openPairingCode(kind);
      const { roster } = await pair({ link: code.link, identity });
      return { identity, roster };
    },
    async close() {
      for (const m of members) m.close();
      primary.close();
      const code = await relay.stop();
      if (code !== 0) throw new Error(`relay exited ${code}:\n${relay.log.join('')}`);
    },
  };
  return net;
}

/** Collects what a member receives, with a way to wait for the next messages. */
export function inbox(m: Member): { messages: InboundMessage[]; next(n?: number, timeoutMs?: number): Promise<InboundMessage[]> } {
  const messages: InboundMessage[] = [];
  m.onMessage((msg) => messages.push(msg));
  let taken = 0;
  return {
    messages,
    async next(n = 1, timeoutMs = 10_000) {
      await until(() => messages.length >= taken + n, `${n} message(s)`, timeoutMs);
      const out = messages.slice(taken, taken + n);
      taken += n;
      return out;
    },
  };
}

export async function until(cond: () => boolean, what: string, timeoutMs = 10_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await sleep(10);
  }
}

export const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
export const bytesOf = (s: string) => new TextEncoder().encode(s);
export const textOf = (b: Uint8Array) => new TextDecoder().decode(b);

/** What the client keeps private, read for assertions only. */
export type SessionInfo = { localIndex: number; remoteIndex: number; initiator: boolean; current: boolean; sent: number; received: number; sendCredit: number; inflight: number };
export function sessionsOf(m: Member): { sessionInfo(peer: string): SessionInfo[] } {
  return (m as unknown as { sessions: { sessionInfo(peer: string): SessionInfo[] } }).sessions;
}

/** A WebSocket driven by hand, for frames and messages the client library never sends. */
export interface Raw {
  ws: WebSocket;
  /** Text messages parsed, binary ones as bytes, in arrival order. */
  received: (Record<string, unknown> | Uint8Array)[];
  /** Resolves with the close code. */
  closed: Promise<number>;
  next(timeoutMs?: number): Promise<Record<string, unknown> | Uint8Array>;
  json(timeoutMs?: number): Promise<Record<string, unknown>>;
}

export function raw(url: string): Raw {
  const ws = new WebSocket(url);
  ws.binaryType = 'arraybuffer';
  const received: Raw['received'] = [];
  let taken = 0;
  let closeCode: number | undefined;
  const closed = new Promise<number>((resolve) => {
    ws.onclose = (ev) => {
      closeCode = ev.code;
      resolve(ev.code);
    };
  });
  ws.onmessage = (ev) => {
    received.push(typeof ev.data === 'string' ? (JSON.parse(ev.data) as Record<string, unknown>) : new Uint8Array(ev.data as ArrayBuffer));
  };
  const r: Raw = {
    ws,
    received,
    closed,
    async next(timeoutMs = 5000) {
      await until(() => received.length > taken || closeCode !== undefined, 'a raw message', timeoutMs);
      if (received.length <= taken) throw new Error(`closed ${closeCode} instead`);
      return received[taken++]!;
    },
    async json(timeoutMs) {
      const m = await r.next(timeoutMs);
      if (m instanceof Uint8Array) throw new Error(`expected text, got ${m.length} binary bytes`);
      return m;
    },
  };
  return r;
}
