// Builds real networks on the test relay: a primary, then members paired
// through the full section 5 exchange.

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
} from '../../src/index.js';
import { TestRelay, type RelayOptions } from './relay.js';

export const FAST: Partial<Timing> = { backoffInitialMs: 20, backoffMaxMs: 200, requestTimeoutMs: 2000 };

export interface TestNetwork {
  relay: TestRelay;
  primary: Primary;
  members: Member[];
  /** Pairs and connects a new member. */
  add(kind: PairingKind, opts?: Partial<MemberOptions>): Promise<Member>;
  close(): Promise<void>;
}

export async function startNetwork(
  opts: { relay?: RelayOptions; member?: Partial<MemberOptions> } = {},
): Promise<TestNetwork> {
  const relay = await TestRelay.start(opts.relay);
  const id = createIdentity();
  const primary = await Primary.connect({
    identity: id,
    roster: createNetwork({ identity: id, relay: relay.url }),
    timing: FAST,
    ...opts.member,
  });
  const members: Member[] = [];
  const net: TestNetwork = {
    relay,
    primary,
    members,
    async add(kind, more = {}) {
      const identity: Identity = createIdentity();
      const code = primary.openPairingCode(kind);
      const { roster } = await pair({ link: code.link, identity });
      const m = await Member.connect({ identity, roster, timing: FAST, ...opts.member, ...more });
      members.push(m);
      return m;
    },
    async close() {
      for (const m of members) m.close();
      primary.close();
      await relay.stop();
    },
  };
  return net;
}

/** Collects messages a member receives, with a way to wait for the next ones. */
export function inbox(m: Member): { messages: InboundMessage[]; next(n?: number, timeoutMs?: number): Promise<InboundMessage[]> } {
  const messages: InboundMessage[] = [];
  m.onMessage((msg) => messages.push(msg));
  let taken = 0;
  return {
    messages,
    async next(n = 1, timeoutMs = 5000) {
      await until(() => messages.length >= taken + n, `${n} message(s)`, timeoutMs);
      const out = messages.slice(taken, taken + n);
      taken += n;
      return out;
    },
  };
}

/** Polls `cond` until it holds. */
export async function until(cond: () => boolean, what: string, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 10));
  }
}

export const bytesOf = (s: string) => new TextEncoder().encode(s);
export const textOf = (b: Uint8Array) => new TextDecoder().decode(b);
