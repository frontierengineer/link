// Being the primary (section 3.1): what a member does while it holds the
// network seed and its roster names it primary. It opens pairing codes and runs
// the B side of pairing (section 5), revokes (section 8), accepts resignations
// (section 7.3), pushes every new roster to the relay and the members, and asks
// the relay for its usage figures (section 4.3: request-only, within the relay's
// budget). A member holds one of these only while it is the primary, and stops
// it in place when it no longer is: its connection is untouched.

import { b64u, fromB64u, fromB64uLen, randomBytes } from './bytes.js';
import { buildPairingLink, formatCode, generateCode, generateCodeId, normalizeCode } from './code.js';
import { ClosedError, InvalidError, LinkError, RateLimitedError, RosterFullError, TimeoutError } from './errors.js';
import { encodeFrame, FrameType } from './frames.js';
import { nodeIdFromEd25519 } from './identity.js';
import { canonicalize } from './jcs.js';
import { integerMember, parseJson } from './json.js';
import type { DiagnosticsHook } from './diag-hook.js';
import type { NetworkKey } from './identity.js';
import type { MemberEvents, Timing } from './member.js';
import { Bucket } from './sessions.js';
import { PrimaryExchange } from './pairing.js';
import type { RelayConnection, RelayState } from './relay.js';
import type { SessionManager } from './sessions.js';
import {
  MAX_ROSTER_BYTES,
  findMember,
  nextRosterSize,
  signNextRoster,
  type Roster,
  type RosterMember,
} from './roster.js';
import { verifyResignation, type Resignation } from './signed.js';
import type { ControlMessage } from './socket.js';

export const CODE_LIFETIME_MS = 15 * 60_000;
/** A member entry with every field at its fixed length. */
const PLACEHOLDER_MEMBER: RosterMember = { id: 'a'.repeat(26), ed25519: 'A'.repeat(43), x25519: 'A'.repeat(43) };
export const CODE_ATTEMPTS = 5;
export const PAIRING_CHANNEL_MS = 60_000;
const RESIGN_SKEW_MS = 300_000;
/** Closed code ids remembered, so a `pairing` naming one is still told apart from one naming an
 * id this primary never opened, which only a relay can make up (section 5.2). */
const CLOSED_CODES = 1024;
/** A `pairingFailed` event for one code and reason at most once in this long. */
export const REFUSAL_EVENT_MS = 1000;
/** A `pairEnd` refusing a code this primary issued always answers the first refusal on a pairing
 * channel, and repeats on that channel at most once in this long, apart from the shared budget
 * below: neither made-up ids nor anyone else holding the code id can use up the answer an honest
 * newcomer with a mistyped or expired code is owed (it would otherwise wait out the relay's 60 s). */
export const CODE_REPLY_MS = 1000;
/** `pairEnd` answers refusing code ids never issued here: this rate, this burst. */
export const REFUSAL_REPLY_RATE = 32;
/** Pairing channels set up per open code: this many a second, this many at once. Each costs a
 * SPAKE2 setup (milliseconds of work), and a `pairEnd` refunds its attempt, so the five attempts
 * alone do not bound them (section 5.2). Beyond it, refused as a code out of attempts, with the
 * text "too many attempts at once; try again". */
export const CHANNEL_SETUP_RATE = 4;
export const CHANNEL_SETUP_BURST = 8;
export const REFUSAL_REPLY_BURST = 64;

export interface PairingCode {
  /** Display form, `XXXX-XXXX`. */
  code: string;
  /** b64u of the 8-byte code id. */
  codeId: string;
  /** The `frontier://pair?...` link carrying network, code, code id and relay. */
  link: string;
  /** Unix milliseconds. */
  expiresAt: number;
}

/** The relay's answer to a usage ask (section 4.3). Per-member figures come from each member's `traffic()`. */
export interface UsageReport {
  network: {
    /** Bytes charged to the network over the last hour, in five-minute steps. */
    bytesHour: number;
    /** Connected members. */
    connections: number;
    limits: { rateBps: number; quotaBytesHour: number; trickleBps: number };
    /** bytesHour / quotaBytesHour; 0 without a quota. */
    quotaUsed: number;
    /** The trickle rate is in effect: send less (drop video, keep audio). */
    slowed: boolean;
  };
}

/** The relay's budget for usage asks per network (section 4.3): this many at once (one: no
 * burst)... */
export const USAGE_BURST = 1;
/** ...then one per this many milliseconds. */
export const USAGE_INTERVAL_MS = 10_000;

/** A roster push to a member that fails is tried again after this long, doubling to the
 * maximum, until it goes, the member leaves the roster, or a newer roster replaces it (section 8). */
export const PUSH_RETRY_INITIAL_MS = 1000;
export const PUSH_RETRY_MAX_MS = 600_000;

/** A primary's events are a member's: any member may become the primary (section 3.1). */
export type PrimaryEvents = MemberEvents;

/** What the role needs of the member it belongs to. */
export interface PrimaryHost {
  readonly id: string;
  /** The roster the member holds now (not a copy). */
  roster(): Roster;
  networkKey(): NetworkKey;
  readonly relay: RelayConnection;
  readonly sessions: SessionManager;
  readonly timing: Timing;
  now(): number;
  mono(): number;
  diag(): DiagnosticsHook | undefined;
  /** Adopts a roster this primary signed. */
  adopt(r: Roster): void;
  online(): Promise<void>;
  isTerminal(): boolean;
  emit<K extends 'paired' | 'pairingFailed'>(event: K, value: MemberEvents[K]): void;
}

interface OpenCode {
  code: string;
  codeId: string;
  /** Unix milliseconds, as shown; `deadline` is the same moment on the monotonic clock. */
  expiresAt: number;
  deadline: number;
  /** Channel setups this code may still have. */
  setups: Bucket;
  failed: number;
  inFlight: number;
  claimed: boolean;
  burned: boolean;
}

interface PairChannel {
  channel: Uint8Array;
  key: string;
  entry: OpenCode;
  exchange: PrimaryExchange;
  stage: 'p1' | 'p3' | 'p5' | 'done';
  claimed: boolean;
  timer: ReturnType<typeof setTimeout>;
}

export class PrimaryRole {
  private readonly codes = new Map<string, OpenCode>();
  private readonly channels = new Map<string, PairChannel>();
  /** Code ids closed here (used, burned, cancelled, expired), oldest first. */
  private readonly closedCodes = new Set<string>();
  /** When a refusal event was last raised, by code id and reason; when a refusal last went, by issued code id. */
  private readonly refusalEvents = new Map<string, number>();
  private readonly codeReplies = new Map<string, number>();
  private readonly refusalReplies = new Bucket(REFUSAL_REPLY_RATE, REFUSAL_REPLY_BURST);
  /** Pushes of the current roster waiting to be tried again, by member. */
  private readonly pushRetries = new Map<string, ReturnType<typeof setTimeout>>();
  private readonly usageRequests = new Map<string, { resolve: (r: UsageReport) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> }>();

  constructor(private readonly m: PrimaryHost) {}

  /**
   * Opens a code that admits one node for 15 minutes. The code is random unless `code` gives
   * one (any spelling `normalizeCode` accepts): a chosen code is easier to say and easier to
   * guess, and like every code it burns after five wrong confirmations.
   */
  openPairingCode(opts: { lifetimeMs?: number; code?: string } = {}): PairingCode {
    let chosen: string | undefined;
    if (opts.code !== undefined) {
      try {
        chosen = normalizeCode(opts.code);
      } catch (e) {
        throw new InvalidError((e as Error).message);
      }
    }
    // Every entry has the same shape, so a placeholder measures the next roster.
    const room = this.sizeWith([...this.m.roster().members, PLACEHOLDER_MEMBER]);
    if (room > MAX_ROSTER_BYTES) throw new RosterFullError(room);
    this.pruneCodes();
    const code = chosen ?? generateCode();
    const codeId = b64u(generateCodeId());
    const lifetime = opts.lifetimeMs ?? CODE_LIFETIME_MS;
    const expiresAt = this.m.now() + lifetime;
    this.codes.set(codeId, {
      code,
      codeId,
      expiresAt,
      deadline: this.m.mono() + lifetime,
      setups: new Bucket(CHANNEL_SETUP_RATE, CHANNEL_SETUP_BURST),
      failed: 0,
      inFlight: 0,
      claimed: false,
      burned: false,
    });
    return {
      code: formatCode(code),
      codeId,
      expiresAt,
      // A network not placed yet names no relay: the link names the one this primary dials.
      link: buildPairingLink({ network: this.m.roster().network, code, codeId, relay: this.m.roster().relay || this.m.relay.relayUrl }),
    };
  }

  /** Withdraws an open code. */
  cancelPairingCode(codeId: string): void {
    const entry = this.codes.get(codeId);
    if (entry) entry.burned = true;
    this.closeCode(codeId);
  }

  /** Removes a member and publishes the roster. Returns the new roster. */
  revoke(nodeId: string): Roster {
    if (nodeId === this.m.id) throw new InvalidError('the primary cannot revoke itself');
    if (!findMember(this.m.roster(), nodeId)) throw new InvalidError(`${nodeId} is not on the roster`);
    return this.publish(this.nextRoster(this.m.roster().members.filter((m) => m.id !== nodeId)));
  }

  /**
   * Asks the relay for this network's usage. The relay allows one ask per USAGE_INTERVAL_MS
   * (10 s) per network, with no burst; an ask sooner than that it refuses at once, and this
   * rejects with RateLimitedError. Ask rarely, and keep the answer; whether the network is
   * slowed is `shaping`, which needs no ask.
   */
  usage(): Promise<UsageReport> {
    const id = b64u(randomBytes(9));
    this.m.diag()?.event({ kind: 'usageAsk' });
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.usageRequests.delete(id);
        reject(new TimeoutError('usage request'));
      }, this.m.timing.requestTimeoutMs);
      this.usageRequests.set(id, { resolve, reject, timer });
      this.m.online()
        .then(() => {
          if (!this.m.relay.sendControl({ type: 'usage', id })) throw new ClosedError('not connected to the relay');
        })
        .catch((e: Error) => {
          clearTimeout(timer);
          this.usageRequests.delete(id);
          reject(e);
        });
    });
  }

  // ── Roster publication ──

  /** The JCS size the next roster with `members` would have once signed. */
  private sizeWith(members: RosterMember[]): number {
    return nextRosterSize(this.m.roster(), members, this.m.now());
  }

  /** The next roster version with `members`, signed. Throws RosterFullError over 65000 bytes. */
  private nextRoster(members: RosterMember[]): Roster {
    return signNextRoster(this.m.roster(), members, this.m.networkKey(), this.m.now());
  }

  /** Adopts and pushes `roster`: to the relay, and to every member but `skip` (a newcomer that
   * holds it already, from P6). */
  private publish(roster: Roster, skip?: string): Roster {
    this.m.adopt(roster);
    this.push(roster, skip);
    return roster;
  }

  /** Pushes the roster held, as after a publication, without signing anything: a new primary
   * does so once it has taken the network seed (section 3.1). */
  republish(): void {
    this.push(this.m.roster());
  }

  private push(roster: Roster, skip?: string): void {
    this.m.relay.sendControl({ type: 'roster', roster });
    // A newer roster replaces any push still waiting to be tried again.
    this.cancelPushes();
    const json = canonicalize(roster);
    for (const m of roster.members) {
      if (m.id === this.m.id || m.id === skip) continue;
      this.pushRoster(m.id, roster, json, PUSH_RETRY_INITIAL_MS);
    }
  }

  /**
   * Pushes `roster` to a member, and if that fails (the member unreachable, the relay connection
   * down) tries again after `wait`, doubling, until it goes: a member with no traffic would
   * otherwise keep an old roster, a revocation above all, until its next handshake.
   */
  private pushRoster(id: string, roster: Roster, json: string, wait: number): void {
    const current = () => !this.m.isTerminal() && this.m.roster().version === roster.version && !!findMember(this.m.roster(), id);
    this.m.sessions.sendRoster(id, roster, json).catch(() => {
      if (!current()) return;
      const t = setTimeout(() => {
        this.pushRetries.delete(id);
        if (current()) this.pushRoster(id, roster, json, Math.min(2 * wait, PUSH_RETRY_MAX_MS));
      }, wait);
      (t as { unref?: () => void }).unref?.();
      clearTimeout(this.pushRetries.get(id));
      this.pushRetries.set(id, t);
    });
  }

  private cancelPushes(): void {
    for (const t of this.pushRetries.values()) clearTimeout(t);
    this.pushRetries.clear();
  }

  /**
   * Stops being the primary, in place (section 3.1): every open code closes, every pairing
   * channel ends (the relay is told; each tells the application, `reason` saying why), pushes
   * still waiting are dropped, and usage asks in flight fail. The connection is untouched.
   */
  stop(reason: string): void {
    this.cancelPushes();
    for (const id of [...this.codes.keys()]) {
      this.codes.get(id)!.burned = true;
      this.closeCode(id);
    }
    for (const key of [...this.channels.keys()]) this.endChannel(key, reason, true, true);
    for (const [id, req] of this.usageRequests) {
      clearTimeout(req.timer);
      req.reject(new InvalidError('this node is no longer the primary'));
      this.usageRequests.delete(id);
    }
  }

  close(): void {
    this.cancelPushes();
  }

  onResign(from: string, json: string): void {
    let r: Resignation;
    try {
      r = parseJson(json) as Resignation;
    } catch {
      return;
    }
    if (typeof r !== 'object' || r === null || r.node !== from || integerMember(r, 'ts') === undefined) return;
    if (Math.abs(this.m.now() - r.ts) > RESIGN_SKEW_MS) return;
    const member = findMember(this.m.roster(), from);
    if (!member || member.id === this.m.roster().primary) return;
    if (!verifyResignation(r, this.m.roster().network, fromB64uLen(member.ed25519, 32, 'ed25519'))) return;
    this.publish(this.nextRoster(this.m.roster().members.filter((m) => m.id !== from)));
  }

  // ── Relay control ──

  /** A relay control message; true when the role consumed it. */
  onControl(msg: ControlMessage): boolean {
    switch (msg.type) {
      case 'usage': {
        const req = typeof msg.id === 'string' ? this.usageRequests.get(msg.id) : undefined;
        if (!req) return true;
        clearTimeout(req.timer);
        this.usageRequests.delete(msg.id as string);
        const report = { network: msg.network } as UsageReport;
        this.m.diag()?.event({ kind: 'usage', slowed: report.network?.slowed === true, trickleBps: Number(report.network?.limits?.trickleBps) || 0 });
        req.resolve(report);
        return true;
      }
      case 'pairing':
        this.onPairing(msg);
        return true;
      case 'pairEnd':
        if (typeof msg.channel === 'string') this.endChannel(msg.channel, 'the newcomer left', false);
        return true;
      case 'error': {
        const req = typeof msg.id === 'string' ? this.usageRequests.get(msg.id) : undefined;
        if (req) {
          clearTimeout(req.timer);
          this.usageRequests.delete(msg.id as string);
          if (msg.code === 'rate_limited') {
            this.m.diag()?.event({ kind: 'usageRefused' });
            req.reject(new RateLimitedError('usage request'));
          } else {
            req.reject(new LinkError(msg.code === 'forbidden' ? 'refused' : 'invalid', `relay answered ${String(msg.code)}`));
          }
          return true;
        }
        return false;
      }
      default:
        return false;
    }
  }

  onConnectionState(s: RelayState): void {
    if (s === 'registered') return;
    for (const key of [...this.channels.keys()]) this.endChannel(key, 'the relay connection dropped', false);
    for (const [id, req] of this.usageRequests) {
      clearTimeout(req.timer);
      req.reject(new ClosedError('relay connection lost'));
      this.usageRequests.delete(id);
    }
  }

  // ── Pairing, B side ──

  private pruneCodes(): void {
    const now = this.m.mono();
    for (const [id, c] of this.codes) if (c.burned || c.deadline <= now) this.closeCode(id);
  }

  /** Forgets an open code, remembering that it was one. */
  private closeCode(id: string): void {
    this.codes.delete(id);
    this.closedCodes.delete(id);
    this.closedCodes.add(id);
    for (const old of this.closedCodes) {
      if (this.closedCodes.size <= CLOSED_CODES) break;
      this.closedCodes.delete(old);
    }
  }

  /**
   * Refuses a `pairing` (section 5.2). For a code id never issued here (only a relay makes those
   * up): `pairEnd` within the shared REFUSAL_REPLY_RATE, and no event. For a code issued here:
   * `pairEnd` for the first refusal on the channel and at most once per CODE_REPLY_MS for that
   * code and channel after, outside the shared budget, and a `pairingFailed` event at most once
   * per REFUSAL_EVENT_MS for that code and reason.
   */
  private refusePairing(key: string, codeId: string, reason: string): void {
    const now = this.m.mono();
    const issued = this.codes.has(codeId) || this.closedCodes.has(codeId);
    const reply = issued ? once(this.codeReplies, `${codeId}/${key}`, now, CODE_REPLY_MS) : this.refusalReplies.take(now);
    if (reply) this.m.relay.sendControl({ type: 'pairEnd', channel: key });
    if (issued && once(this.refusalEvents, `${codeId}/${reason}`, now, REFUSAL_EVENT_MS)) this.m.emit('pairingFailed', { codeId, reason });
  }

  private onPairing(msg: ControlMessage): void {
    if (typeof msg.channel !== 'string' || typeof msg.code !== 'string') return;
    let channel: Uint8Array;
    try {
      channel = fromB64uLen(msg.channel, 16, 'channel');
    } catch {
      return;
    }
    const key = msg.channel;
    const entry = this.codes.get(msg.code);
    const refuse = (reason: string) => this.refusePairing(key, msg.code as string, reason);
    if (this.channels.has(key)) return;
    if (!entry || entry.burned || entry.deadline <= this.m.mono()) return refuse('unknown or expired code');
    if (entry.claimed) return refuse('code already used');
    // Reserve a slot atomically: attempts in flight plus failures never exceed five, and setups
    // stay within the code's own budget (a relay could otherwise set up and end channels on it,
    // each refunded, as fast as it likes).
    if (entry.failed + entry.inFlight >= CODE_ATTEMPTS) return refuse('no attempts left');
    // The same refusal (a code out of attempts, for now), but an honest newcomer is told to retry.
    if (!entry.setups.take(this.m.mono())) return refuse('too many attempts at once; try again');
    entry.inFlight++;
    const ch: PairChannel = {
      channel,
      key,
      entry,
      exchange: new PrimaryExchange(entry.code, fromB64u(entry.codeId)),
      stage: 'p1',
      claimed: false,
      timer: setTimeout(() => this.endChannel(key, 'pairing timed out', true), PAIRING_CHANNEL_MS),
    };
    this.channels.set(key, ch);
  }

  onPairFrame(channel: Uint8Array, body: Uint8Array): void {
    const ch = this.channels.get(b64u(channel));
    if (!ch) return;
    try {
      switch (ch.stage) {
        case 'p1':
          this.sendPair(ch, ch.exchange.onP1(body));
          ch.stage = 'p3';
          return;
        case 'p3': {
          if (!ch.exchange.onP3(body)) return this.failAttempt(ch, 'wrong code');
          if (ch.entry.claimed || ch.entry.burned) return this.endChannel(ch.key, 'code already used', true);
          ch.entry.claimed = true;
          ch.claimed = true;
          this.sendPair(ch, ch.exchange.p4());
          ch.stage = 'p5';
          return;
        }
        case 'p5':
          return this.completePairing(ch, body);
        default:
          return;
      }
    } catch (e) {
      // A malformed message counts as a failed attempt.
      this.failAttempt(ch, `malformed pairing message: ${(e as Error).message}`);
    }
  }

  private completePairing(ch: PairChannel, body: Uint8Array): void {
    const keys = ch.exchange.onP5(body);
    const id = nodeIdFromEd25519(keys.ed25519);
    if (findMember(this.m.roster(), id)) return this.endChannel(ch.key, `${id} is already a member`, true);
    const member: RosterMember = { id, ed25519: b64u(keys.ed25519), x25519: b64u(keys.x25519) };
    let next: Roster;
    try {
      next = this.nextRoster([...this.m.roster().members, member]);
    } catch (e) {
      if (e instanceof RosterFullError) return this.endChannel(ch.key, e.message, true);
      throw e;
    }
    ch.stage = 'done';
    clearTimeout(ch.timer);
    this.channels.delete(ch.key);
    ch.entry.inFlight--;
    ch.entry.burned = true;
    this.closeCode(ch.entry.codeId);
    this.sendPair(ch, ch.exchange.p6(next));
    // The newcomer has this roster already (P6): pushing it too would only fail while it
    // reconnects, and be tried again.
    this.publish(next, member.id);
    this.m.relay.sendControl({ type: 'pairEnd', channel: ch.key });
    this.m.emit('paired', { member, codeId: ch.entry.codeId, roster: next });
  }

  private sendPair(ch: PairChannel, body: Uint8Array): void {
    this.m.relay.sendBinary(encodeFrame(FrameType.Pair, ch.channel, body));
  }

  /** A failed confirmation: the slot stays used; five burn the code. */
  private failAttempt(ch: PairChannel, reason: string): void {
    clearTimeout(ch.timer);
    this.channels.delete(ch.key);
    ch.entry.inFlight--;
    ch.entry.failed++;
    if (ch.claimed) ch.entry.claimed = false;
    if (ch.entry.failed >= CODE_ATTEMPTS) {
      ch.entry.burned = true;
      this.closeCode(ch.entry.codeId);
    }
    this.m.relay.sendControl({ type: 'pairEnd', channel: ch.key });
    this.m.emit('pairingFailed', { codeId: ch.entry.codeId, reason });
  }

  /** A timeout or a dropped connection: the slot is refunded. `always` tells the application
   * whatever the once-a-second limit says (the primary stopping being one). */
  private endChannel(key: string, reason: string, tellRelay: boolean, always = false): void {
    const ch = this.channels.get(key);
    if (!ch) return;
    clearTimeout(ch.timer);
    this.channels.delete(key);
    ch.entry.inFlight--;
    if (ch.claimed) ch.entry.claimed = false;
    if (tellRelay) this.m.relay.sendControl({ type: 'pairEnd', channel: key });
    // Channels ended without a failed attempt (left, timed out) cost nothing to whoever ends
    // them, so they tell the application at most once a second per code and reason.
    if (always || once(this.refusalEvents, `${ch.entry.codeId}/${reason}`, this.m.mono(), REFUSAL_EVENT_MS)) {
      this.m.emit('pairingFailed', { codeId: ch.entry.codeId, reason });
    }
  }
}

/** Whether `key` may act now, at most once per `ms`; the table is bounded (when full, the stale
 * entries go, and then all, so a key's first use is never refused). */
function once(table: Map<string, number>, key: string, now: number, ms: number): boolean {
  const last = table.get(key);
  if (last !== undefined && now - last < ms) return false;
  if (table.size >= 2 * CLOSED_CODES) {
    for (const [k, t] of table) if (now - t >= ms) table.delete(k);
    if (table.size >= 2 * CLOSED_CODES) table.clear();
  }
  table.set(key, now);
  return true;
}
