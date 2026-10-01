// The primary: the member that signs the roster. It opens pairing codes and
// runs the B side of pairing (section 5), revokes (section 8), accepts
// resignations (section 7.3), pushes every new roster to the relay and the
// members, and reads the relay's usage figures (section 4.3).

import { b64u, fromB64u, fromB64uLen, randomBytes } from './bytes.js';
import { buildPairingLink, formatCode, generateCode, generateCodeId } from './code.js';
import { ClosedError, InvalidError, LinkError, TimeoutError } from './errors.js';
import { encodeFrame, FrameType } from './frames.js';
import { nodeIdFromEd25519 } from './identity.js';
import { canonicalize } from './jcs.js';
import { Member, type MemberEvents, type MemberOptions, type UsageAlert } from './member.js';
import { PrimaryExchange } from './pairing.js';
import type { RelayState } from './relay.js';
import {
  PAIRING_KINDS,
  findMember,
  signRoster,
  type PairingKind,
  type Roster,
  type RosterMember,
} from './roster.js';
import { verifyResignation, type Resignation } from './signed.js';
import type { ControlMessage } from './socket.js';

export const CODE_LIFETIME_MS = 15 * 60_000;
export const CODE_ATTEMPTS = 5;
export const PAIRING_CHANNEL_MS = 60_000;
const RESIGN_SKEW_MS = 300_000;

export interface PairingCode {
  /** Display form, `XXXX-XXXX`. */
  code: string;
  /** b64u of the 8-byte code id. */
  codeId: string;
  kind: PairingKind;
  /** The `frontier://pair?...` link carrying network, code, code id and relay. */
  link: string;
  /** Unix milliseconds. */
  expiresAt: number;
}

export interface UsageReport {
  network: {
    bytesHour: number;
    bytesDay: number;
    connections: number;
    limits: { rateBps: number; quotaBytesHour: number; trickleBps: number };
    quotaUsed: number;
    slowed: boolean;
  };
  members: { id: string; bytesHour: number; bytesDay: number; connected: boolean }[];
}

export type PrimaryEvents = MemberEvents & {
  /** A newcomer completed pairing and is on the published roster. */
  paired: { member: RosterMember; roster: Roster };
  /** A pairing attempt ended without a new member. */
  pairingFailed: { codeId: string; reason: string };
};

interface OpenCode {
  code: string;
  codeId: string;
  kind: PairingKind;
  expiresAt: number;
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

export class Primary extends Member<PrimaryEvents> {
  private readonly codes = new Map<string, OpenCode>();
  private readonly channels = new Map<string, PairChannel>();
  private readonly usageRequests = new Map<string, { resolve: (r: UsageReport) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> }>();

  constructor(opts: MemberOptions) {
    super(opts);
    if (opts.identity.id !== opts.roster.network) throw new InvalidError('this identity is not the network primary');
  }

  /** Creates the primary and resolves once it is registered with the relay. */
  static override async connect(opts: MemberOptions): Promise<Primary> {
    const p = new Primary(opts);
    await p.waitConnected();
    return p;
  }

  /** Opens a code that admits one node of `kind` for 15 minutes. */
  openPairingCode(kind: PairingKind, opts: { lifetimeMs?: number } = {}): PairingCode {
    if (!PAIRING_KINDS.includes(kind)) throw new InvalidError(`kind must be one of ${PAIRING_KINDS.join(', ')}`);
    this.pruneCodes();
    const code = generateCode();
    const codeId = b64u(generateCodeId());
    const expiresAt = this.now() + (opts.lifetimeMs ?? CODE_LIFETIME_MS);
    this.codes.set(codeId, { code, codeId, kind, expiresAt, failed: 0, inFlight: 0, claimed: false, burned: false });
    return {
      code: formatCode(code),
      codeId,
      kind,
      expiresAt,
      link: buildPairingLink({ network: this.network, code, codeId, relay: this.currentRoster.relay }),
    };
  }

  /** Withdraws an open code. */
  cancelPairingCode(codeId: string): void {
    const entry = this.codes.get(codeId);
    if (entry) entry.burned = true;
    this.codes.delete(codeId);
  }

  /** Removes a member and publishes the roster. Returns the new roster. */
  revoke(nodeId: string): Roster {
    if (nodeId === this.id) throw new InvalidError('the primary cannot revoke itself');
    if (!findMember(this.currentRoster, nodeId)) throw new InvalidError(`${nodeId} is not on the roster`);
    return this.publish(this.nextRoster(this.currentRoster.members.filter((m) => m.id !== nodeId)));
  }

  /** Asks the relay for this network's usage. */
  usage(): Promise<UsageReport> {
    const id = b64u(randomBytes(9));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.usageRequests.delete(id);
        reject(new TimeoutError('usage request'));
      }, this.timing.requestTimeoutMs);
      this.usageRequests.set(id, { resolve, reject, timer });
      this.online()
        .then(() => {
          if (!this.relay.sendControl({ type: 'usage', id })) throw new ClosedError('not connected to the relay');
        })
        .catch((e: Error) => {
          clearTimeout(timer);
          this.usageRequests.delete(id);
          reject(e);
        });
    });
  }

  // ── Roster publication ──

  /** The next roster version with `members`, signed. */
  private nextRoster(members: RosterMember[]): Roster {
    const prev = this.currentRoster;
    return signRoster(
      {
        network: prev.network,
        version: prev.version + 1,
        issuedAt: Math.max(this.now(), prev.issuedAt),
        relay: prev.relay,
        primary: prev.primary,
        members,
      },
      this.identity,
    );
  }

  /** Adopts a roster this primary signed and pushes it to the relay and every member. */
  private publish(roster: Roster): Roster {
    this.adoptRoster(roster);
    this.relay.sendControl({ type: 'roster', roster });
    const json = canonicalize(roster);
    for (const m of roster.members) {
      if (m.id === this.id) continue;
      this.sessions.sendControl(m.id, { type: 'roster', json }).catch(() => undefined);
    }
    return roster;
  }

  protected override onResign(from: string, json: string): void {
    let r: Resignation;
    try {
      r = JSON.parse(json) as Resignation;
    } catch {
      return;
    }
    if (typeof r !== 'object' || r === null || r.node !== from || typeof r.ts !== 'number') return;
    if (Math.abs(this.now() - r.ts) > RESIGN_SKEW_MS) return;
    const member = findMember(this.currentRoster, from);
    if (!member || member.kind === 'primary') return;
    if (!verifyResignation(r, this.network, fromB64uLen(member.ed25519, 32, 'ed25519'))) return;
    this.publish(this.nextRoster(this.currentRoster.members.filter((m) => m.id !== from)));
  }

  // ── Relay control ──

  protected override onControl(msg: ControlMessage): void {
    switch (msg.type) {
      case 'usage': {
        const req = typeof msg.id === 'string' ? this.usageRequests.get(msg.id) : undefined;
        if (!req) return;
        clearTimeout(req.timer);
        this.usageRequests.delete(msg.id as string);
        req.resolve({ network: msg.network, members: msg.members } as UsageReport);
        return;
      }
      case 'usageAlert':
        this.emit('usageAlert', { quotaUsed: Number(msg.quotaUsed), slowed: msg.slowed === true } satisfies UsageAlert);
        return;
      case 'pairing':
        this.onPairing(msg);
        return;
      case 'pairEnd':
        if (typeof msg.channel === 'string') this.endChannel(msg.channel, 'the newcomer left', false);
        return;
      case 'error': {
        const req = typeof msg.id === 'string' ? this.usageRequests.get(msg.id) : undefined;
        if (req) {
          clearTimeout(req.timer);
          this.usageRequests.delete(msg.id as string);
          req.reject(new LinkError(msg.code === 'forbidden' ? 'refused' : 'invalid', `relay answered ${String(msg.code)}`));
          return;
        }
        super.onControl(msg);
        return;
      }
      default:
        super.onControl(msg);
    }
  }

  protected override onConnectionState(s: RelayState): void {
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
    const now = this.now();
    for (const [id, c] of this.codes) if (c.burned || c.expiresAt <= now) this.codes.delete(id);
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
    const refuse = (reason: string) => {
      this.relay.sendControl({ type: 'pairEnd', channel: key });
      this.emit('pairingFailed', { codeId: msg.code as string, reason });
    };
    if (this.channels.has(key)) return;
    if (!entry || entry.burned || entry.expiresAt <= this.now()) return refuse('unknown or expired code');
    if (entry.claimed) return refuse('code already used');
    // Reserve a slot atomically: attempts in flight plus failures never exceed five.
    if (entry.failed + entry.inFlight >= CODE_ATTEMPTS) return refuse('no attempts left');
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

  protected override onPairFrame(channel: Uint8Array, body: Uint8Array): void {
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
    if (findMember(this.currentRoster, id)) return this.endChannel(ch.key, `${id} is already a member`, true);
    const member: RosterMember = { id, ed25519: b64u(keys.ed25519), x25519: b64u(keys.x25519), kind: ch.entry.kind };
    ch.stage = 'done';
    clearTimeout(ch.timer);
    this.channels.delete(ch.key);
    ch.entry.inFlight--;
    ch.entry.burned = true;
    this.codes.delete(ch.entry.codeId);
    const next = this.nextRoster([...this.currentRoster.members, member]);
    this.sendPair(ch, ch.exchange.p6(next));
    this.publish(next);
    this.relay.sendControl({ type: 'pairEnd', channel: ch.key });
    this.emit('paired', { member, roster: next });
  }

  private sendPair(ch: PairChannel, body: Uint8Array): void {
    this.relay.sendBinary(encodeFrame(FrameType.Pair, ch.channel, body));
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
      this.codes.delete(ch.entry.codeId);
    }
    this.relay.sendControl({ type: 'pairEnd', channel: ch.key });
    this.emit('pairingFailed', { codeId: ch.entry.codeId, reason });
  }

  /** A timeout or a dropped connection: the slot is refunded. */
  private endChannel(key: string, reason: string, tellRelay: boolean): void {
    const ch = this.channels.get(key);
    if (!ch) return;
    clearTimeout(ch.timer);
    this.channels.delete(key);
    ch.entry.inFlight--;
    if (ch.claimed) ch.entry.claimed = false;
    if (tellRelay) this.relay.sendControl({ type: 'pairEnd', channel: key });
    this.emit('pairingFailed', { codeId: ch.entry.codeId, reason });
  }
}
