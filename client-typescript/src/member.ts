// A member of a network: one relay connection, sessions with the other
// members, the roster it holds, and the application's message stream. Any
// member may be the primary (section 3.1): while it holds the network seed and
// its roster names it primary, it acts as one, on the same connection.

import { DIAGNOSTICS, type CoreStats, type DiagnosticsHook, type DiagnosticsReport } from './diag-hook.js';
import { b64u } from './bytes.js';
import { ClosedError, InvalidError, ReplacedError, RevokedError, TimeoutError, UnreachableError, type LinkError } from './errors.js';
import { Emitter } from './events.js';
import { decodeFrame, encodeFrame, FRAME_HEADER, FrameType, type SessionMessage } from './frames.js';
import { networkKeyFromSeed, nodeIdFromBytes, nodeIdToBytes, type Identity, type NetworkKey } from './identity.js';
import { integerMember, parseJson } from './json.js';
import { RelayConnection, type RelayState } from './relay.js';
import { PrimaryRole, type PairingCode, type UsageReport } from './primary-role.js';
import {
  acceptanceProblem,
  cloneRoster,
  findMember,
  isValidRoster,
  primaryOf,
  signNextRoster,
  type Roster,
  type RosterMember,
} from './roster.js';
import { Bucket, DEFAULT_CREDIT_WINDOW, DEFAULT_SESSION_TIMING, INITIAL_CREDIT, SessionManager, type SessionTiming } from './sessions.js';
import { signResignation } from './signed.js';
import { chooseSocket, type ControlMessage, type WebSocketConstructor, type WebSocketStreamConstructor } from './socket.js';

export interface Timing extends SessionTiming {
  /** First reconnect delay (500 ms), doubling... */
  backoffInitialMs: number;
  /** ...to at most this (10 s). */
  backoffMaxMs: number;
  /** How long relay requests (usage, roster sync, resign) wait for an answer (10 s). */
  requestTimeoutMs: number;
}

export const DEFAULT_TIMING: Timing = {
  ...DEFAULT_SESSION_TIMING,
  backoffInitialMs: 500,
  backoffMaxMs: 10_000,
  requestTimeoutMs: 10_000,
};

export interface MemberOptions {
  identity: Identity;
  /** The newest roster this member holds (persist it from the `roster` event). */
  roster: Roster;
  /** Defaults to `roster.relay`. A roster whose network is not placed yet has none (`''`): a
   * member of it needs this, or it is not started (InvalidError). */
  relayUrl?: string;
  /** The network key pinned at pairing; defaults to `roster.networkKey`. */
  pinnedNetworkKey?: string;
  /**
   * The network seed, for the node its application wants to be the primary (section 3.1); it
   * must derive `roster.networkKey`. Its custody is the application's: the member never stores,
   * sends or deletes it. When the roster names another member primary, this node claims the
   * primary once registered.
   */
  networkSeed?: Uint8Array;
  /** A WHATWG WebSocket constructor. When given, it is used as is. */
  WebSocket?: WebSocketConstructor;
  /** A WHATWG WebSocketStream constructor, for real back-pressure. Without either option, a
   * member uses globalThis.WebSocketStream where it exists and globalThis.WebSocket otherwise. */
  WebSocketStream?: WebSocketStreamConstructor;
  /** The receive window this member grants each session: 1 MiB (the initial credit) or more. */
  creditWindow?: number;
  timing?: Partial<Timing>;
  /** On close code 4009: where the network lives now. */
  resolveRelay?: (network: string) => Promise<string | undefined>;
  /** Wall clock, Unix milliseconds, for tests: signed times (`ts`, `issuedAt`) and expiry shown to
   * the application. */
  now?: () => number;
  /** Monotonic clock, milliseconds, for tests: every rate, interval and timeout (section 7.4).
   * Defaults to `performance.now()`. A reading earlier than the last is held at the last, so a
   * budget is never stranded by a clock that steps back. */
  monotonicNow?: () => number;
}

/** A clock that never goes back: a reading earlier than the last is the last. */
export function monotonic(read: () => number): () => number {
  let last = -Infinity;
  return () => {
    const t = read();
    if (t > last) last = t;
    return last;
  };
}

/** A roster goes to one peer, asked for or pushed, at most once in this long; offers within it
 * are coalesced into one at its end (section 7.4). A roster can be 65000 bytes; a request, or a
 * replayed handshake-init showing an old version, is small. */
export const ROSTER_ANSWER_INTERVAL_MS = 250;

/** `relayError` events: this many a second, this many at once (section 11). */
export const RELAY_ERROR_RATE = 16;
export const RELAY_ERROR_BURST = 64;

export type MemberState = 'connecting' | 'connected' | 'disconnected' | 'revoked' | 'replaced' | 'closed';

export interface InboundMessage {
  from: string;
  bytes: Uint8Array;
}

/** Counts in one direction. */
export interface Traffic {
  /** Whole application messages, and their payload bytes. */
  messages: number;
  bytes: number;
  /** Routed frames of every type (handshakes, credit and control included) and their full size,
   * header included: what the relay charges. Pairing frames are not counted. */
  frames: number;
  frameBytes: number;
}

export interface PeerTraffic {
  sent: Traffic;
  received: Traffic;
}

/** `member.traffic()`: what this member sent and received since `since`, per peer and in total. */
export interface TrafficReport {
  /** Unix milliseconds the counts start from (creation, or the last `resetTraffic`). */
  since: number;
  total: PeerTraffic;
  /** UTF-8 bytes of control messages exchanged with the relay. */
  relay: { sent: number; received: number };
  peers: Record<string, PeerTraffic>;
}

/** How the relay shapes this member's network (section 9), from its `shaping` notices. */
export interface Shaping {
  /** The rate in force, bytes a second: the network's rate, or its trickle rate once its quota
   * is spent; 0 for none. Sends are paced to it. */
  rateBps: number;
  /** The quota is spent and the trickle rate is in force: send less (drop video, keep audio). */
  slowed: boolean;
}

const UNSHAPED: Shaping = { rateBps: 0, slowed: false };

const zeroTraffic = (): Traffic => ({ messages: 0, bytes: 0, frames: 0, frameBytes: 0 });
const zeroPeer = (): PeerTraffic => ({ sent: zeroTraffic(), received: zeroTraffic() });
const copyPeer = (p: PeerTraffic): PeerTraffic => ({ sent: { ...p.sent }, received: { ...p.received } });

export type MemberEvents = {
  state: MemberState;
  /** A newer roster was accepted. Persist it. */
  roster: Roster;
  /** The relay closed the connection (any code). */
  disconnect: { code: number; reason: string };
  /** 4009: the network moved to another relay node. */
  moved: { network: string };
  /** A non-fatal `error` control message from the relay. */
  relayError: { code: string; message?: string; id?: string };
  /** The relay shapes the network differently: slowed (its quota spent), no longer slowed, or
   * at another rate. `member.shaping` holds the latest. */
  shaping: Shaping;
  /** A newcomer completed pairing and is on the published roster (the primary only). `codeId`
   * is the code that admitted it: an application that labels its members does so by code. */
  paired: { member: RosterMember; codeId: string; roster: Roster };
  /** A pairing attempt ended without a new member (the primary only). */
  pairingFailed: { codeId: string; reason: string };
};

/** Why a primary's pairing channels end when it stops being the primary. */
export const DEMOTED_REASON = 'another member is the primary now';

function mapState(s: RelayState): MemberState {
  return s === 'registered' ? 'connected' : s;
}

export class Member<E extends MemberEvents = MemberEvents> extends Emitter<E> {
  readonly identity: Identity;
  protected currentRoster: Roster;
  protected readonly pinnedNetworkKey: string;
  /** The network key, when this node was given the network seed. */
  private readonly netKey: NetworkKey | undefined;
  /** Being the primary, while this node is (section 3.1). */
  private prim: PrimaryRole | undefined;
  /** Started with the seed while the roster names another primary: it claims at registration. */
  private claimPending: boolean;
  protected readonly relay: RelayConnection;
  protected readonly sessions: SessionManager;
  protected readonly timing: Timing;
  protected readonly now: () => number;
  /** For every rate, interval and timeout: never the wall clock, which can step back. */
  protected readonly mono: () => number;
  private readonly inbox: { msg: InboundMessage; release: () => void }[] = [];
  private handler: ((m: InboundMessage) => void) | undefined;
  private readers: ((r: IteratorResult<InboundMessage>) => void)[] = [];
  private stateWaiters: (() => void)[] = [];
  private rosterWaiters: (() => void)[] = [];
  private trafficSince: number;
  private trafficTotal = zeroPeer();
  private trafficPeers = new Map<string, PeerTraffic>();
  private relayTextBase = { sent: 0, received: 0 };
  private wasRegistered = false;
  private shapingNow: Shaping = UNSHAPED;
  /** Budget for `relayError` events, so a relay's errors cannot flood the application. */
  private readonly relayErrors = new Bucket(RELAY_ERROR_RATE, RELAY_ERROR_BURST);
  /** Per peer: when a roster last went to it, and an offer due at the interval's end. */
  private readonly rosterAnswers = new Map<string, { at: number; due: ReturnType<typeof setTimeout> | undefined }>();
  /** Installed by the diagnostics entry point; checked once per send and per receive. */
  protected diag: DiagnosticsHook | undefined;

  /** Creates the member and starts connecting; see also `Member.connect`. */
  constructor(opts: MemberOptions) {
    super();
    if (!isValidRoster(opts.roster)) throw new InvalidError('the roster is not valid');
    if (!findMember(opts.roster, opts.identity.id)) throw new InvalidError('this identity is not on the roster');
    this.identity = opts.identity;
    this.currentRoster = cloneRoster(opts.roster);
    this.pinnedNetworkKey = opts.pinnedNetworkKey ?? opts.roster.networkKey;
    if (this.pinnedNetworkKey !== opts.roster.networkKey) throw new InvalidError('the roster is not signed by the pinned network key');
    if (opts.networkSeed !== undefined) {
      if (!(opts.networkSeed instanceof Uint8Array) || opts.networkSeed.length !== 32) throw new InvalidError('networkSeed must be 32 bytes');
      const key = networkKeyFromSeed(opts.networkSeed);
      if (b64u(key.ed25519.pub) !== opts.roster.networkKey) throw new InvalidError("networkSeed does not derive the roster's networkKey");
      this.netKey = key;
    }
    this.claimPending = this.netKey !== undefined && primaryOf(opts.roster).id !== opts.identity.id;
    this.timing = { ...DEFAULT_TIMING, ...opts.timing };
    this.now = opts.now ?? Date.now;
    this.mono = monotonic(opts.monotonicNow ?? (() => performance.now()));
    const creditWindow = opts.creditWindow ?? DEFAULT_CREDIT_WINDOW;
    if (!Number.isInteger(creditWindow) || creditWindow < INITIAL_CREDIT || creditWindow > 0xffffffff) {
      throw new InvalidError('creditWindow must be an integer from 1 MiB to 2^32 - 1');
    }
    // An unplaced network (section 3.2) has no relay to dial: a member of one is not started
    // unless it is given a relay URL itself.
    const url = opts.relayUrl ?? opts.roster.relay;
    if (url === '') throw new InvalidError('the network has no relay yet: place it (placeNetwork), or give relayUrl');
    try {
      new URL(url);
    } catch {
      throw new InvalidError(`the relay URL ${JSON.stringify(url)} is not a URL`);
    }
    this.relay = new RelayConnection({
      url,
      identity: opts.identity,
      roster: () => this.currentRoster,
      WebSocket: chooseSocket({ WebSocket: opts.WebSocket, WebSocketStream: opts.WebSocketStream }),
      now: this.now,
      backoffInitialMs: this.timing.backoffInitialMs,
      backoffMaxMs: this.timing.backoffMaxMs,
      resolveRelay: opts.resolveRelay,
    });
    this.sessions = new SessionManager({
      identity: opts.identity,
      roster: () => this.currentRoster,
      now: this.mono,
      wallNow: this.now,
      creditWindow,
      timing: this.timing,
      sendFrame: (type, peer, body) => this.sendFrame(type, peer, body),
      writable: () => this.relay.writable,
      whenWritable: (f) => this.relay.whenWritable(f),
      bufferedAmount: () => this.relay.bufferedAmount,
      wirePosition: () => this.relay.wirePosition,
      note: (e) => this.diag?.event(e),
      deliver: (from, bytes, release) => this.deliver({ from, bytes }, release),
      control: (from, msg) => this.onSessionControl(from, msg),
      peerVersion: (from, version) => this.onPeerVersion(from, version),
      rosterHint: () => this.askPrimary(),
    });
    this.trafficSince = this.now();
    this.relay.on('state', (s) => this.onRelayState(s));
    this.relay.on('disconnect', (d) => this.emitAny('disconnect', d));
    this.relay.on('moved', (m) => this.emitAny('moved', m));
    this.relay.on('registered', (msg) => {
      // A relay without the feature never says: this network is taken as unshaped there.
      if (!this.relay.features.has('shaping')) this.setShaping(UNSHAPED);
      // Section 4.1: the relay returns its newer roster when this member presented an older one.
      if (msg.roster !== undefined) this.offerRoster(msg.roster);
      // A relay that keeps only a compact record of a newer roster says so without sending it;
      // the primary, or the first up-to-date peer met (onPeerVersion), hands it over.
      else if ((integerMember(msg, 'rosterVersion') ?? 0) > this.currentRoster.version) {
        queueMicrotask(() => this.askPrimary());
      }
    });
    this.relay.on('control', (msg) => this.onControl(msg));
    this.relay.on('binary', (b) => this.onBinary(b));
    this.syncRole();
    // Started after construction completes, so subclass fields exist before the first event.
    queueMicrotask(() => this.relay.start());
  }

  /** Creates a member and resolves once it is registered with the relay. */
  static async connect(opts: MemberOptions): Promise<Member> {
    const m = new Member(opts);
    await m.waitConnected();
    return m;
  }

  get id(): string {
    return this.identity.id;
  }

  get network(): string {
    return this.currentRoster.network;
  }

  /** A copy of the newest roster held. */
  get roster(): Roster {
    return cloneRoster(this.currentRoster);
  }

  get state(): MemberState {
    return mapState(this.relay.state);
  }

  get relayUrl(): string {
    return this.relay.relayUrl;
  }

  /** How the relay shapes this network now, from its last `shaping` notice: the rate in force
   * and whether the network is slowed. Unshaped before any notice. The `shaping` event says when
   * it changes, so there is no need to poll `usage` for it. */
  get shaping(): Shaping {
    return { ...this.shapingNow };
  }

  /** Whether this node is the primary now: it holds the network seed and its roster names it. */
  get isPrimary(): boolean {
    return this.prim !== undefined;
  }

  // ── The primary's operations (section 3.1): InvalidError unless this node is the primary ──

  /**
   * Opens a code that admits one node for 15 minutes. The code is random unless `code` gives
   * one (any spelling `normalizeCode` accepts): a chosen code is easier to say and easier to
   * guess, and like every code it burns after five wrong confirmations. Without `separate` it
   * is the network's default code (id `DEFAULT_CODE_ID`, and no `i` in its link), and closes
   * the default code open before it; with `separate` it has a random id of its own and stands
   * beside the default code and any other separate code.
   */
  openPairingCode(opts: { lifetimeMs?: number; code?: string; separate?: boolean } = {}): PairingCode {
    return this.requirePrimary().openPairingCode(opts);
  }

  /** Withdraws an open code: the default code when `codeId` is not given. */
  cancelPairingCode(codeId?: string): void {
    this.prim?.cancelPairingCode(codeId);
  }

  /** Removes a member and publishes the roster. Returns the new roster. */
  revoke(nodeId: string): Roster {
    return this.requirePrimary().revoke(nodeId);
  }

  /**
   * Asks the relay for this network's usage. The relay allows one ask per USAGE_INTERVAL_MS
   * (10 s) per network, with no burst; an ask sooner than that it refuses at once, and this
   * rejects with RateLimitedError. Ask rarely, and keep the answer; whether the network is
   * slowed is `shaping`, which needs no ask.
   */
  usage(): Promise<UsageReport> {
    if (!this.prim) return Promise.reject(new InvalidError('this node is not the primary'));
    return this.prim.usage();
  }

  /**
   * Resolves when registered with the relay. Rejects with RevokedError,
   * ReplacedError or ClosedError if the member reaches a terminal state, and with TimeoutError
   * after `timeoutMs` when given.
   */
  waitConnected(timeoutMs?: number): Promise<void> {
    return new Promise((resolve, reject) => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const check = (): boolean => {
        const s = this.state;
        if (s === 'connected') resolve();
        else if (s === 'revoked') reject(new RevokedError());
        else if (s === 'replaced') reject(new ReplacedError());
        else if (s === 'closed') reject(new ClosedError());
        else return false;
        clearTimeout(timer);
        return true;
      };
      if (check()) return;
      const waiter = () => {
        if (!check()) this.stateWaiters.push(waiter);
      };
      this.stateWaiters.push(waiter);
      if (timeoutMs !== undefined) {
        timer = setTimeout(() => {
          this.stateWaiters = this.stateWaiters.filter((w) => w !== waiter);
          reject(new TimeoutError('connecting to the relay'));
        }, timeoutMs);
      }
    });
  }

  /**
   * Sends one message to a member. Resolves once every fragment is handed to
   * the relay connection. Rejects with UnreachableError, RefusedError,
   * RevokedError, ReplacedError, TimeoutError, ClosedError or InvalidError.
   */
  async send(peerId: string, bytes: Uint8Array): Promise<void> {
    if (!(bytes instanceof Uint8Array)) throw new InvalidError('bytes must be a Uint8Array');
    const diag = this.diag;
    if (diag) diag.send(peerId, bytes); // `throw` mode fails the send here, before anything goes out
    const began = diag ? this.mono() : 0;
    try {
      await this.online();
      await this.sessions.send(peerId, bytes);
    } catch (e) {
      if (diag) {
        if (e instanceof UnreachableError) diag.event({ kind: 'unreachable', peer: peerId });
        diag.sent(peerId, bytes.length, this.mono() - began, true);
      }
      throw e;
    }
    const t = this.peerTraffic(peerId).sent;
    t.messages++;
    t.bytes += bytes.length;
    this.trafficTotal.sent.messages++;
    this.trafficTotal.sent.bytes += bytes.length;
    if (diag) diag.sent(peerId, bytes.length, this.mono() - began, false);
  }

  /** What this member sent and received, per peer and in total, since creation or `resetTraffic()`. */
  traffic(): TrafficReport {
    const peers: Record<string, PeerTraffic> = {};
    for (const [id, p] of this.trafficPeers) peers[id] = copyPeer(p);
    return {
      since: this.trafficSince,
      total: copyPeer(this.trafficTotal),
      relay: { sent: this.relay.textSent - this.relayTextBase.sent, received: this.relay.textReceived - this.relayTextBase.received },
      peers,
    };
  }

  resetTraffic(): void {
    this.trafficSince = this.now();
    this.trafficTotal = zeroPeer();
    this.trafficPeers.clear();
    this.relayTextBase = { sent: this.relay.textSent, received: this.relay.textReceived };
  }

  /** The diagnostics report, when `enableDiagnostics` (from `@frontierengineer/link-client/diagnostics`) is on. */
  diagnostics(): DiagnosticsReport | undefined {
    return this.diag?.report(this.coreStats());
  }

  resetDiagnostics(): void {
    this.diag?.reset();
  }

  /** Installs or removes the diagnostics hook; used by the diagnostics entry point only. */
  [DIAGNOSTICS](hook: DiagnosticsHook | undefined): void {
    this.diag = hook;
  }

  protected coreStats(): CoreStats {
    return { ...this.sessions.stats };
  }

  private peerTraffic(id: string): PeerTraffic {
    let p = this.trafficPeers.get(id);
    if (!p) this.trafficPeers.set(id, (p = zeroPeer()));
    return p;
  }

  /**
   * Delivers every message to `handler` as it arrives (and drains any already
   * waiting). Returns a function that removes the handler.
   */
  onMessage(handler: (m: InboundMessage) => void): () => void {
    this.handler = handler;
    this.pump();
    return () => {
      if (this.handler === handler) this.handler = undefined;
    };
  }

  /**
   * Messages as an async stream, for one consumer. A message is credited back
   * to its sender only when taken, so a slow reader slows its senders.
   */
  get messages(): AsyncIterableIterator<InboundMessage> {
    const self = this;
    return {
      [Symbol.asyncIterator]() {
        return this;
      },
      next(): Promise<IteratorResult<InboundMessage>> {
        const item = self.inbox.shift();
        if (item) {
          item.release();
          return Promise.resolve({ value: item.msg, done: false });
        }
        if (self.isTerminal()) return Promise.resolve({ value: undefined, done: true });
        return new Promise((resolve) => self.readers.push(resolve));
      },
      return(): Promise<IteratorResult<InboundMessage>> {
        return Promise.resolve({ value: undefined, done: true });
      },
    };
  }

  /** Asks the primary for its newest roster. Resolves true when a newer one was accepted. */
  async syncRoster(): Promise<boolean> {
    if (this.id === primaryOf(this.currentRoster).id) return false;
    await this.online();
    const before = this.currentRoster.version;
    const got = this.waitForRoster(this.timing.requestTimeoutMs);
    // Delivery is at most once (a request on a session the primary lost is
    // answered with reset), so the idempotent request is repeated until answered.
    let answered = false;
    got.then(
      () => (answered = true),
      () => (answered = true),
    );
    const retry = Math.max(50, this.timing.requestTimeoutMs / 4);
    while (!answered) {
      await this.sessions.sendControl(primaryOf(this.currentRoster).id, { type: 'roster-request' }).catch(() => undefined);
      await Promise.race([got.catch(() => undefined), new Promise((r) => setTimeout(r, retry))]);
    }
    await got;
    return this.currentRoster.version > before;
  }

  /**
   * Leaves the network: sends a signed resignation to the primary and resolves
   * once the relay has closed this member (state `revoked`).
   */
  async resign(): Promise<void> {
    if (this.id === primaryOf(this.currentRoster).id) throw new InvalidError('the primary cannot resign');
    if (this.netKey) throw new InvalidError('a node started with the network seed cannot resign');
    await this.online();
    const r = signResignation(this.identity, this.network, this.now());
    const done = new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        off();
        reject(new TimeoutError('resigning'));
      }, this.timing.requestTimeoutMs);
      const off = this.on('state', (s) => {
        if (s === 'revoked') {
          clearTimeout(timer);
          off();
          resolve();
        }
      });
    });
    // Repeated until the relay closes this member, since delivery is at most once.
    let finished = false;
    const settled = done.then(
      () => (finished = true),
      () => (finished = true),
    );
    const retry = Math.max(50, this.timing.requestTimeoutMs / 4);
    while (!finished && this.state === 'connected') {
      await this.sessions.sendControl(primaryOf(this.currentRoster).id, { type: 'resign', json: JSON.stringify(r) }).catch(() => undefined);
      await Promise.race([settled, new Promise((t) => setTimeout(t, retry))]);
    }
    return done;
  }

  close(): void {
    if (this.relay.state === 'closed') return;
    this.prim?.close();
    this.relay.close();
    this.sessions.close();
    this.cancelRosterOffers(true);
  }

  // ── Internals ──

  protected emitAny<K extends keyof MemberEvents>(event: K, value: MemberEvents[K]): void {
    (this.emit as (k: K, v: MemberEvents[K]) => void)(event, value);
  }

  protected isTerminal(): boolean {
    return this.relay.terminal;
  }

  protected async online(): Promise<void> {
    if (this.relay.state === 'revoked') throw new RevokedError();
    if (this.relay.state === 'replaced') throw new ReplacedError();
    if (this.relay.state === 'closed') throw new ClosedError();
    if (this.relay.state !== 'registered') await this.waitConnected(this.timing.handshakeTimeoutMs);
  }

  protected sendFrame(type: number, peer: string, body: Uint8Array): boolean {
    // Section 6: 0x08 only to a relay that lists `control`; otherwise the same body as 0x03.
    if (type === FrameType.Control && !this.relay.features.has('control')) type = FrameType.Data;
    if (!this.relay.sendBinary(encodeFrame(type, nodeIdToBytes(peer), body))) return false;
    const size = FRAME_HEADER + body.length;
    const t = this.peerTraffic(peer).sent;
    t.frames++;
    t.frameBytes += size;
    this.trafficTotal.sent.frames++;
    this.trafficTotal.sent.frameBytes += size;
    return true;
  }

  private onRelayState(s: RelayState): void {
    if (this.diag) {
      if (s === 'connecting' && this.wasRegistered) this.diag.event({ kind: 'reconnect' });
      if (s === 'replaced') this.diag.event({ kind: 'replaced' });
    }
    if (s === 'registered') this.wasRegistered = true;
    if (s === 'connecting') {
      // Budgets carry across connections and refill only with time (section 7.4), so a relay
      // that forces reconnects gains nothing; an offer due on the old connection is dropped,
      // but when the last went to each peer is kept.
      this.cancelRosterOffers();
    }
    if (s !== 'registered') {
      const err: LinkError =
        s === 'revoked'
          ? new RevokedError()
          : s === 'replaced'
            ? new ReplacedError()
            : s === 'closed'
              ? new ClosedError()
              : new ClosedError('relay connection lost');
      this.sessions.dropAll(err);
    }
    if (s === 'registered' && this.claimPending) this.claimPrimary();
    if (this.relay.terminal) {
      this.prim?.close();
      this.sessions.close();
      this.cancelRosterOffers(true);
      for (const r of this.readers.splice(0)) r({ value: undefined, done: true });
    }
    this.onConnectionState(s);
    this.emitAny('state', mapState(s));
    for (const w of this.stateWaiters.splice(0)) w();
  }

  /** Hook for subclasses. */
  protected onConnectionState(s: RelayState): void {
    this.prim?.onConnectionState(s);
  }

  protected onControl(msg: ControlMessage): void {
    if (msg.type === 'shaping') {
      const rateBps = integerMember(msg, 'rateBps');
      if (rateBps !== undefined && typeof msg.slowed === 'boolean') this.setShaping({ rateBps, slowed: msg.slowed });
      return;
    }
    if (this.prim?.onControl(msg)) return;
    if (msg.type === 'error') {
      const e: { code: string; message?: string; id?: string } = { code: String(msg.code) };
      if (typeof msg.message === 'string') e.message = msg.message;
      if (typeof msg.id === 'string') e.id = msg.id;
      if (this.relayErrors.take(this.mono())) this.emitAny('relayError', e);
    }
  }

  private setShaping(next: Shaping): void {
    this.sessions.setRate(next.rateBps);
    if (next.rateBps === this.shapingNow.rateBps && next.slowed === this.shapingNow.slowed) return;
    this.shapingNow = { ...next };
    this.diag?.event({ kind: 'shaping', slowed: next.slowed, rateBps: next.rateBps });
    this.emitAny('shaping', { ...next });
  }

  protected onBinary(bytes: Uint8Array): void {
    let f;
    try {
      f = decodeFrame(bytes);
    } catch {
      return;
    }
    if (f.type === FrameType.Pair) return this.onPairFrame(f.peer, f.body);
    const from = nodeIdFromBytes(f.peer);
    const t = this.peerTraffic(from).received;
    t.frames++;
    t.frameBytes += bytes.length;
    this.trafficTotal.received.frames++;
    this.trafficTotal.received.frameBytes += bytes.length;
    this.sessions.handleFrame(f, from);
  }

  protected onPairFrame(channel: Uint8Array, body: Uint8Array): void {
    this.prim?.onPairFrame(channel, body);
  }

  private deliver(msg: InboundMessage, release: () => void): void {
    const t = this.peerTraffic(msg.from).received;
    t.messages++;
    t.bytes += msg.bytes.length;
    this.trafficTotal.received.messages++;
    this.trafficTotal.received.bytes += msg.bytes.length;
    if (this.diag) this.diag.received(msg.from, msg.bytes);
    this.inbox.push({ msg, release });
    this.pump();
  }

  private pump(): void {
    while (this.inbox.length > 0) {
      if (this.handler) {
        const item = this.inbox.shift()!;
        item.release();
        try {
          this.handler(item.msg);
        } catch (e) {
          // The handler's error is the application's; it must not stall delivery.
          queueMicrotask(() => {
            throw e;
          });
        }
        continue;
      }
      const reader = this.readers.shift();
      if (!reader) return;
      const item = this.inbox.shift()!;
      item.release();
      reader({ value: item.msg, done: false });
    }
  }

  private onSessionControl(from: string, msg: SessionMessage): void {
    switch (msg.type) {
      case 'roster-request':
        this.offerRosterTo(from);
        return;
      case 'roster': {
        let candidate: unknown;
        try {
          candidate = parseJson(msg.json);
        } catch {
          return;
        }
        this.offerRoster(candidate);
        for (const w of this.rosterWaiters.splice(0)) w();
        return;
      }
      case 'resign':
        this.prim?.onResign(from, msg.json);
        return;
      default:
        return;
    }
  }

  // ── The network seed (section 3.1) ──

  private requirePrimary(): PrimaryRole {
    if (!this.prim) throw new InvalidError('this node is not the primary');
    return this.prim;
  }

  /**
   * Settles what this node is after a roster change: the primary while it holds the network
   * seed and its roster names it. Stopping being the primary closes nothing but its codes and
   * pairing channels: the connection and every session stay.
   */
  private syncRole(): void {
    const named = primaryOf(this.currentRoster).id;
    const primary = this.netKey !== undefined && named === this.id;
    if (primary && !this.prim) {
      this.prim = new PrimaryRole({
        id: this.id,
        roster: () => this.currentRoster,
        networkKey: () => this.netKey!,
        relay: this.relay,
        sessions: this.sessions,
        timing: this.timing,
        now: () => this.now(),
        mono: () => this.mono(),
        diag: () => this.diag,
        adopt: (r) => this.adoptRoster(r),
        online: () => this.online(),
        isTerminal: () => this.isTerminal(),
        emit: (event, value) => this.emitAny(event, value),
      });
    } else if (!primary && this.prim) {
      const role = this.prim;
      this.prim = undefined;
      role.stop(DEMOTED_REASON);
    }
  }

  /**
   * Claims the primary (section 3.1), once, at the first registration of a node started with
   * the network seed while its roster names another member primary: the next roster names this
   * node primary, nothing else changed, and is published as any change.
   */
  private claimPrimary(): void {
    this.claimPending = false;
    const r = this.currentRoster;
    if (!this.netKey || r.primary === this.id) return;
    this.adoptRoster(signNextRoster(r, r.members, this.netKey, this.now(), this.id));
    this.prim?.republish();
  }

  /** Sends a peer this member's roster (it asked, or a handshake showed it behind) at once, or
   * once at the end of ROSTER_ANSWER_INTERVAL_MS after the last, however often meanwhile. */
  private offerRosterTo(from: string): void {
    const now = this.mono();
    const a = this.rosterAnswers.get(from);
    if (a?.due !== undefined) return;
    if (a && now - a.at < ROSTER_ANSWER_INTERVAL_MS) {
      a.due = setTimeout(() => {
        a.due = undefined;
        a.at = this.mono();
        this.sendRoster(from);
      }, a.at + ROSTER_ANSWER_INTERVAL_MS - now);
      (a.due as { unref?: () => void }).unref?.();
      return;
    }
    this.rosterAnswers.set(from, { at: now, due: undefined });
    this.sendRoster(from);
  }

  /** Drops offers due; `forget` also drops when the last went (on close). */
  private cancelRosterOffers(forget = false): void {
    for (const a of this.rosterAnswers.values()) {
      clearTimeout(a.due);
      a.due = undefined;
    }
    if (forget) this.rosterAnswers.clear();
  }

  /** Sends the newest roster held to a peer; never a second while one is still unsent to it. */
  protected sendRoster(to: string): void {
    this.sessions.sendRoster(to, this.currentRoster).catch(() => undefined);
  }

  /** Applies section 3 acceptance. Returns true when the roster was taken. */
  protected offerRoster(candidate: unknown): boolean {
    if (acceptanceProblem(candidate, this.pinnedNetworkKey, this.currentRoster.version) !== null) return false;
    this.adoptRoster(candidate as Roster);
    return true;
  }

  protected adoptRoster(r: Roster): void {
    this.currentRoster = cloneRoster(r);
    this.sessions.rosterChanged();
    this.syncRole();
    this.emitAny('roster', cloneRoster(r));
    if (!findMember(r, this.id)) this.relay.revoke();
  }

  /**
   * Rosters spread member to member (section 7.1). A peer holding a newer roster is asked for
   * it: any member answers with the newest it holds, and a roster is taken only if the pinned
   * network key signed it, so the peer need not be trusted. A peer that is behind, and still on this
   * member's roster, is handed this one. So a change, a revocation above all, reaches every
   * member that meets one which has it: no need for the primary to be online, nor for the relay
   * to remember.
   */
  private onPeerVersion(from: string, version: number): void {
    const mine = this.currentRoster.version;
    if (version > mine) {
      // The primary is the fallback, for a peer this member cannot open a session to.
      this.sessions.sendControl(from, { type: 'roster-request' }).catch(() => this.askPrimary());
    } else if (version < mine && from !== this.id && findMember(this.currentRoster, from)) {
      // Coalesced like an answer: a relay may replay one genuine handshake-init carrying an old
      // version as often as it likes (message 1 has no replay protection).
      this.offerRosterTo(from);
    }
  }

  private askPrimary(): void {
    const primary = primaryOf(this.currentRoster).id;
    if (this.id === primary) return;
    this.sessions.sendControl(primary, { type: 'roster-request' }).catch(() => undefined);
  }

  private waitForRoster(timeoutMs: number): Promise<void> {
    return new Promise((resolve, reject) => {
      const w = () => {
        clearTimeout(timer);
        resolve();
      };
      const timer = setTimeout(() => {
        this.rosterWaiters = this.rosterWaiters.filter((x) => x !== w);
        reject(new TimeoutError('roster request'));
      }, timeoutMs);
      this.rosterWaiters.push(w);
    });
  }
}
