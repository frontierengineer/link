// A member of a network: one relay connection, sessions with the other
// members, the roster it holds, and the application's message stream.

import { DIAGNOSTICS, type CoreStats, type DiagnosticsHook, type DiagnosticsReport } from './diag-hook.js';
import { ClosedError, InvalidError, ReplacedError, RevokedError, TimeoutError, UnreachableError, type LinkError } from './errors.js';
import { Emitter } from './events.js';
import { decodeFrame, encodeFrame, FRAME_HEADER, FrameType, type SessionMessage } from './frames.js';
import { nodeIdFromBytes, nodeIdToBytes, type Identity } from './identity.js';
import { canonicalize } from './jcs.js';
import { RelayConnection, type RelayState } from './relay.js';
import { acceptanceProblem, cloneRoster, findMember, isValidRoster, type Roster } from './roster.js';
import { DEFAULT_CREDIT_WINDOW, DEFAULT_SESSION_TIMING, INITIAL_CREDIT, SessionManager, type SessionTiming } from './sessions.js';
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
  /** Defaults to `roster.relay`. */
  relayUrl?: string;
  /** The primary key pinned at pairing; defaults to `roster.primary.ed25519`. */
  pinnedPrimary?: string;
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
  /** Clock, for tests. */
  now?: () => number;
}

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
};

function mapState(s: RelayState): MemberState {
  return s === 'registered' ? 'connected' : s;
}

export class Member<E extends MemberEvents = MemberEvents> extends Emitter<E> {
  readonly identity: Identity;
  protected currentRoster: Roster;
  protected readonly pinnedPrimary: string;
  protected readonly relay: RelayConnection;
  protected readonly sessions: SessionManager;
  protected readonly timing: Timing;
  protected readonly now: () => number;
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
  /** Installed by the diagnostics entry point; checked once per send and per receive. */
  protected diag: DiagnosticsHook | undefined;

  /** Creates the member and starts connecting; see also `Member.connect`. */
  constructor(opts: MemberOptions) {
    super();
    if (!isValidRoster(opts.roster)) throw new InvalidError('the roster is not valid');
    if (!findMember(opts.roster, opts.identity.id)) throw new InvalidError('this identity is not on the roster');
    this.identity = opts.identity;
    this.currentRoster = cloneRoster(opts.roster);
    this.pinnedPrimary = opts.pinnedPrimary ?? opts.roster.primary.ed25519;
    if (this.pinnedPrimary !== opts.roster.primary.ed25519) throw new InvalidError('the roster is not signed by the pinned primary');
    this.timing = { ...DEFAULT_TIMING, ...opts.timing };
    this.now = opts.now ?? Date.now;
    const creditWindow = opts.creditWindow ?? DEFAULT_CREDIT_WINDOW;
    if (!Number.isInteger(creditWindow) || creditWindow < INITIAL_CREDIT || creditWindow > 0xffffffff) {
      throw new InvalidError('creditWindow must be an integer from 1 MiB to 2^32 - 1');
    }
    this.relay = new RelayConnection({
      url: opts.relayUrl ?? opts.roster.relay,
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
      now: this.now,
      creditWindow,
      timing: this.timing,
      sendFrame: (type, peer, body) => this.sendFrame(type, peer, body),
      writable: () => this.relay.writable,
      whenWritable: (f) => this.relay.whenWritable(f),
      bufferedAmount: () => this.relay.bufferedAmount,
      note: (e) => this.diag?.event(e),
      deliver: (from, bytes, release) => this.deliver({ from, bytes }, release),
      control: (from, msg) => this.onSessionControl(from, msg),
      peerVersion: (from, version) => this.onPeerVersion(from, version),
    });
    this.trafficSince = this.now();
    this.relay.on('state', (s) => this.onRelayState(s));
    this.relay.on('disconnect', (d) => this.emitAny('disconnect', d));
    this.relay.on('moved', (m) => this.emitAny('moved', m));
    this.relay.on('registered', (msg) => {
      // Section 4.1: the relay returns its newer roster when this member presented an older one.
      if (msg.roster !== undefined) this.offerRoster(msg.roster);
      // A relay that keeps only a compact record of a newer roster says so without sending it;
      // the primary, or the first up-to-date peer met (onPeerVersion), hands it over.
      else if (typeof msg.rosterVersion === 'number' && msg.rosterVersion > this.currentRoster.version) {
        queueMicrotask(() => this.askPrimary());
      }
    });
    this.relay.on('control', (msg) => this.onControl(msg));
    this.relay.on('binary', (b) => this.onBinary(b));
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
    const began = diag ? this.now() : 0;
    try {
      await this.online();
      await this.sessions.send(peerId, bytes);
    } catch (e) {
      if (diag) {
        if (e instanceof UnreachableError) diag.event({ kind: 'unreachable', peer: peerId });
        diag.sent(peerId, bytes.length, this.now() - began, true);
      }
      throw e;
    }
    const t = this.peerTraffic(peerId).sent;
    t.messages++;
    t.bytes += bytes.length;
    this.trafficTotal.sent.messages++;
    this.trafficTotal.sent.bytes += bytes.length;
    if (diag) diag.sent(peerId, bytes.length, this.now() - began, false);
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
    if (this.id === this.network) return false;
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
      await this.sessions.sendControl(this.network, { type: 'roster-request' }).catch(() => undefined);
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
    if (this.id === this.network) throw new InvalidError('the primary cannot resign');
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
      await this.sessions.sendControl(this.network, { type: 'resign', json: JSON.stringify(r) }).catch(() => undefined);
      await Promise.race([settled, new Promise((t) => setTimeout(t, retry))]);
    }
    return done;
  }

  close(): void {
    if (this.relay.state === 'closed') return;
    this.relay.close();
    this.sessions.close();
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
    if (this.relay.terminal) {
      this.sessions.close();
      for (const r of this.readers.splice(0)) r({ value: undefined, done: true });
    }
    this.onConnectionState(s);
    this.emitAny('state', mapState(s));
    for (const w of this.stateWaiters.splice(0)) w();
  }

  /** Hook for the primary. */
  protected onConnectionState(_s: RelayState): void {}

  protected onControl(msg: ControlMessage): void {
    if (msg.type === 'error') {
      const e: { code: string; message?: string; id?: string } = { code: String(msg.code) };
      if (typeof msg.message === 'string') e.message = msg.message;
      if (typeof msg.id === 'string') e.id = msg.id;
      this.emitAny('relayError', e);
    }
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

  /** Hook for the primary. */
  protected onPairFrame(_channel: Uint8Array, _body: Uint8Array): void {}

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
        this.sessions
          .sendControl(from, { type: 'roster', json: canonicalize(this.currentRoster) })
          .catch(() => undefined);
        return;
      case 'roster': {
        let candidate: unknown;
        try {
          candidate = JSON.parse(msg.json);
        } catch {
          return;
        }
        this.offerRoster(candidate);
        for (const w of this.rosterWaiters.splice(0)) w();
        return;
      }
      case 'resign':
        this.onResign(from, msg.json);
        return;
      default:
        return;
    }
  }

  /** Hook for the primary. */
  protected onResign(_from: string, _json: string): void {}

  /** Applies section 3 acceptance. Returns true when the roster was taken. */
  protected offerRoster(candidate: unknown): boolean {
    if (acceptanceProblem(candidate, this.pinnedPrimary, this.currentRoster.version) !== null) return false;
    this.adoptRoster(candidate as Roster);
    return true;
  }

  protected adoptRoster(r: Roster): void {
    this.currentRoster = cloneRoster(r);
    this.sessions.rosterChanged();
    this.emitAny('roster', cloneRoster(r));
    if (!findMember(r, this.id)) this.relay.revoke();
  }

  /**
   * Rosters spread member to member (section 7.1). A peer holding a newer roster is asked for
   * it: any member answers with the newest it holds, and a roster is taken only if the pinned
   * primary signed it, so the peer need not be trusted. A peer that is behind, and still on this
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
      this.sessions.sendControl(from, { type: 'roster', json: canonicalize(this.currentRoster) }).catch(() => undefined);
    }
  }

  private askPrimary(): void {
    if (this.id === this.network) return;
    this.sessions.sendControl(this.network, { type: 'roster-request' }).catch(() => undefined);
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
