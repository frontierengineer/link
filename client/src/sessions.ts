// Sessions (section 7): Noise IK handshakes keyed by roster x25519 keys,
// transport with receiver indices, rekeying, idle expiry, and the session
// message layer (fragmentation and credit flow control).
//
// Two lanes share the relay socket. Control (handshakes, refused, reset and
// session messages other than `message`) is encrypted and handed over at once.
// Message fragments wait in a gate until the socket is short, the session's
// un-credited bytes are within its pace, and credit allows; only then is a
// fragment encrypted, in the same synchronous step that hands it to the socket.
// Wire order is therefore nonce order, and control can pass queued data without
// breaking Noise's implicit counter.
//
// Credit and reassembly belong to one Noise session, and a message is never
// split across two sessions: a rekey switches at a message boundary, and a
// retired session lives past its 30 s grace while a message still uses it.
// Every session starts with 1 MiB of credit each way; a larger `creditWindow`
// is granted as extra credit as soon as the session is up.

import { EMPTY, readU32be, readU64be, u32be, u64be, utf8, fromB64uLen, randomBytes } from './bytes.js';
import type { CoreStats, DiagnosticsEvent } from './diag-hook.js';
import { ClosedError, InvalidError, LinkError, RefusedError, TimeoutError, UnreachableError } from './errors.js';
import {
  dataBody,
  decodeSessionMessage,
  encodeSessionMessage,
  FrameType,
  handshakeInitBody,
  handshakeRespBody,
  parseData,
  parseHandshakeInit,
  parseHandshakeResp,
  RefusedReason,
  type Frame,
  type SessionMessage,
} from './frames.js';
import type { Identity } from './identity.js';
import { CipherState, HandshakeState, PATTERNS } from './noise.js';
import { findMember, type Roster } from './roster.js';

export const MAX_MESSAGE = 64 * 1024 * 1024;
/** One transport plaintext: a Noise message is at most 65535 bytes, 16 of them the tag (section 7.2). */
export const MAX_PLAINTEXT = 65535 - 16;
export const MAX_FRAGMENT = MAX_PLAINTEXT - 2;
/** Credit every session starts with, in each direction (section 7.3). */
export const INITIAL_CREDIT = 1024 * 1024;
export const DEFAULT_CREDIT_WINDOW = INITIAL_CREDIT;
/** Owed credit is returned at once from this much (section 7.3)... */
export const CREDIT_BATCH_BYTES = 65536;
/** ...and otherwise this long after it began to be owed. */
export const CREDIT_DELAY_MS = 250;
/** A session may have at least this many message bytes un-credited, or one and a half times
 * what was credited back over the last second if more: about 1.5 s of what the receiver takes.
 * Not below CREDIT_BATCH_BYTES, so a receiver always owes enough to answer at once. */
export const PACE_FLOOR_BYTES = 65536;
/** The smallest fragment the pace cuts a message into. */
export const PACE_MIN_FRAGMENT = 16384;

export interface SessionTiming {
  /** Handshake timeout per message (10 s). */
  handshakeTimeoutMs: number;
  /** Initiator rekeys after this long (10 min). */
  rekeyIntervalMs: number;
  /** ...or after this many messages in either direction (2^32). */
  rekeyMessages: number;
  /** Previous session's keys are kept this long after a rekey (30 s); a responder also
   * treats a session older than rekeyIntervalMs + retireGraceMs as expired, except while a
   * message is still crossing it, which always completes first. */
  retireGraceMs: number;
  /** A session with no frame in either direction this long is forgotten (10 min). */
  idleMs: number;
}

export const DEFAULT_SESSION_TIMING: SessionTiming = {
  handshakeTimeoutMs: 10_000,
  rekeyIntervalMs: 10 * 60_000,
  rekeyMessages: 2 ** 32,
  retireGraceMs: 30_000,
  idleMs: 10 * 60_000,
};

export function sessionPrologue(network: string): Uint8Array {
  return utf8(`frontier-link/1/session${network}`);
}

export interface SessionHost {
  identity: Identity;
  roster(): Roster;
  now(): number;
  /** The receive window this side grants; at least INITIAL_CREDIT. */
  creditWindow: number;
  timing: SessionTiming;
  /** Hands a frame to the relay; false when not connected. Control is sent as FrameType.Control. */
  sendFrame(type: number, peer: string, body: Uint8Array): boolean;
  /** Data may be handed to the socket now (little waits in it, or it is gone and a send fails at once). */
  writable(): boolean;
  /** Calls `f` once data may be handed to the socket again. */
  whenWritable(f: () => void): void;
  /** Bytes waiting in the socket. */
  bufferedAmount(): number;
  /** Tells an installed diagnostics hook. */
  note(e: DiagnosticsEvent): void;
  /** A complete message; call `release` once the application has taken it. */
  deliver(from: string, bytes: Uint8Array, release: () => void): void;
  /** roster-request, roster or resign from a peer. */
  control(from: string, msg: SessionMessage): void;
  /** The peer reported (in a handshake payload) a roster version. */
  peerVersion(from: string, version: number): void;
}

/** A message fragment waiting in the gate. `run` encrypts and hands it over, synchronously. */
interface GateEntry {
  s: Session;
  /** An empty message needs no credit. */
  empty: boolean;
  run: () => void;
  fail: (e: unknown) => void;
}

class Session {
  readonly createdAt: number;
  lastActivity: number;
  sent = 0;
  received = 0;
  ended = false;
  endError: LinkError | undefined;
  retired = false;
  /** Outbound messages currently bound to this session. */
  activeSends = 0;
  /** Bytes this side may still send. */
  sendCredit: number;
  /** Message bytes sent and not yet credited back (credit beyond that, a larger window, is not carried). */
  inflight = 0;
  /** Credit applied to `inflight`, in one-second buckets: the receiver's take rate. */
  rateAt: number;
  rateCur = 0;
  ratePrev = 0;
  creditTimer: ReturnType<typeof setTimeout> | undefined;
  // Receive side.
  partial: Uint8Array[] = [];
  partialLen = 0;
  partialCredited = 0;
  /** Complete messages handed to the application and not yet taken. */
  held = 0;
  owed = 0;

  constructor(
    readonly peer: string,
    readonly localIndex: number,
    readonly remoteIndex: number,
    readonly initiator: boolean,
    readonly send: CipherState,
    readonly recv: CipherState,
    now: number,
  ) {
    this.createdAt = now;
    this.lastActivity = now;
    this.rateAt = now;
    this.sendCredit = INITIAL_CREDIT;
  }
}

interface PendingInit {
  peer: string;
  localIndex: number;
  hs: HandshakeState;
  timer: ReturnType<typeof setTimeout>;
  waiters: { resolve: (s: Session) => void; reject: (e: LinkError) => void }[];
}

interface PeerState {
  current: Session | undefined;
  sessions: Set<Session>;
  pending: PendingInit | undefined;
  /** Serialises outbound messages to this peer. */
  chain: Promise<void>;
}

export class SessionManager {
  private readonly peers = new Map<string, PeerState>();
  private readonly byIndex = new Map<number, Session | PendingInit>();
  private sweepTimer: ReturnType<typeof setInterval> | undefined;
  private closed = false;
  private readonly gate: GateEntry[] = [];
  private pumping = false;
  private repump = false;
  private awaitingSocket = false;
  readonly stats: CoreStats = { creditsSent: 0, messagesReceived: 0, inflightMaxBytes: 0, socketBacklogMaxBytes: 0, controlBacklogMaxBytes: 0 };

  constructor(private readonly h: SessionHost) {
    const t = h.timing;
    const period = Math.max(20, Math.min(t.idleMs, t.rekeyIntervalMs, t.retireGraceMs) / 4);
    this.sweepTimer = setInterval(() => this.sweep(), period);
    (this.sweepTimer as { unref?: () => void }).unref?.();
  }

  // ── Public operations ──

  /** Sends one application message, fragmenting and waiting for credit as needed. */
  send(peer: string, bytes: Uint8Array): Promise<void> {
    if (this.closed) return Promise.reject(new ClosedError());
    if (bytes.length > MAX_MESSAGE) return Promise.reject(new InvalidError('message exceeds 64 MiB'));
    if (peer === this.h.identity.id) return Promise.reject(new InvalidError('cannot send to self'));
    if (!findMember(this.h.roster(), peer)) return Promise.reject(new InvalidError(`${peer} is not on the roster`));
    const ps = this.peer(peer);
    const run = ps.chain.then(() => this.sendNow(peer, bytes));
    ps.chain = run.catch(() => undefined);
    return run;
  }

  /** Sends a control session message (roster-request, roster, resign). */
  async sendControl(peer: string, msg: SessionMessage): Promise<void> {
    if (this.closed) throw new ClosedError();
    const s = await this.ensureSession(peer);
    this.transmit(s, msg);
  }

  /** Ends every session with peers no longer on the roster. */
  rosterChanged(): void {
    const roster = this.h.roster();
    for (const [id, ps] of this.peers) {
      const m = findMember(roster, id);
      if (m) continue;
      const err = new InvalidError(`${id} is no longer on the roster`);
      this.failPending(ps, err);
      for (const s of [...ps.sessions]) this.endSession(s, err);
    }
  }

  /** Ends all sessions, e.g. when the relay connection drops. */
  dropAll(err: LinkError): void {
    for (const ps of this.peers.values()) {
      this.failPending(ps, err);
      for (const s of [...ps.sessions]) this.endSession(s, err);
    }
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    clearInterval(this.sweepTimer);
    this.dropAll(new ClosedError());
  }

  /** For tests and diagnostics: live sessions with a peer. */
  sessionInfo(peer: string): { localIndex: number; remoteIndex: number; initiator: boolean; current: boolean; sent: number; received: number; sendCredit: number; inflight: number }[] {
    const ps = this.peers.get(peer);
    if (!ps) return [];
    return [...ps.sessions].map((s) => ({
      localIndex: s.localIndex,
      remoteIndex: s.remoteIndex,
      initiator: s.initiator,
      current: ps.current === s,
      sent: s.sent,
      received: s.received,
      sendCredit: s.sendCredit,
      inflight: s.inflight,
    }));
  }

  // ── Frames from the relay ──

  handleFrame(f: Frame, from: string): void {
    if (this.closed) return;
    try {
      switch (f.type) {
        case FrameType.HandshakeInit:
          return this.onInit(from, f.body);
        case FrameType.HandshakeResp:
          return this.onResp(from, f.body);
        case FrameType.Data:
        case FrameType.Control:
          return this.onData(from, f.body);
        case FrameType.Unreachable:
          return this.onUnreachable(from);
        case FrameType.Refused:
          return this.onRefused(from, f.body[0] ?? 0);
        case FrameType.Reset:
          return this.onReset(from, readU32be(f.body, 0));
        default:
          return;
      }
    } catch {
      // A malformed frame is dropped; it never takes the member down.
    }
  }

  private onInit(from: string, body: Uint8Array): void {
    const roster = this.h.roster();
    const { senderIndex, noise } = parseHandshakeInit(body);
    if (senderIndex === 0) return;
    const hs = new HandshakeState({
      pattern: PATTERNS.IK,
      initiator: false,
      prologue: sessionPrologue(roster.network),
      s: this.h.identity.x25519,
    });
    let payload: Uint8Array;
    try {
      payload = hs.readMessage(noise).payload;
    } catch {
      return;
    }
    const version = payload.length === 8 ? Number(readU64be(payload, 0)) : undefined;
    const member = findMember(roster, from);
    const rs = hs.remoteStatic;
    if (!member || !rs || !sameKey(member.x25519, rs)) {
      this.h.sendFrame(FrameType.Refused, from, Uint8Array.of(RefusedReason.NotOnRoster));
      if (version !== undefined) this.h.peerVersion(from, version);
      return;
    }
    if (version === undefined) return;
    const localIndex = this.newIndex();
    const { message, transport } = hs.writeMessage(u64be(roster.version));
    if (!transport) return;
    if (!this.h.sendFrame(FrameType.HandshakeResp, from, handshakeRespBody(localIndex, senderIndex, message))) return;
    const s = new Session(from, localIndex, senderIndex, false, transport.send, transport.recv, this.h.now());
    this.adopt(s);
    this.h.peerVersion(from, version);
  }

  private onResp(from: string, body: Uint8Array): void {
    const { senderIndex, receiverIndex, noise } = parseHandshakeResp(body);
    const p = this.byIndex.get(receiverIndex);
    if (!p || p instanceof Session || p.peer !== from || senderIndex === 0) return;
    const ps = this.peer(from);
    let payload: Uint8Array;
    let transport;
    try {
      ({ payload, transport } = p.hs.readMessage(noise));
      if (!transport || payload.length !== 8) throw new Error('bad response');
    } catch {
      this.failPending(ps, new ClosedError(`handshake with ${from} failed`));
      return;
    }
    // The responder's key must still be on the current roster.
    const member = findMember(this.h.roster(), from);
    if (!member || !sameKey(member.x25519, p.hs.remoteStatic!)) {
      this.failPending(ps, new InvalidError(`${from} is no longer on the roster`));
      return;
    }
    clearTimeout(p.timer);
    ps.pending = undefined;
    const s = new Session(from, p.localIndex, senderIndex, true, transport.send, transport.recv, this.h.now());
    this.byIndex.set(p.localIndex, s);
    this.adopt(s);
    for (const w of p.waiters) w.resolve(s);
    this.h.peerVersion(from, Number(readU64be(payload, 0)));
  }

  private onData(from: string, body: Uint8Array): void {
    const { receiverIndex, ciphertext } = parseData(body);
    const s = this.byIndex.get(receiverIndex);
    if (!(s instanceof Session) || s.peer !== from || s.ended || (this.expired(s) && !this.crossing(s))) {
      // Section 7.2: a receiver index this side does not hold (or a responder
      // session past its lifetime, unless a message is still crossing it in
      // either direction) is answered with reset.
      if (s instanceof Session && s.peer === from) this.endSession(s, new ClosedError(`session with ${from} expired`));
      this.h.sendFrame(FrameType.Reset, from, u32be(receiverIndex));
      return;
    }
    let plaintext: Uint8Array;
    try {
      plaintext = s.recv.decryptWithAd(EMPTY, ciphertext);
    } catch {
      this.endSession(s, new ClosedError(`session with ${from} lost a frame`));
      return;
    }
    s.received++;
    s.lastActivity = this.h.now();
    let msg: SessionMessage;
    try {
      msg = decodeSessionMessage(plaintext);
    } catch {
      this.endSession(s, new ClosedError(`session with ${from} carried a malformed message`));
      return;
    }
    switch (msg.type) {
      case 'message':
        this.onFragment(s, msg.more, msg.bytes);
        break;
      case 'credit': {
        s.sendCredit += msg.bytes;
        const took = Math.min(s.inflight, msg.bytes);
        s.inflight -= took;
        this.rollRate(s, this.h.now());
        s.rateCur += took;
        this.pump();
        break;
      }
      default:
        this.h.control(from, msg);
    }
    this.maybeRekey(s);
  }

  private onFragment(s: Session, more: boolean, bytes: Uint8Array): void {
    if (s.partialLen + bytes.length > MAX_MESSAGE) {
      this.endSession(s, new ClosedError(`${s.peer} sent a message over 64 MiB`));
      return;
    }
    s.partial.push(bytes.slice());
    s.partialLen += bytes.length;
    if (more) {
      // Fragments of a message in progress are taken at once while the
      // application keeps up, so a message larger than the window can finish.
      if (s.held === 0) {
        s.owed += bytes.length;
        s.partialCredited += bytes.length;
        this.flushCredit(s);
      }
      return;
    }
    const whole = joinParts(s.partial, s.partialLen);
    this.stats.messagesReceived++;
    const uncredited = s.partialLen - s.partialCredited;
    s.partial = [];
    s.partialLen = 0;
    s.partialCredited = 0;
    s.held++;
    let released = false;
    this.h.deliver(s.peer, whole, () => {
      if (released) return;
      released = true;
      s.held--;
      s.owed += uncredited;
      if (s.held === 0 && s.partialLen > s.partialCredited) {
        s.owed += s.partialLen - s.partialCredited;
        s.partialCredited = s.partialLen;
      }
      this.flushCredit(s);
    });
  }

  /** Returns owed credit in batches: at once from CREDIT_BATCH_BYTES, else CREDIT_DELAY_MS after it began to be owed. */
  private flushCredit(s: Session, now = false): void {
    if (s.ended || s.owed <= 0) return;
    if (!now && s.owed < CREDIT_BATCH_BYTES) {
      if (s.creditTimer === undefined) {
        s.creditTimer = setTimeout(() => {
          s.creditTimer = undefined;
          this.flushCredit(s, true);
        }, CREDIT_DELAY_MS);
        (s.creditTimer as { unref?: () => void }).unref?.();
      }
      return;
    }
    clearTimeout(s.creditTimer);
    s.creditTimer = undefined;
    while (s.owed > 0) {
      const n = Math.min(s.owed, 0xffffffff);
      s.owed -= n;
      this.stats.creditsSent++;
      if (!this.transmit(s, { type: 'credit', bytes: n })) return;
    }
  }

  private onUnreachable(peer: string): void {
    const ps = this.peers.get(peer);
    if (!ps) return;
    const err = new UnreachableError(peer);
    this.failPending(ps, err);
    for (const s of [...ps.sessions]) this.endSession(s, err);
  }

  /** The peer holds no session for `index` (our remote index): drop ours; the next send handshakes. */
  private onReset(peer: string, index: number): void {
    const ps = this.peers.get(peer);
    if (!ps) return;
    for (const s of [...ps.sessions]) {
      if (s.remoteIndex === index) this.endSession(s, new ClosedError(`${peer} reset the session`));
    }
  }

  private onRefused(peer: string, reason: number): void {
    const ps = this.peers.get(peer);
    if (!ps) return;
    const err = new RefusedError(peer, reason);
    this.failPending(ps, err);
    for (const s of [...ps.sessions]) this.endSession(s, err);
  }

  // ── Session lifecycle ──

  private peer(id: string): PeerState {
    let ps = this.peers.get(id);
    if (!ps) {
      ps = { current: undefined, sessions: new Set(), pending: undefined, chain: Promise.resolve() };
      this.peers.set(id, ps);
    }
    return ps;
  }

  private newIndex(): number {
    for (;;) {
      const b = randomBytes(4);
      const i = ((b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!) >>> 0;
      if (i !== 0 && !this.byIndex.has(i)) return i;
    }
  }

  /** Makes a newly established session the one new messages use. */
  private adopt(s: Session): void {
    const ps = this.peer(s.peer);
    this.byIndex.set(s.localIndex, s);
    ps.sessions.add(s);
    // A window beyond the initial 1 MiB is granted as extra credit at once.
    const extra = this.h.creditWindow - INITIAL_CREDIT;
    if (extra > 0) {
      s.owed += extra;
      this.flushCredit(s);
    }
    const prev = ps.current;
    ps.current = s;
    if (prev && prev !== s) {
      prev.retired = true;
      prev.lastActivity = Math.max(prev.lastActivity, this.h.now());
    }
  }

  private async ensureSession(peer: string): Promise<Session> {
    const ps = this.peer(peer);
    const cur = ps.current;
    if (cur && this.expired(cur)) {
      // Expiry yields to a message in flight (section 7.2): one still crossing finishes on
      // the old session, which is retired; this send takes a new one.
      if (this.crossing(cur)) cur.retired = true;
      else this.endSession(cur, new ClosedError(`session with ${peer} expired`));
      return this.initiate(peer);
    }
    if (cur && !cur.ended) {
      this.maybeRekey(cur);
      return cur;
    }
    return this.initiate(peer);
  }

  private initiate(peer: string): Promise<Session> {
    // A send chained before close() runs after it: it must not start a handshake.
    if (this.closed) return Promise.reject(new ClosedError());
    const ps = this.peer(peer);
    if (ps.pending) {
      const p = ps.pending;
      return new Promise((resolve, reject) => p.waiters.push({ resolve, reject }));
    }
    const roster = this.h.roster();
    const member = findMember(roster, peer);
    if (!member) return Promise.reject(new InvalidError(`${peer} is not on the roster`));
    const hs = new HandshakeState({
      pattern: PATTERNS.IK,
      initiator: true,
      prologue: sessionPrologue(roster.network),
      s: this.h.identity.x25519,
      rs: fromB64uLen(member.x25519, 32, 'x25519'),
    });
    const localIndex = this.newIndex();
    const { message } = hs.writeMessage(u64be(roster.version));
    this.h.note({ kind: 'handshake', peer });
    return new Promise<Session>((resolve, reject) => {
      const p: PendingInit = {
        peer,
        localIndex,
        hs,
        waiters: [{ resolve, reject }],
        timer: setTimeout(() => {
          if (ps.pending === p) this.failPending(ps, new TimeoutError(`handshake with ${peer}`));
        }, this.h.timing.handshakeTimeoutMs),
      };
      ps.pending = p;
      this.byIndex.set(localIndex, p);
      if (!this.h.sendFrame(FrameType.HandshakeInit, peer, handshakeInitBody(localIndex, message))) {
        this.failPending(ps, new ClosedError('not connected to the relay'));
      }
    });
  }

  private failPending(ps: PeerState, err: LinkError): void {
    const p = ps.pending;
    if (!p) return;
    clearTimeout(p.timer);
    ps.pending = undefined;
    this.byIndex.delete(p.localIndex);
    for (const w of p.waiters) w.reject(err);
  }

  private endSession(s: Session, err: LinkError): void {
    if (s.ended) return;
    s.ended = true;
    s.endError = err;
    this.byIndex.delete(s.localIndex);
    const ps = this.peers.get(s.peer);
    if (ps) {
      ps.sessions.delete(s);
      if (ps.current === s) ps.current = undefined;
    }
    clearTimeout(s.creditTimer);
    s.creditTimer = undefined;
    // Fragments waiting in the gate on this session fail with it.
    this.pump();
  }

  /** A responder session older than the rekey interval plus the grace has expired. */
  private expired(s: Session): boolean {
    const t = this.h.timing;
    return !s.initiator && this.h.now() - s.createdAt > t.rekeyIntervalMs + t.retireGraceMs;
  }

  /** A message is part-way across the session: one being received, or one this side is sending. */
  private crossing(s: Session): boolean {
    return s.partialLen > 0 || s.activeSends > 0;
  }

  private maybeRekey(s: Session): void {
    if (!s.initiator || s.retired || s.ended) return;
    const t = this.h.timing;
    const due =
      this.h.now() - s.createdAt >= t.rekeyIntervalMs || s.sent >= t.rekeyMessages || s.received >= t.rekeyMessages;
    if (due && !this.peer(s.peer).pending) this.initiate(s.peer).catch(() => undefined);
  }

  private sweep(): void {
    const now = this.h.now();
    const t = this.h.timing;
    for (const ps of this.peers.values()) {
      for (const s of [...ps.sessions]) {
        const quiet = now - s.lastActivity;
        if (quiet >= t.idleMs) {
          this.endSession(s, new ClosedError(`session with ${s.peer} went idle`));
        } else if (this.expired(s) && s.activeSends === 0 && s.partialLen === 0 && s.held === 0) {
          this.endSession(s, new ClosedError(`session with ${s.peer} expired`));
        } else if (s.retired && quiet >= t.retireGraceMs && s.activeSends === 0 && s.partialLen === 0 && s.held === 0) {
          this.endSession(s, new ClosedError(`session with ${s.peer} was replaced`));
        } else if (s.sent + s.received > 0) {
          // A session that never carried a frame is left to expire, not rekeyed.
          this.maybeRekey(s);
        }
      }
    }
  }

  // ── Sending ──

  private transmit(s: Session, msg: SessionMessage): boolean {
    if (s.ended) return false;
    const plaintext = encodeSessionMessage(msg);
    // Checked before encrypting, so a refused message does not spend a nonce.
    if (plaintext.length > MAX_PLAINTEXT) throw new InvalidError(`a ${msg.type} session message exceeds ${MAX_PLAINTEXT} bytes`);
    const backlog = this.h.bufferedAmount();
    const data = msg.type === 'message';
    if (data) this.stats.socketBacklogMaxBytes = Math.max(this.stats.socketBacklogMaxBytes, backlog);
    else this.stats.controlBacklogMaxBytes = Math.max(this.stats.controlBacklogMaxBytes, backlog);
    // Encrypted and handed over in one step: the frame's nonce is its place on the wire.
    const ct = s.send.encryptWithAd(EMPTY, plaintext);
    s.sent++;
    s.lastActivity = this.h.now();
    return this.h.sendFrame(data ? FrameType.Data : FrameType.Control, s.peer, dataBody(s.remoteIndex, ct));
  }

  private async sendNow(peer: string, bytes: Uint8Array): Promise<void> {
    const s = await this.ensureSession(peer);
    s.activeSends++;
    try {
      let off = 0;
      do {
        await new Promise<void>((resolve, reject) => {
          this.gate.push({
            s,
            empty: bytes.length === 0,
            fail: reject,
            run: () => {
              // Never more than the room left under the pace (but not below PACE_MIN_FRAGMENT), so
              // the socket holds about the pace and no more: on a slow link fragments shrink, and
              // control behind them waits a fraction of a second rather than a whole fragment.
              const room = Math.max(PACE_MIN_FRAGMENT, this.pace(s) - s.inflight);
              const n = Math.min(bytes.length - off, MAX_FRAGMENT, Math.max(s.sendCredit, 0), room);
              const more = off + n < bytes.length;
              if (!this.transmit(s, { type: 'message', more, bytes: bytes.subarray(off, off + n) })) {
                throw s.endError ?? new ClosedError('not connected to the relay');
              }
              s.sendCredit -= n;
              s.inflight += n;
              if (s.inflight > this.stats.inflightMaxBytes) this.stats.inflightMaxBytes = s.inflight;
              off += n;
              resolve();
            },
          });
          this.pump();
        });
      } while (off < bytes.length);
    } finally {
      s.activeSends--;
      this.maybeRekey(s);
    }
  }

  /** Message bytes `s` may have un-credited: about a second and a half of what its receiver takes. */
  private pace(s: Session): number {
    const now = this.h.now();
    this.rollRate(s, now);
    // A second's worth of credit: the larger of the last whole second and the one under way.
    // (Not their interpolated sum: credit comes in lumps, and a lump early in the second under
    // way would count a second twice.)
    return Math.max(PACE_FLOOR_BYTES, Math.floor(1.5 * Math.max(s.ratePrev, s.rateCur)));
  }

  private rollRate(s: Session, now: number): void {
    const d = now - s.rateAt;
    if (d >= 2000 || d < 0) {
      s.ratePrev = 0;
      s.rateCur = 0;
      s.rateAt = now;
    } else if (d >= 1000) {
      s.ratePrev = s.rateCur;
      s.rateCur = 0;
      s.rateAt += 1000;
    }
  }

  /**
   * Hands waiting fragments to the socket, oldest first, skipping a session that is out of
   * credit or over its pace (it is woken by its next credit) so one slow receiver never holds
   * up another. Stops while the socket is backed up, and resumes once it drains.
   */
  private pump(): void {
    if (this.pumping) {
      // Asked again while running (a socket that turned writable at once): run once more after.
      this.repump = true;
      return;
    }
    this.pumping = true;
    try {
      do {
        this.repump = false;
        this.pumpOnce();
      } while (this.repump);
    } finally {
      this.pumping = false;
    }
  }

  private pumpOnce(): void {
    for (let i = 0; i < this.gate.length; ) {
      const e = this.gate[i]!;
      if (e.s.ended || this.closed) {
        this.gate.splice(i, 1);
        e.fail(e.s.endError ?? new ClosedError());
        continue;
      }
      if ((!e.empty && e.s.sendCredit <= 0) || e.s.inflight >= this.pace(e.s)) {
        i++;
        continue;
      }
      if (!this.h.writable()) {
        if (!this.awaitingSocket) {
          this.awaitingSocket = true;
          this.h.whenWritable(() => {
            this.awaitingSocket = false;
            this.pump();
          });
        }
        return;
      }
      this.gate.splice(i, 1);
      try {
        e.run();
      } catch (err) {
        e.fail(err);
      }
    }
  }
}

function sameKey(b64: string, raw: Uint8Array): boolean {
  const k = fromB64uLen(b64, 32, 'x25519');
  if (k.length !== raw.length) return false;
  let d = 0;
  for (let i = 0; i < k.length; i++) d |= k[i]! ^ raw[i]!;
  return d === 0;
}

function joinParts(parts: Uint8Array[], len: number): Uint8Array {
  if (parts.length === 1) return parts[0]!;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}
