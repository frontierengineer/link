// Sessions (section 7): Noise IK handshakes keyed by roster x25519 keys,
// transport with receiver indices, rekeying, idle expiry, and the session
// message layer (fragmentation and credit flow control).
//
// Credit and reassembly belong to one Noise session, and a message is never
// split across two sessions: a rekey switches at a message boundary, and a
// retired session lives past its 30 s grace while a message still uses it.
// Every session starts with 1 MiB of credit each way; a larger `creditWindow`
// is granted as extra credit as soon as the session is up.

import { EMPTY, readU32be, readU64be, u32be, u64be, utf8, fromB64uLen, randomBytes } from './bytes.js';
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
export const MAX_FRAGMENT = 65535 - 16 - 2;
/** Credit every session starts with, in each direction (section 7.3). */
export const INITIAL_CREDIT = 1024 * 1024;
export const DEFAULT_CREDIT_WINDOW = INITIAL_CREDIT;

export interface SessionTiming {
  /** Handshake timeout per message (10 s). */
  handshakeTimeoutMs: number;
  /** Initiator rekeys after this long (10 min). */
  rekeyIntervalMs: number;
  /** ...or after this many messages in either direction (2^32). */
  rekeyMessages: number;
  /** Previous session's keys are kept this long after a rekey (30 s); a responder also
   * treats a session older than rekeyIntervalMs + retireGraceMs as expired. */
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
  /** Hands a frame to the relay; false when not connected. */
  sendFrame(type: number, peer: string, body: Uint8Array): boolean;
  /** A complete message; call `release` once the application has taken it. */
  deliver(from: string, bytes: Uint8Array, release: () => void): void;
  /** roster-request, roster or resign from a peer. */
  control(from: string, msg: SessionMessage): void;
  /** The peer reported (in a handshake payload) a roster version. */
  peerVersion(from: string, version: number): void;
}

interface Waiter {
  resolve: () => void;
  reject: (e: LinkError) => void;
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
  creditWaiters: Waiter[] = [];
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
  sessionInfo(peer: string): { localIndex: number; remoteIndex: number; initiator: boolean; current: boolean; sent: number; received: number; sendCredit: number }[] {
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
      case 'credit':
        s.sendCredit += msg.bytes;
        for (const w of s.creditWaiters.splice(0)) w.resolve();
        break;
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

  private flushCredit(s: Session): void {
    if (s.ended || s.owed <= 0) return;
    while (s.owed > 0) {
      const n = Math.min(s.owed, 0xffffffff);
      s.owed -= n;
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
    if (cur && this.expired(cur)) this.endSession(cur, new ClosedError(`session with ${peer} expired`));
    if (cur && !cur.ended) {
      this.maybeRekey(cur);
      return cur;
    }
    return this.initiate(peer);
  }

  private initiate(peer: string): Promise<Session> {
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
    for (const w of s.creditWaiters.splice(0)) w.reject(err);
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
    const ct = s.send.encryptWithAd(EMPTY, encodeSessionMessage(msg));
    s.sent++;
    s.lastActivity = this.h.now();
    return this.h.sendFrame(FrameType.Data, s.peer, dataBody(s.remoteIndex, ct));
  }

  private async sendNow(peer: string, bytes: Uint8Array): Promise<void> {
    const s = await this.ensureSession(peer);
    s.activeSends++;
    try {
      let off = 0;
      do {
        while (s.sendCredit <= 0 && bytes.length - off > 0) {
          await new Promise<void>((resolve, reject) => s.creditWaiters.push({ resolve, reject }));
        }
        if (s.ended) throw s.endError ?? new ClosedError(`session with ${peer} ended`);
        const n = Math.min(bytes.length - off, MAX_FRAGMENT, Math.max(s.sendCredit, 0));
        const more = off + n < bytes.length;
        if (!this.transmit(s, { type: 'message', more, bytes: bytes.subarray(off, off + n) })) {
          throw s.endError ?? new ClosedError('not connected to the relay');
        }
        s.sendCredit -= n;
        off += n;
      } while (off < bytes.length);
    } finally {
      s.activeSends--;
      this.maybeRekey(s);
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
