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
//
// Every byte from a peer is hostile, so what a peer can make this side hold or do
// is bounded (sections 7.2 to 7.4):
// - a Noise message over 65535 bytes, message bytes beyond the credit this side
//   granted, or an empty fragment with "more" set end the session;
// - a message in reassembly is one buffer of at most 64 MiB, never a list of
//   fragments;
// - per peer, messages in reassembly plus whole messages the application has not
//   taken are at most PEER_BUFFERED_BYTES(window) bytes and PEER_HELD_MESSAGES
//   messages, and at most MAX_SESSIONS_PER_PEER sessions live at once;
// - handshake-inits are processed, and resets sent, at a bounded rate, each id
//   with its own budget (so one peer cannot spend another's), and a roster is not
//   queued to a peer while one as new is still unsent to it. Inits labelled with a
//   member's id that fail spend that id's own failure budget. Budgets carry across
//   relay connections, refilling only with time.

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
import { canonicalize } from './jcs.js';
import { findMember, type Roster } from './roster.js';

export const MAX_MESSAGE = 64 * 1024 * 1024;
/** A Noise message is at most 65535 bytes (section 7.2); a longer one received ends its session. */
export const MAX_NOISE_MESSAGE = 65535;
/** One transport plaintext: a Noise message, less the 16-byte tag. */
export const MAX_PLAINTEXT = MAX_NOISE_MESSAGE - 16;
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

// What one peer may leave here (section 7.3). A session that would take its peer beyond
// either bound ends; the message is lost, as delivery is at most once.
/** Bytes per peer, in reassembly and waiting for the application, over all its sessions: two
 * whole messages (one waiting on a session, the next arriving on the session a rekey made)
 * and four windows. */
export const PEER_BUFFERED_BYTES = (creditWindow: number): number => 2 * MAX_MESSAGE + 4 * creditWindow;
/** Whole messages per peer waiting for the application. */
export const PEER_HELD_MESSAGES = 65536;
/** Sessions with one peer live at once; adopting one more ends the oldest that is not current. */
export const MAX_SESSIONS_PER_PEER = 8;

// Rates (section 7.4), as token buckets: so many a second, so many at once. Every budget
// belongs to one id, so a peer flooding spends only its own; the tables are bounded.
/** Handshake-inits processed per roster member (each costs Diffie-Hellman work before
 * anything is known of the sender)... */
export const INIT_RATE = 16;
export const INIT_BURST = 32;
/** ...per id off the roster... */
export const STRANGER_INIT_RATE = 4;
export const STRANGER_INIT_BURST = 8;
/** ...and from all ids off the roster together: a ceiling only a relay forging ids can reach
 * (a member always arrives under its own id), never a budget members share. */
export const STRANGERS_INIT_RATE = 128;
export const STRANGERS_INIT_BURST = 256;
/** Inits labelled with one roster member's id that fail (do not read, or are not on its key):
 * this many a second, this many at once, apart from its init budget. While spent, that id's
 * inits are dropped before any Diffie-Hellman work. Per id, never shared: a member sending bad
 * inits under its own id starves only itself, and a relay forging an id silences only that id. */
export const FAILED_INIT_RATE = 2;
export const FAILED_INIT_BURST = 4;
/** Ids off the roster whose budgets are kept; past it, the least recently used is forgotten. */
export const STRANGERS = 256;
/** An init from an id off the roster hints that a newer roster lists it: the primary is asked
 * for its roster at most once in this long... */
export const ROSTER_HINT_INTERVAL_MS = 1000;
/** ...doubling after each hint that brought no newer roster, up to this; a newer roster resets
 * it. A relay can provoke hints on every node at once, and each costs the primary a roster. */
export const ROSTER_HINT_MAX_MS = 5 * 60_000;
/** A `reset` for one peer and index goes out at most once in this long... */
export const RESET_REPEAT_MS = 1000;
/** ...and to one peer at this rate. */
export const RESET_RATE = 32;
export const RESET_BURST = 64;
/** ...and to all ids off the roster together at this rate: a ceiling only forged ids reach. */
export const STRANGERS_RESET_RATE = 128;
export const STRANGERS_RESET_BURST = 256;
/** The (peer, index) pairs remembered for RESET_REPEAT_MS: a memory bound, not a budget. */
const RECENT_RESETS = 1024;

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

/** Message 1's payload (section 7.1): the roster version, then the stamp, each u64 big-endian. */
export const INIT_PAYLOAD_BYTES = 16;

export function initPayload(version: number, stamp: bigint): Uint8Array {
  const out = new Uint8Array(INIT_PAYLOAD_BYTES);
  out.set(u64be(version), 0);
  out.set(u64be(stamp), 8);
  return out;
}

/** W (section 7.1): how far ahead of the responder's wall clock a stamp may be, and how far
 * before the responder's start (or a member's joining) a first stamp may be. The relay holds
 * every member's clock within 5 minutes of its own, so honest members are within 10 of each other. */
export const STAMP_WINDOW_MS = 10 * 60_000;
/** Last accepted stamps kept for ids that left the roster, most recently left last, so that
 * one admitted again still refuses its inits from before (section 7.1). */
export const RETAINED_STAMPS = 1024;

/** The stamp after `last`: milliseconds since the Unix epoch, and always above every stamp sent. */
export function nextStamp(wallNowMs: number, last: bigint): bigint {
  const now = BigInt(Math.max(0, Math.floor(wallNowMs)));
  return now > last ? now : last + 1n;
}

export interface SessionHost {
  identity: Identity;
  roster(): Roster;
  /** A monotonic clock in milliseconds: every rate, interval and timeout here (section 7.4). */
  now(): number;
  /** The wall clock, Unix milliseconds: only for the stamps of handshake-inits (section 7.1). */
  wallNow(): number;
  /** The receive window this side grants; at least INITIAL_CREDIT. */
  creditWindow: number;
  /** Lower per-peer bounds than PEER_BUFFERED_BYTES and PEER_HELD_MESSAGES, so tests reach them. */
  limits?: { peerBufferedBytes?: number; peerHeldMessages?: number } | undefined;
  timing: SessionTiming;
  /** Hands a frame to the relay; false when not connected. Control is sent as FrameType.Control. */
  sendFrame(type: number, peer: string, body: Uint8Array): boolean;
  /** Data may be handed to the socket now (little waits in it, or it is gone and a send fails at once). */
  writable(): boolean;
  /** Calls `f` once data may be handed to the socket again. */
  whenWritable(f: () => void): void;
  /** Bytes waiting in the socket. */
  bufferedAmount(): number;
  /** Where the relay connection is: which connection, the bytes handed to its socket, and
   * those of them the socket has sent. */
  wirePosition(): { conn: number; queued: number; written: number };
  /** Tells an installed diagnostics hook. */
  note(e: DiagnosticsEvent): void;
  /** A complete message; call `release` once the application has taken it. */
  deliver(from: string, bytes: Uint8Array, release: () => void): void;
  /** roster-request, roster or resign from a peer. */
  control(from: string, msg: SessionMessage): void;
  /** The peer reported (in a handshake payload) a roster version. */
  peerVersion(from: string, version: number): void;
  /** An id off the roster wants a session: ask the primary for its roster (already rate-limited). */
  rosterHint(): void;
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
  /** The message in reassembly: its first `partialLen` bytes. */
  partial: Uint8Array = EMPTY;
  partialLen = 0;
  partialCredited = 0;
  /** Complete messages handed to the application and not yet taken. */
  held = 0;
  owed = 0;
  /** Message bytes the peer may still send: credit granted, less message bytes received. */
  allowance = INITIAL_CREDIT;

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
  /** Bytes this peer has here (messages in reassembly and not taken), and messages not taken. */
  buffered: number;
  held: number;
  /** Handshake-inits from this peer that may still be processed, those of them that may fail,
   * and resets owed it that may be sent. */
  inits: Bucket;
  failedInits: Bucket;
  resets: Bucket;
  /** The greatest stamp of an init from this member that passed the key check and was accepted
   * (section 7.1): an init stamped no later is a replay. Forgotten when it leaves the roster. */
  stamp: bigint;
  /** The newest roster queued to this peer: its version, the connection, and the wire
   * position just after it. While that is not yet written, no roster as old is queued again. */
  rosterQueued: { version: number; conn: number; end: number } | undefined;
}

/** The budgets of an id off the roster. */
interface Stranger {
  inits: Bucket;
  resets: Bucket;
}

/** A token bucket: `rate` tokens a second, at most `burst` at once; it starts full. */
export class Bucket {
  private tokens: number;
  private at: number | undefined;

  constructor(
    private readonly rate: number,
    private readonly burst: number,
  ) {
    this.tokens = burst;
  }

  /** Takes one token if there is one. */
  take(now: number): boolean {
    if (!this.has(now)) return false;
    this.tokens--;
    return true;
  }

  /** Whether a token is there now, taking none. `now` is a monotonic clock; should it step back
   * all the same, the bucket refills from there rather than waiting out the step. */
  has(now: number): boolean {
    if (this.at !== undefined && now > this.at) this.tokens = Math.min(this.burst, this.tokens + ((now - this.at) * this.rate) / 1000);
    this.at = now;
    return this.tokens >= 1;
  }
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
  /** Resets sent lately, by peer and index. */
  private recentResets = new Map<string, number>();
  /** Ids off the roster, least recently used first, and the ceiling on all their inits. */
  private strangers = new Map<string, Stranger>();
  private readonly strangersInits = new Bucket(STRANGERS_INIT_RATE, STRANGERS_INIT_BURST);
  private readonly strangersResets = new Bucket(STRANGERS_RESET_RATE, STRANGERS_RESET_BURST);
  /** When the primary was last asked for its roster on a stranger's hint, and the wait before the next. */
  private rosterHintAt: number | undefined;
  private rosterHintWait = ROSTER_HINT_INTERVAL_MS;
  /** A hint that came within the wait, deferred to its end: one ask, however many came. */
  private rosterHintTimer: ReturnType<typeof setTimeout> | undefined;
  /** The last stamp this node sent, to any peer. */
  private lastStamp = 0n;
  /** When this responder started, and when each member id joined its roster since: monotonic
   * instants, turned into wall time only when used, so a wall-clock correction moves them too. */
  private readonly startedMono: number;
  private readonly memberSince = new Map<string, number>();
  /** The last accepted stamp of ids that left the roster, oldest first, at most RETAINED_STAMPS. */
  private readonly retainedStamps = new Map<string, bigint>();
  readonly stats: CoreStats = { creditsSent: 0, messagesReceived: 0, inflightMaxBytes: 0, socketBacklogMaxBytes: 0, controlBacklogMaxBytes: 0 };

  constructor(private readonly h: SessionHost) {
    this.startedMono = h.now();
    for (const m of h.roster().members) this.memberSince.set(m.id, this.startedMono);
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

  /**
   * Sends `roster` to a peer, unless a roster at least as new is still waiting in the socket
   * for it: the one on its way already says as much, and a roster is the largest thing a
   * member sends on demand (up to 65000 bytes).
   */
  async sendRoster(peer: string, roster: Roster, json = canonicalize(roster)): Promise<void> {
    if (this.closed) throw new ClosedError();
    const s = await this.ensureSession(peer);
    const ps = this.peer(peer);
    const at = this.h.wirePosition();
    const q = ps.rosterQueued;
    if (q && q.version >= roster.version && q.conn === at.conn && at.written < q.end) return;
    if (!this.transmit(s, { type: 'roster', json })) throw s.endError ?? new ClosedError('not connected to the relay');
    const after = this.h.wirePosition();
    ps.rosterQueued = { version: roster.version, conn: after.conn, end: after.queued };
  }

  /** A newer roster was taken: ends every session with peers no longer on it, and lets the next
   * hint go after the shortest wait again. */
  rosterChanged(): void {
    this.rosterHintWait = ROSTER_HINT_INTERVAL_MS;
    const roster = this.h.roster();
    const now = this.h.now();
    for (const m of roster.members) {
      if (this.memberSince.has(m.id)) continue;
      this.memberSince.set(m.id, now);
      // Admitted again: its last accepted stamp comes back, so its inits from before still fail.
      const kept = this.retainedStamps.get(m.id);
      if (kept !== undefined) {
        this.retainedStamps.delete(m.id);
        this.peer(m.id).stamp = kept;
      }
    }
    for (const id of this.memberSince.keys()) if (!findMember(roster, id)) this.memberSince.delete(id);
    for (const [id, ps] of this.peers) {
      const m = findMember(roster, id);
      if (m) continue;
      if (ps.stamp > 0n) {
        this.retainedStamps.delete(id);
        this.retainedStamps.set(id, ps.stamp);
        for (const old of this.retainedStamps.keys()) {
          if (this.retainedStamps.size <= RETAINED_STAMPS) break;
          this.retainedStamps.delete(old);
        }
      }
      ps.stamp = 0n;
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
    clearTimeout(this.rosterHintTimer);
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
    // Within the sender's own budget, before any Diffie-Hellman work (section 7.4); beyond it,
    // dropped unanswered. An id off the roster may be one a newer roster lists. Inits labelled
    // with a member's id that keep failing (a relay forging the id, or the member sending bad
    // ones) stop that id's inits until its failure budget refills.
    const member = findMember(roster, from);
    const now = this.h.now();
    const allowed = member
      ? this.peer(from).failedInits.has(now) && this.peer(from).inits.take(now)
      : this.stranger(from).inits.take(now) && this.strangersInits.take(now);
    if (!allowed) {
      if (!member) this.rosterHint();
      return;
    }
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
      if (member) this.peer(from).failedInits.take(now);
      return;
    }
    const wellFormed = payload.length === INIT_PAYLOAD_BYTES;
    const version = wellFormed ? Number(readU64be(payload, 0)) : undefined;
    const rs = hs.remoteStatic;
    if (!member || !rs || !sameKey(member.x25519, rs)) {
      this.h.sendFrame(FrameType.Refused, from, Uint8Array.of(RefusedReason.NotOnRoster));
      // A member's id on another key spends that id's failure budget, and its version says
      // nothing. An id off the roster cannot be asked itself (there is no session with it):
      // its newer version is a hint for the primary.
      if (member) this.peer(from).failedInits.take(now);
      else if (version !== undefined && version > roster.version) this.rosterHint();
      return;
    }
    // On the member's key but without the 16-byte payload: malformed, so a failure all the same.
    const ps = this.peer(from);
    if (version === undefined) {
      ps.failedInits.take(now);
      return;
    }
    // A stamp no later than the last accepted from this member is a replay (a relay, or anyone
    // who saw the frame, sending it again): dropped unanswered, a failure, and nothing else.
    // One more than W ahead of this side's clock is refused too, and stores nothing: an honest
    // member is never that far ahead, and a stamp stored that far ahead would lock it out.
    const stamp = readU64be(payload, 8);
    const ahead = BigInt(Math.floor(this.h.wallNow())) + BigInt(STAMP_WINDOW_MS);
    if (stamp <= this.stampFloor(from, ps) || stamp > ahead) {
      ps.failedInits.take(now);
      return;
    }
    const localIndex = this.newIndex();
    const { message, transport } = hs.writeMessage(u64be(roster.version));
    if (!transport) return;
    if (!this.h.sendFrame(FrameType.HandshakeResp, from, handshakeRespBody(localIndex, senderIndex, message))) return;
    ps.stamp = stamp;
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
      if (this.resetAllowed(from, receiverIndex)) this.h.sendFrame(FrameType.Reset, from, u32be(receiverIndex));
      return;
    }
    if (ciphertext.length > MAX_NOISE_MESSAGE) {
      this.endSession(s, new ClosedError(`session with ${from} carried a frame over ${MAX_NOISE_MESSAGE} bytes`));
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
        // A peer cannot take it past what a number holds exactly.
        s.sendCredit = Math.min(s.sendCredit + msg.bytes, Number.MAX_SAFE_INTEGER);
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
    const n = bytes.length;
    const ps = this.peer(s.peer);
    let problem: string | undefined;
    if (more && n === 0) problem = 'sent an empty fragment that says more follow';
    else if (n > s.allowance) problem = 'sent message bytes beyond the credit granted';
    else if (s.partialLen + n > MAX_MESSAGE) problem = 'sent a message over 64 MiB';
    else if (ps.buffered + n > (this.h.limits?.peerBufferedBytes ?? PEER_BUFFERED_BYTES(this.h.creditWindow))) problem = 'left more buffered than this member keeps for a peer';
    else if (!more && ps.held >= (this.h.limits?.peerHeldMessages ?? PEER_HELD_MESSAGES)) problem = 'sent more messages than this member holds untaken';
    if (problem !== undefined) {
      this.endSession(s, new ClosedError(`${s.peer} ${problem}`));
      return;
    }
    s.allowance -= n;
    ps.buffered += n;
    appendPartial(s, bytes);
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
    // The buffer itself when it is exactly the message, so a whole message is copied once.
    const whole = s.partial.length === s.partialLen ? s.partial : s.partial.slice(0, s.partialLen);
    this.stats.messagesReceived++;
    const size = s.partialLen;
    const uncredited = s.partialLen - s.partialCredited;
    s.partial = EMPTY;
    s.partialLen = 0;
    s.partialCredited = 0;
    s.held++;
    ps.held++;
    let released = false;
    this.h.deliver(s.peer, whole, () => {
      if (released) return;
      released = true;
      s.held--;
      ps.held--;
      ps.buffered -= size;
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
      s.allowance += n;
    }
  }

  private onUnreachable(peer: string): void {
    const ps = this.peers.get(peer);
    if (!ps) return;
    const err = new UnreachableError(peer);
    this.failPending(ps, err);
    for (const s of [...ps.sessions]) this.endSession(s, err);
  }

  /**
   * Whether a `reset` may go to `peer` for `index` now (section 7.4): not twice for one peer and
   * index within RESET_REPEAT_MS, and within the reset rate. A flood of unknown indices, which a
   * relay can forge, is answered at a bounded rate.
   */
  private resetAllowed(peer: string, index: number): boolean {
    const now = this.h.now();
    const key = `${peer}/${index}`;
    const last = this.recentResets.get(key);
    if (last !== undefined && now - last < RESET_REPEAT_MS) return false;
    if (findMember(this.h.roster(), peer)) {
      if (!this.peer(peer).resets.take(now)) return false;
    } else if (!this.strangersResets.has(now) || !this.stranger(peer).resets.take(now) || !this.strangersResets.take(now)) return false;
    if (this.recentResets.size >= RECENT_RESETS) {
      for (const [k, t] of this.recentResets) if (now - t >= RESET_REPEAT_MS) this.recentResets.delete(k);
      if (this.recentResets.size >= RECENT_RESETS) this.recentResets.clear();
    }
    this.recentResets.set(key, now);
    return true;
  }

  /** The budgets of `id`, an id off the roster, made if need be; the table keeps the STRANGERS most recently used. */
  private stranger(id: string): Stranger {
    let st = this.strangers.get(id);
    if (st) this.strangers.delete(id);
    else st = { inits: new Bucket(STRANGER_INIT_RATE, STRANGER_INIT_BURST), resets: new Bucket(RESET_RATE, RESET_BURST) };
    this.strangers.set(id, st);
    for (const old of this.strangers.keys()) {
      if (this.strangers.size <= STRANGERS) break;
      this.strangers.delete(old);
    }
    return st;
  }

  /**
   * An id off the roster wants a session: the primary is asked for its roster, then not again
   * for ROSTER_HINT_INTERVAL_MS, doubled after every hint to ROSTER_HINT_MAX_MS until a newer
   * roster arrives (rosterChanged resets it). A hint within the wait is deferred to its end.
   */
  private rosterHint(): void {
    const now = this.h.now();
    if (this.rosterHintAt !== undefined && now - this.rosterHintAt < this.rosterHintWait) {
      // Deferred, not dropped: a newer roster may be waiting, revoking someone.
      if (this.rosterHintTimer === undefined) {
        this.rosterHintTimer = setTimeout(() => {
          this.rosterHintTimer = undefined;
          this.askOnHint();
        }, this.rosterHintAt + this.rosterHintWait - now);
        (this.rosterHintTimer as { unref?: () => void }).unref?.();
      }
      return;
    }
    this.askOnHint();
  }

  private askOnHint(): void {
    if (this.closed) return;
    clearTimeout(this.rosterHintTimer);
    this.rosterHintTimer = undefined;
    if (this.rosterHintAt !== undefined) this.rosterHintWait = Math.min(2 * this.rosterHintWait, ROSTER_HINT_MAX_MS);
    this.rosterHintAt = this.h.now();
    this.h.rosterHint();
  }

  /**
   * The stamp an init from `id` must exceed: the greater of the last stored (or retained across a
   * removal and re-admission) and W before this side started or `id` joined its roster, whichever
   * is later (taken from the monotonic clock and read as wall time now). So inits recorded before
   * that cannot be replayed after a restart, nor one recorded but never delivered before a
   * removal, once the re-admission is more than W after it.
   */
  private stampFloor(id: string, ps: PeerState): bigint {
    const mono = this.h.now();
    const since = Math.max(this.startedMono, this.memberSince.get(id) ?? mono);
    const floor = BigInt(Math.floor(this.h.wallNow() - (mono - since) - STAMP_WINDOW_MS));
    return ps.stamp > floor ? ps.stamp : floor;
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
      ps = {
        current: undefined,
        sessions: new Set(),
        pending: undefined,
        chain: Promise.resolve(),
        buffered: 0,
        held: 0,
        inits: new Bucket(INIT_RATE, INIT_BURST),
        failedInits: new Bucket(FAILED_INIT_RATE, FAILED_INIT_BURST),
        resets: new Bucket(RESET_RATE, RESET_BURST),
        rosterQueued: undefined,
        stamp: 0n,
      };
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
    // A Set iterates in insertion order: the first is the oldest.
    for (const old of ps.sessions) {
      if (ps.sessions.size <= MAX_SESSIONS_PER_PEER) break;
      if (old !== s) this.endSession(old, new ClosedError(`more than ${MAX_SESSIONS_PER_PEER} sessions with ${s.peer}`));
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
    this.lastStamp = nextStamp(this.h.wallNow(), this.lastStamp);
    const { message } = hs.writeMessage(initPayload(roster.version, this.lastStamp));
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
    // A message still in reassembly is lost with the session.
    if (ps) ps.buffered -= s.partialLen;
    s.partial = EMPTY;
    s.partialLen = 0;
    s.partialCredited = 0;
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

/** Appends a fragment to the message in reassembly, growing its buffer by doubling, to at most 64 MiB. */
function appendPartial(s: Session, bytes: Uint8Array): void {
  const need = s.partialLen + bytes.length;
  if (need > s.partial.length) {
    const grown = new Uint8Array(s.partialLen === 0 ? need : Math.min(MAX_MESSAGE, Math.max(need, 2 * s.partial.length)));
    grown.set(s.partial.subarray(0, s.partialLen));
    s.partial = grown;
  }
  s.partial.set(bytes, s.partialLen);
  s.partialLen = need;
}
