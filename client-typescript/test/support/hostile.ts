// A hostile peer and a scripted relay, for the tests that reproduce attacks on a member.
//
// - `pairOfManagers` wires an attacker's SessionManager to a victim's, back to back, so the
//   victim's genuine receive path runs while the attacker is driven directly: it can transmit
//   whatever it likes on a session (ignoring credit and the Noise size bound), as a peer
//   running its own code would.
// - `ScriptedRelay` is a WebSocket constructor a real Member dials. It answers `hello` and
//   `register` as the relay does, routes the member's frames to an attacker SessionManager and
//   the attacker's back, and lets the test hold the socket's buffer (nothing written) or send
//   the member any control text it likes.

import { encodeFrame, decodeFrame, FrameType, type Frame, type SessionMessage } from '../../src/frames.js';
import { b64u, randomBytes } from '../../src/bytes.js';
import { nodeIdFromBytes, nodeIdToBytes, type Identity } from '../../src/identity.js';
import { createIdentity, createNetwork, MAX_ROSTER_BYTES, memberFromIdentity, networkKeyFromSeed, rosterSize, signRoster, type NetworkKey, type Roster } from '../../src/index.js';
import { DEFAULT_SESSION_TIMING, INITIAL_CREDIT, SessionManager, type SessionHost } from '../../src/sessions.js';
import type { WebSocketLike } from '../../src/socket.js';

export const MiB = 1024 * 1024;
export const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));

/** Private state, for measurement. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const priv = (o: unknown) => o as any;

export interface Cast {
  primary: Identity;
  attacker: Identity;
  victim: Identity;
  roster: Roster;
  /** The network seed the primary holds, and the key it derives, which signs the roster. */
  networkSeed: Uint8Array;
  net: NetworkKey;
}

/** A network of a primary, an attacker and a victim (both members), at version 2; with `full`,
 * as many more members as fit the 65000-byte roster limit. */
export function cast(full = false): Cast {
  const primary = createIdentity();
  const attacker = createIdentity();
  const victim = createIdentity();
  const { roster: v1, networkSeed } = createNetwork({ identity: primary, relay: 'ws://relay.test/v1' });
  const net = networkKeyFromSeed(networkSeed);
  const members = [...v1.members, memberFromIdentity(attacker), memberFromIdentity(victim)];
  if (full) {
    // Measured with a signature's worth of placeholder, then signed once.
    const signature = 'A'.repeat(86);
    for (;;) {
      const more = [...members, memberFromIdentity(createIdentity())].sort((x, y) => (x.id < y.id ? -1 : 1));
      if (rosterSize({ ...v1, version: 2, members: more, signature }) > MAX_ROSTER_BYTES) break;
      members.splice(0, members.length, ...more);
    }
  }
  const roster = signRoster({ ...v1, version: 2, members }, net);
  return { primary, attacker, victim, roster, networkSeed, net };
}

export interface Received {
  from: string;
  bytes: Uint8Array;
  release: () => void;
}

function host(
  self: Identity,
  roster: () => Roster,
  send: (type: number, peer: string, body: Uint8Array) => boolean,
  inbox: Received[],
  control: SessionMessage[],
  more: Partial<SessionHost> = {},
): SessionHost {
  return {
    identity: self,
    roster,
    now: () => Date.now(),
    wallNow: () => Date.now(),
    creditWindow: INITIAL_CREDIT,
    timing: DEFAULT_SESSION_TIMING,
    sendFrame: send,
    writable: () => true,
    whenWritable: (f) => f(),
    bufferedAmount: () => 0,
    wirePosition: () => ({ conn: 1, queued: 0, written: 0 }),
    note: () => undefined,
    deliver: (from, bytes, release) => inbox.push({ from, bytes, release }),
    control: (_from, msg) => control.push(msg),
    peerVersion: () => undefined,
    rosterHint: () => undefined,
    ...more,
  };
}

export interface Pair extends Cast {
  attackerMgr: SessionManager;
  victimMgr: SessionManager;
  /** What the victim delivered (never released unless the test does). */
  victimInbox: Received[];
  /** Frames the victim sent, by type. */
  victimSent: number[];
  /** Opens a session from the attacker to the victim the ordinary way. */
  open(): Promise<void>;
  /** The attacker's current session with the victim. */
  attackerSession(): ReturnType<typeof priv>;
  /** The victim's live sessions with the attacker. */
  victimSessions(): ReturnType<typeof priv>[];
  /** Encrypts and sends `msg` on the attacker's current session, whatever credit says. */
  transmit(msg: SessionMessage): void;
  close(): void;
}

/** An attacker and a victim SessionManager, back to back; frames cross a microtask. */
export function pairOfManagers(victimHost: Partial<SessionHost> = {}, attackerHost: Partial<SessionHost> = {}): Pair {
  const c = cast();
  const victimInbox: Received[] = [];
  const victimSent: number[] = [];
  let am: SessionManager;
  let vm: SessionManager;
  const route = (from: string, to: () => SessionManager) => (type: number, _peer: string, body: Uint8Array) => {
    // The relay delivers 0x08 as 0x03 (section 6).
    const t = type === FrameType.Control ? FrameType.Data : type;
    queueMicrotask(() => to().handleFrame({ type: t, peer: nodeIdToBytes(from), body } as Frame, from));
    return true;
  };
  am = new SessionManager(host(c.attacker, () => c.roster, route(c.attacker.id, () => vm), [], [], attackerHost));
  const toAttacker = route(c.victim.id, () => am);
  vm = new SessionManager(
    host(
      c.victim,
      () => c.roster,
      (type, peer, body) => {
        victimSent.push(type);
        return toAttacker(type, peer, body);
      },
      victimInbox,
      [],
      victimHost,
    ),
  );
  const pair: Pair = {
    ...c,
    attackerMgr: am,
    victimMgr: vm,
    victimInbox,
    victimSent,
    async open() {
      await am.sendControl(c.victim.id, { type: 'roster-request' });
      await tick(5);
    },
    attackerSession: () => priv(am).peers.get(c.victim.id).current,
    victimSessions: () => {
      const ps = priv(vm).peers.get(c.attacker.id);
      return ps ? [...ps.sessions] : [];
    },
    transmit(msg) {
      priv(am).transmit(pair.attackerSession(), msg);
    },
    close() {
      am.close();
      vm.close();
    },
  };
  return pair;
}

/** One connection the member dialled. */
export class ScriptedSocket implements WebSocketLike {
  binaryType = 'arraybuffer';
  readyState = 0;
  bufferedAmount = 0;
  onopen: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onclose: ((ev: { code: number; reason: string }) => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;
  /** Control messages the member sent, parsed. */
  readonly texts: { type: string; [k: string]: unknown }[] = [];
  /** Routed frames the member sent. */
  readonly frames: Frame[] = [];
  closedWith: number | undefined;

  constructor(private readonly relay: ScriptedRelay) {
    relay.sockets.push(this);
    queueMicrotask(() => {
      this.readyState = 1;
      this.onopen?.({});
      this.text(JSON.stringify({ type: 'hello', version: 1, challenge: b64u(randomBytes(32)), features: ['control'] }));
    });
  }

  /** Sends the member a text frame, exactly these characters. */
  text(s: string): void {
    if (this.readyState === 1) this.onmessage?.({ data: s });
  }

  /** Sends the member a binary frame. */
  binary(bytes: Uint8Array): void {
    if (this.readyState === 1) this.onmessage?.({ data: bytes.slice().buffer });
  }

  send(data: string | Uint8Array | ArrayBuffer): void {
    if (this.readyState !== 1) throw new Error('not open');
    const size = typeof data === 'string' ? new TextEncoder().encode(data).length : data.byteLength;
    // A held socket writes nothing: what is handed over stays in its buffer.
    if (this.relay.hold) this.bufferedAmount += size;
    if (typeof data === 'string') {
      const msg = JSON.parse(data) as { type: string; [k: string]: unknown };
      this.texts.push(msg);
      if (msg.type === 'register') queueMicrotask(() => this.relay.onRegister(this, msg));
      return;
    }
    const f = decodeFrame(data instanceof Uint8Array ? data : new Uint8Array(data));
    this.frames.push(f);
    this.relay.onFrame(this, f);
  }

  close(code?: number): void {
    if (this.readyState >= 2) return;
    this.closedWith = code;
    this.readyState = 3;
    queueMicrotask(() => this.onclose?.({ code: code ?? 1005, reason: '' }));
  }
}

/** A relay the test scripts: it registers the member, and routes between it and an attacker. */
export class ScriptedRelay {
  readonly sockets: ScriptedSocket[] = [];
  /** While true, sockets keep everything handed to them as buffered (the relay reads nothing). */
  hold = false;
  /** The answer to `register`; by default `registered` at the member's roster version. */
  registered: (msg: { [k: string]: unknown }) => string = (msg) =>
    JSON.stringify({ type: 'registered', node: msg.node, rosterVersion: (msg.roster as Roster).version });
  readonly attackerInbox: Received[] = [];
  readonly attackerControl: SessionMessage[] = [];
  /** Frames the member sent the attacker, by type. */
  readonly toAttacker: number[] = [];
  attacker: SessionManager | undefined;
  /** Every frame the attacker's SessionManager sent, as the relay saw it: a recording to replay. */
  readonly fromAttackerLog: { type: number; body: Uint8Array }[] = [];
  /** The next this many frames for the attacker are answered `unreachable`, as if it were offline. */
  unreachableNext = 0;
  private attackerId = '';

  /** The constructor to give the member as its `WebSocket` option. */
  readonly WebSocket = ((relay: ScriptedRelay) =>
    class {
      constructor(_url: string) {
        return new ScriptedSocket(relay);
      }
    })(this) as unknown as new (url: string) => WebSocketLike;

  get socket(): ScriptedSocket {
    return this.sockets[this.sockets.length - 1]!;
  }

  onRegister(s: ScriptedSocket, msg: { [k: string]: unknown }): void {
    s.text(this.registered(msg));
  }

  /** Gives the attacker a SessionManager whose frames reach the member through the relay. */
  attach(identity: Identity, roster: () => Roster): SessionManager {
    this.attackerId = identity.id;
    this.attacker = new SessionManager(
      host(
        identity,
        roster,
        (type, _peer, body) => {
          const t = type === FrameType.Control ? FrameType.Data : type;
          this.fromAttackerLog.push({ type: t, body });
          const bytes = encodeFrame(t, nodeIdToBytes(identity.id), body);
          queueMicrotask(() => this.socket.binary(bytes));
          return true;
        },
        this.attackerInbox,
        this.attackerControl,
      ),
    );
    return this.attacker;
  }

  /** Sends the member a raw routed frame as if from the attacker. */
  fromAttacker(type: number, body: Uint8Array): void {
    this.socket.binary(encodeFrame(type, nodeIdToBytes(this.attackerId), body));
  }

  onFrame(s: ScriptedSocket, f: Frame): void {
    const to = nodeIdFromBytes(f.peer);
    if (to !== this.attackerId || !this.attacker) return;
    if (this.unreachableNext > 0) {
      // As the relay does for a peer not connected: the frame goes nowhere.
      this.unreachableNext--;
      queueMicrotask(() => s.binary(encodeFrame(FrameType.Unreachable, f.peer, new Uint8Array(0))));
      return;
    }
    this.toAttacker.push(f.type);
    const from = memberIdOf(s);
    const t = f.type === FrameType.Control ? FrameType.Data : f.type;
    queueMicrotask(() => this.attacker!.handleFrame({ type: t, peer: nodeIdToBytes(from), body: f.body } as Frame, from));
  }
}

function memberIdOf(s: ScriptedSocket): string {
  const reg = s.texts.find((t) => t.type === 'register');
  return String(reg?.node);
}
