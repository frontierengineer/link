// A minimal in-process relay for the client's integration tests: just enough
// of sections 4, 5.2 and 6 to register members, route frames and pairing
// channels, hold rosters and answer usage. Test support only; the real relay
// is the Go one, and the limits of section 9 are not modelled here.

import { randomBytes } from 'node:crypto';
import { b64u, fromB64uLen } from '../../src/bytes.js';
import { decodeFrame, encodeFrame, FrameType, MAX_FRAME } from '../../src/frames.js';
import { nodeIdFromBytes, nodeIdFromEd25519, nodeIdToBytes } from '../../src/identity.js';
import { ed25519Verify } from '../../src/crypto.js';
import { findMember, rosterProblem, type Roster } from '../../src/roster.js';
import { registerSigningBytes } from '../../src/signed.js';
import { listen, type ServerSocket, type WsServer } from './ws-server.js';

interface Conn {
  sock: ServerSocket;
  state: 'hello' | 'registered' | 'pairing' | 'closed';
  challenge: Uint8Array;
  network?: string;
  node?: string;
  channel?: string;
}

interface Channel {
  id: string;
  network: string;
  newcomer: Conn;
  primary: Conn;
  timer: ReturnType<typeof setTimeout>;
}

export interface RelayOptions {
  /** Close members dropped by a pushed roster with 4008 (section 4.2). Default true. */
  enforceRoster?: boolean;
  /** Clock for the registration time check. */
  now?: () => number;
}

export type FrameVerdict = 'pass' | 'drop' | 'unreachable';

export interface FrameLogEntry {
  from: string;
  to: string;
  type: number;
  size: number;
}

export class TestRelay {
  readonly rosters = new Map<string, Roster>();
  readonly conns = new Map<string, Map<string, Conn>>();
  readonly channels = new Map<string, Channel>();
  readonly bytesFrom = new Map<string, number>();
  readonly frameLog: FrameLogEntry[] = [];
  readonly closes: { node: string | undefined; code: number }[] = [];
  enforceRoster: boolean;
  /** Decides the fate of each routed member frame; tests use it to lose or block frames. */
  filter: ((e: FrameLogEntry) => FrameVerdict) | undefined;
  private readonly now: () => number;

  private constructor(
    private readonly ws: WsServer,
    opts: RelayOptions,
  ) {
    this.enforceRoster = opts.enforceRoster ?? true;
    this.now = opts.now ?? Date.now;
  }

  static async start(opts: RelayOptions = {}): Promise<TestRelay> {
    let relay: TestRelay | undefined;
    const ws = await listen('/v1', 2 * MAX_FRAME, (s) => relay!.accept(s));
    relay = new TestRelay(ws, opts);
    return relay;
  }

  get url(): string {
    return this.ws.url;
  }

  get origin(): string {
    return new URL(this.ws.url).host;
  }

  async stop(): Promise<void> {
    for (const ch of this.channels.values()) clearTimeout(ch.timer);
    await this.ws.close();
  }

  isConnected(network: string, node: string): boolean {
    return this.conns.get(network)?.has(node) ?? false;
  }

  /** Closes a member's connection with `code` (e.g. 4009 or 1001). */
  closeNode(network: string, node: string, code: number): void {
    this.conns.get(network)?.get(node)?.sock.close(code);
  }

  /** Drops a member's TCP connection without a close frame. */
  dropNode(network: string, node: string): void {
    this.conns.get(network)?.get(node)?.sock.destroy();
  }

  /** Pushes a usageAlert to the network's primary. */
  usageAlert(network: string, quotaUsed: number, slowed: boolean): void {
    this.conns.get(network)?.get(network)?.sock.sendText(JSON.stringify({ type: 'usageAlert', quotaUsed, slowed }));
  }

  private accept(sock: ServerSocket): void {
    const conn: Conn = { sock, state: 'hello', challenge: new Uint8Array(randomBytes(32)) };
    sock.handlers = {
      onText: (t) => this.onText(conn, t),
      onBinary: (b) => this.onBinary(conn, b),
      onClose: (code) => this.onClose(conn, code),
    };
    sock.sendText(JSON.stringify({ type: 'hello', version: 1, challenge: b64u(conn.challenge) }));
  }

  private close(conn: Conn, code: number): void {
    conn.sock.close(code);
  }

  private onClose(conn: Conn, code: number): void {
    const prev = conn.state;
    conn.state = 'closed';
    this.closes.push({ node: conn.node, code });
    if (prev === 'registered' && conn.network && conn.node) {
      const net = this.conns.get(conn.network);
      if (net?.get(conn.node) === conn) net.delete(conn.node);
      for (const ch of [...this.channels.values()]) if (ch.primary === conn) this.endChannel(ch, false);
    }
    if (prev === 'pairing' && conn.channel) {
      const ch = this.channels.get(conn.channel);
      if (ch) this.endChannel(ch, true);
    }
  }

  private onText(conn: Conn, text: string): void {
    if (text.length > 65536) return this.close(conn, 4000);
    let msg: Record<string, unknown>;
    try {
      msg = JSON.parse(text) as Record<string, unknown>;
    } catch {
      return this.close(conn, 4000);
    }
    if (conn.state === 'hello') {
      if (msg.type === 'register') return this.register(conn, msg);
      if (msg.type === 'pair') return this.pair(conn, msg);
      return this.close(conn, 4000);
    }
    if (conn.state === 'pairing') {
      if (msg.type === 'pairEnd') {
        const ch = conn.channel ? this.channels.get(conn.channel) : undefined;
        if (ch) this.endChannel(ch, true);
      }
      return;
    }
    if (conn.state !== 'registered') return;
    const isPrimary = conn.node === conn.network;
    switch (msg.type) {
      case 'roster':
        if (isPrimary) this.pushRoster(conn, msg.roster);
        return;
      case 'usage':
        if (!isPrimary) {
          conn.sock.sendText(JSON.stringify({ type: 'error', code: 'forbidden', id: msg.id }));
          return;
        }
        conn.sock.sendText(JSON.stringify(this.usage(conn.network!, msg.id)));
        return;
      case 'pairEnd': {
        const ch = typeof msg.channel === 'string' ? this.channels.get(msg.channel) : undefined;
        if (ch && ch.primary === conn) this.endChannel(ch, false);
        return;
      }
      default:
        conn.sock.sendText(JSON.stringify({ type: 'error', code: 'bad_request', message: `unknown type ${String(msg.type)}` }));
    }
  }

  private register(conn: Conn, msg: Record<string, unknown>): void {
    const { network, node, ed25519, ts, sig, roster } = msg;
    if (
      typeof network !== 'string' ||
      typeof node !== 'string' ||
      typeof ed25519 !== 'string' ||
      typeof ts !== 'number' ||
      typeof sig !== 'string' ||
      typeof roster !== 'object'
    ) {
      return this.close(conn, 4000);
    }
    let key: Uint8Array;
    let signature: Uint8Array;
    try {
      key = fromB64uLen(ed25519, 32, 'ed25519');
      signature = fromB64uLen(sig, 64, 'sig');
    } catch {
      return this.close(conn, 4000);
    }
    if (nodeIdFromEd25519(key) !== node) return this.close(conn, 4007);
    const signed = registerSigningBytes({ network, node, challenge: conn.challenge, ts, origin: this.origin });
    if (!ed25519Verify(signature, signed, key)) return this.close(conn, 4007);
    if (Math.abs(this.now() - ts) > 300_000) return this.close(conn, 4007);
    if (rosterProblem(roster) !== null || (roster as Roster).network !== network) return this.close(conn, 4008);
    // The effective roster is the newer of the presented one and the relay's.
    const presented = roster as Roster;
    const held = this.rosters.get(network);
    const effective = held && held.version > presented.version ? held : presented;
    if (effective === presented) this.rosters.set(network, presented);
    if (!findMember(effective, node)) return this.close(conn, 4008);
    let net = this.conns.get(network);
    if (!net) this.conns.set(network, (net = new Map()));
    const old = net.get(node);
    conn.state = 'registered';
    conn.network = network;
    conn.node = node;
    net.set(node, conn);
    if (old) old.sock.close(4005);
    const registered: Record<string, unknown> = { type: 'registered', node, rosterVersion: effective.version };
    if (effective !== presented) registered.roster = effective;
    conn.sock.sendText(JSON.stringify(registered));
  }

  private pushRoster(conn: Conn, roster: unknown): void {
    const held = this.rosters.get(conn.network!);
    if (rosterProblem(roster) !== null) return;
    const r = roster as Roster;
    if (r.network !== conn.network || (held && r.version <= held.version)) return;
    this.rosters.set(r.network, r);
    if (!this.enforceRoster) return;
    for (const [node, c] of [...(this.conns.get(r.network) ?? [])]) {
      if (!findMember(r, node)) c.sock.close(4008);
    }
  }

  private usage(network: string, id: unknown): Record<string, unknown> {
    const roster = this.rosters.get(network)!;
    const net = this.conns.get(network) ?? new Map();
    let total = 0;
    const members = roster.members.map((m) => {
      const bytes = this.bytesFrom.get(m.id) ?? 0;
      total += bytes;
      return { id: m.id, bytesHour: bytes, bytesDay: bytes, connected: net.has(m.id) };
    });
    return {
      type: 'usage',
      id,
      network: {
        bytesHour: total,
        bytesDay: total,
        connections: net.size,
        limits: { rateBps: 0, quotaBytesHour: 0, trickleBps: 0 },
        quotaUsed: 0,
        slowed: false,
      },
      members,
    };
  }

  private pair(conn: Conn, msg: Record<string, unknown>): void {
    if (typeof msg.network !== 'string' || typeof msg.code !== 'string') return this.close(conn, 4000);
    const primary = this.conns.get(msg.network)?.get(msg.network);
    if (!primary) {
      conn.sock.sendText(JSON.stringify({ type: 'error', code: 'unreachable' }));
      return this.close(conn, 1000);
    }
    const id = b64u(new Uint8Array(randomBytes(16)));
    const ch: Channel = {
      id,
      network: msg.network,
      newcomer: conn,
      primary,
      timer: setTimeout(() => this.endChannel(ch, true), 60_000),
    };
    this.channels.set(id, ch);
    conn.state = 'pairing';
    conn.channel = id;
    conn.sock.sendText(JSON.stringify({ type: 'pairing', channel: id }));
    primary.sock.sendText(JSON.stringify({ type: 'pairing', channel: id, code: msg.code }));
  }

  /** Ends a channel; `tellPrimary` when the primary did not end it itself. */
  private endChannel(ch: Channel, tellPrimary: boolean): void {
    if (!this.channels.delete(ch.id)) return;
    clearTimeout(ch.timer);
    if (tellPrimary && ch.primary.state === 'registered') {
      ch.primary.sock.sendText(JSON.stringify({ type: 'pairEnd', channel: ch.id }));
    }
    if (ch.newcomer.state === 'pairing') this.close(ch.newcomer, 1000);
  }

  private onBinary(conn: Conn, bytes: Uint8Array): void {
    if (bytes.length > MAX_FRAME) return this.close(conn, 4000);
    let f;
    try {
      f = decodeFrame(bytes);
    } catch {
      return this.close(conn, 4000);
    }
    if (conn.state === 'pairing') {
      const ch = conn.channel ? this.channels.get(conn.channel) : undefined;
      if (f.type !== FrameType.Pair || !ch || b64u(f.peer) !== ch.id) return;
      ch.primary.sock.sendBinary(bytes);
      return;
    }
    if (conn.state !== 'registered') return this.close(conn, 4000);
    const from = conn.node!;
    if (f.type === FrameType.Pair) {
      const ch = this.channels.get(b64u(f.peer));
      if (ch && ch.primary === conn) ch.newcomer.sock.sendBinary(bytes);
      return;
    }
    if (![FrameType.HandshakeInit, FrameType.HandshakeResp, FrameType.Data, FrameType.Refused].includes(f.type as 1)) return;
    const to = nodeIdFromBytes(f.peer);
    this.bytesFrom.set(from, (this.bytesFrom.get(from) ?? 0) + bytes.length);
    const entry = { from, to, type: f.type, size: bytes.length };
    this.frameLog.push(entry);
    const verdict = this.filter?.(entry) ?? 'pass';
    if (verdict === 'drop') return;
    const target = verdict === 'unreachable' ? undefined : this.conns.get(conn.network!)?.get(to);
    if (!target) {
      conn.sock.sendBinary(encodeFrame(FrameType.Unreachable, f.peer, new Uint8Array(0)));
      return;
    }
    target.sock.sendBinary(encodeFrame(f.type, nodeIdToBytes(from), f.body));
  }
}
