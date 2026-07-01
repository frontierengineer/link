// The end-to-end layer: it turns a raw Pipe into an authenticated, sealed,
// always-on encrypted session. Two handshakes feed it:
//   • reconnect — Noise NKpsk0 (here): the host is authenticated by its pinned
//     static key, the client by possession of its device token (the PSK).
//   • first-pair / recovery — SPAKE2 (in pairing.ts), which produces a shared
//     secret this module turns into the same sealed transport.
// After either, app traffic rides a SealedStream: per-direction ChaCha20-
// Poly1305 with a monotonic, never-transmitted nonce, so tamper, replay, and
// reordering are all rejected by the AEAD. There is no plaintext mode.

import { HandshakeState, PATTERNS, type Transport, CipherState } from './noise.js';
import { type KeyPair, hkdfSha256 } from './crypto.js';
import { type Pipe } from './pipe.js';
import { Reader, Writer, equalCt, utf8, fromUtf8 } from './bytes.js';

const EMPTY = new Uint8Array(0);

// — wire framing for the handshake header (the first frame, client→host) —

export const MAGIC = Uint8Array.of(0x46, 0x4c, 0x6b, 0x31); // "FLk1"
export const VERSION = 1;

export enum Mode {
  Pair = 1, // SPAKE2 with a short code
  Recover = 2, // SPAKE2 with a high-entropy recovery key
  Reconnect = 3, // Noise NKpsk0 with the pinned static key + token
}

export const KEY_ID_LEN = 16;
export const TOKEN_LEN = 32;
export const STATIC_PUB_LEN = 32;

export interface Header {
  mode: Mode;
  keyId?: Uint8Array; // present iff mode === Reconnect
}

export function encodeHeader(h: Header): Uint8Array {
  const w = new Writer().bytes(MAGIC).u8(VERSION).u8(h.mode);
  if (h.mode === Mode.Reconnect) {
    if (!h.keyId || h.keyId.length !== KEY_ID_LEN) throw new Error('reconnect header needs a 16-byte keyId');
    w.bytes(h.keyId);
  }
  return w.finish();
}

export function decodeHeader(frame: Uint8Array): Header {
  const r = new Reader(frame);
  const magic = r.bytes(MAGIC.length);
  if (!equalCt(magic, MAGIC)) throw new Error('bad protocol magic');
  const version = r.u8();
  if (version !== VERSION) throw new Error(`unsupported protocol version ${version}`);
  const mode = r.u8();
  if (mode === Mode.Reconnect) {
    const keyId = r.bytes(KEY_ID_LEN).slice();
    return { mode, keyId };
  }
  if (mode === Mode.Pair || mode === Mode.Recover) return { mode };
  throw new Error(`unknown mode ${mode}`);
}

// — the sealed transport —

export class SealedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SealedError';
  }
}

// A pending request was abandoned because the session dropped (not an
// application-level failure). The managed connection retries these across a
// reconnect; callers of a bare SecureSession see them as a normal rejection.
export class SessionClosedError extends Error {
  constructor(reason: string) {
    super(`session closed: ${reason}`);
    this.name = 'SessionClosedError';
  }
}

// Seal one application frame for transmission. Delegates to the send-direction
// CipherState, whose counter advances on every call, so two identical
// plaintexts produce different ciphertexts and the peer rejects any frame that
// arrives out of counter order.
export function seal(send: CipherState, plaintext: Uint8Array): Uint8Array {
  return send.encryptWithAd(EMPTY, plaintext);
}

// Open one received frame. Throws SealedError on any authentication failure —
// the caller MUST tear the session down rather than continue, because a failure
// means the stream was tampered with, replayed, reordered, or truncated.
export function open(recv: CipherState, frame: Uint8Array): Uint8Array {
  try {
    return recv.decryptWithAd(EMPTY, frame);
  } catch {
    throw new SealedError('sealed frame failed authentication (tamper/replay/reorder)');
  }
}

// Build a transport from a raw shared secret (the SPAKE2 output). The two
// directions get independent keys via HKDF, oriented by role so client and host
// agree on which key seals which direction. `initiator` is the client; `salt`
// binds the keys to the handshake transcript (the SPAKE2 transcript hash).
export function transportFromSecret(secret: Uint8Array, initiator: boolean, salt: Uint8Array): Transport {
  // Two 32-byte keys: k1 = client->host, k2 = host->client.
  const okm = hkdfSha256(secret, salt, utf8('FrontierLink/transport/v1'), 64);
  const c1 = new CipherState(okm.slice(0, 32));
  const c2 = new CipherState(okm.slice(32, 64));
  return initiator
    ? { send: c1, recv: c2, handshakeHash: salt }
    : { send: c2, recv: c1, handshakeHash: salt };
}

// — Noise NKpsk0 reconnect (the runtime handshake) —

export interface ReconnectInitiatorOptions {
  hostStaticPub: Uint8Array; // the pinned key
  token: Uint8Array; // the device token, used as the Noise PSK
  keyId: Uint8Array; // routes the host to the right token
  handshakeTimeoutMs?: number;
}

// Drive the client (initiator) side. Returns the live transport, or throws if
// the host could not be authenticated (wrong/substituted static key) or the
// token was rejected — both surface as an AEAD failure on the second message.
export async function reconnectInitiator(pipe: Pipe, opts: ReconnectInitiatorOptions): Promise<Transport> {
  const timeout = opts.handshakeTimeoutMs ?? 10_000;
  const header = encodeHeader({ mode: Mode.Reconnect, keyId: opts.keyId });
  const hs = new HandshakeState({
    pattern: PATTERNS.NKpsk0!,
    initiator: true,
    prologue: header,
    rs: opts.hostStaticPub,
    psk: opts.token,
  });
  // F0: the header (becomes the prologue both sides bind to). F1: Noise msg1.
  pipe.send(header);
  const { message: msg1 } = hs.writeMessage(EMPTY);
  pipe.send(msg1);
  const msg2 = await pipe.recv(timeout);
  const { transport } = hs.readMessage(msg2);
  if (!transport) throw new SealedError('reconnect: handshake did not complete');
  return transport;
}

export interface ReconnectResponderOptions {
  hostStatic: KeyPair;
  // Look up the token for a key id; return undefined to refuse (unknown or
  // revoked device). The lookup is the revocation point.
  resolveToken: (keyId: Uint8Array) => Uint8Array | undefined;
  handshakeTimeoutMs?: number;
}

export interface ReconnectResult {
  transport: Transport;
  keyId: Uint8Array;
}

// Drive the host (responder) side after the header frame has been read. Throws
// if the device is unknown/revoked or the client fails to prove the token.
export async function reconnectResponder(pipe: Pipe, header: Header, opts: ReconnectResponderOptions): Promise<ReconnectResult> {
  const timeout = opts.handshakeTimeoutMs ?? 10_000;
  if (header.mode !== Mode.Reconnect || !header.keyId) throw new Error('reconnectResponder: not a reconnect header');
  const token = opts.resolveToken(header.keyId);
  if (!token) throw new SealedError('reconnect refused: unknown or revoked device');
  const hs = new HandshakeState({
    pattern: PATTERNS.NKpsk0!,
    initiator: false,
    prologue: encodeHeader(header),
    s: opts.hostStatic,
    psk: token,
  });
  const msg1 = await pipe.recv(timeout);
  hs.readMessage(msg1); // throws if the token (PSK) or static DH is wrong
  const { message: msg2, transport } = hs.writeMessage(EMPTY);
  pipe.send(msg2);
  if (!transport) throw new SealedError('reconnect: handshake did not complete');
  return { transport, keyId: header.keyId };
}

// — the application session over a completed transport —

export type RequestHandler = (cmd: unknown) => unknown | Promise<unknown>;

interface Envelope {
  t: 'req' | 'res' | 'evt';
  id?: number;
  cmd?: unknown;
  ok?: boolean;
  data?: unknown;
  error?: string;
}

export interface SessionOptions {
  onRequest?: RequestHandler;
  requestTimeoutMs?: number;
  // Defense-in-depth idle reaper: tear the session down after this many ms with
  // NO frame in EITHER direction. There is no ping/pong, so a genuinely silent
  // session would otherwise linger (host-side, bounded only by the relay's idle
  // policy). The window resets on every frame SENT or RECEIVED, so a session that
  // is actively used in either direction — e.g. a host streaming an event feed to
  // an otherwise-quiet client — is never reaped; only one silent BOTH ways is. The
  // default is generous (10 min) and the managed client auto-reconnects, so a
  // reaped-for-idle session is harmless. (A half-dead peer is still caught by the
  // ws/TCP layer + the relay's idle policy + send-backpressure errors.) Override
  // per end as needed.
  idleTimeoutMs?: number;
}

// Generous so ordinary request/response/event traffic resets it long before it
// fires; only a truly silent session is reaped.
const DEFAULT_IDLE_TIMEOUT_MS = 10 * 60_000;

// A small request/response + event protocol, every frame sealed. Both ends can
// request and emit events; the host typically sets onRequest, the client calls
// request(). The read loop fails the whole session on the first authentication
// error — there is no "skip a bad frame".
export class SecureSession {
  private nextId = 1;
  private readonly pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void; timer: NodeJS.Timeout }>();
  private readonly listeners = new Set<(data: unknown) => void>();
  private readonly onRequest: RequestHandler | undefined;
  private readonly requestTimeoutMs: number;
  private readonly idleTimeoutMs: number;
  private idleTimer: NodeJS.Timeout | undefined;
  private alive = true;
  private resolveDone!: (info: { reason?: string }) => void;
  readonly done: Promise<{ reason?: string }> = new Promise((r) => (this.resolveDone = r));

  constructor(private readonly pipe: Pipe, private readonly transport: Transport, opts: SessionOptions = {}) {
    this.onRequest = opts.onRequest;
    this.requestTimeoutMs = opts.requestTimeoutMs ?? 30_000;
    this.idleTimeoutMs = opts.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT_MS;
    this.bumpIdle(); // arm the idle window; it resets on every frame either direction
    void this.readLoop();
    void this.pipe.closed.then((info) => this.shutdown(info.reason ?? 'pipe closed'));
  }

  get isOpen(): boolean {
    return this.alive;
  }

  // Send a request and await the peer's response. Rejects on timeout, on a
  // peer-reported error, or if the session drops.
  request(cmd: unknown, timeoutMs?: number): Promise<unknown> {
    if (!this.alive) return Promise.reject(new Error('session closed'));
    const id = this.nextId++;
    const frame = this.encode({ t: 'req', id, cmd });
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error('request timed out'));
      }, timeoutMs ?? this.requestTimeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.safeSend(frame);
    });
  }

  // Fire-and-forget event to the peer.
  send(data: unknown): void {
    if (!this.alive) return;
    this.safeSend(this.encode({ t: 'evt', data }));
  }

  // Subscribe to peer events; returns an unsubscribe function.
  onMessage(fn: (data: unknown) => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  close(reason = 'closed by application'): void {
    this.shutdown(reason);
  }

  private encode(env: Envelope): Uint8Array {
    return seal(this.transport.send, utf8(JSON.stringify(env)));
  }

  // Reset the idle window. Called on every frame SENT and every frame RECEIVED, so
  // "idle" means genuinely silent in BOTH directions (a session actively streaming
  // one way stays alive). unref so a quiet session's timer never holds the process.
  private bumpIdle(): void {
    if (!this.alive) return;
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = setTimeout(() => this.shutdown('idle timeout (no traffic either direction)'), this.idleTimeoutMs);
    this.idleTimer.unref?.();
  }

  private safeSend(frame: Uint8Array): void {
    try {
      this.pipe.send(frame);
      this.bumpIdle(); // outbound traffic keeps the session alive
    } catch {
      this.shutdown('send failed');
    }
  }

  private async readLoop(): Promise<void> {
    while (this.alive) {
      let frame: Uint8Array;
      try {
        // The idle reaper is an explicit timer reset on every frame either
        // direction (see bumpIdle), so the recv itself blocks indefinitely; when
        // the window elapses, shutdown() closes the pipe and this recv rejects.
        frame = await this.pipe.recv();
      } catch (e) {
        this.shutdown(e instanceof Error ? e.message : 'recv failed');
        return;
      }
      this.bumpIdle(); // inbound traffic keeps the session alive
      let env: Envelope;
      try {
        const plain = open(this.transport.recv, frame);
        env = JSON.parse(fromUtf8(plain)) as Envelope;
      } catch (e) {
        // An authentication failure is fatal and security-relevant: stop.
        this.shutdown(e instanceof Error ? e.message : 'bad frame');
        return;
      }
      await this.dispatch(env);
    }
  }

  private async dispatch(env: Envelope): Promise<void> {
    switch (env.t) {
      case 'res': {
        if (env.id === undefined) return;
        const waiter = this.pending.get(env.id);
        if (!waiter) return;
        this.pending.delete(env.id);
        clearTimeout(waiter.timer);
        if (env.ok) waiter.resolve(env.data);
        else waiter.reject(new Error(env.error ?? 'request failed'));
        return;
      }
      case 'req': {
        if (env.id === undefined) return;
        if (!this.onRequest) {
          this.safeSend(this.encode({ t: 'res', id: env.id, ok: false, error: 'no request handler' }));
          return;
        }
        try {
          const data = await this.onRequest(env.cmd);
          this.safeSend(this.encode({ t: 'res', id: env.id, ok: true, data }));
        } catch (e) {
          this.safeSend(this.encode({ t: 'res', id: env.id, ok: false, error: e instanceof Error ? e.message : 'handler error' }));
        }
        return;
      }
      case 'evt': {
        for (const fn of this.listeners) {
          try {
            fn(env.data);
          } catch {
            /* a listener throwing must not kill the session */
          }
        }
        return;
      }
      default:
        return;
    }
  }

  private shutdown(reason: string): void {
    if (!this.alive) return;
    this.alive = false;
    if (this.idleTimer) { clearTimeout(this.idleTimer); this.idleTimer = undefined; }
    for (const [, waiter] of this.pending) {
      clearTimeout(waiter.timer);
      waiter.reject(new SessionClosedError(reason));
    }
    this.pending.clear();
    this.listeners.clear();
    // Always tear the underlying socket down. Otherwise a single tampered frame
    // (which stops the read loop) would leak the pipe — unbounded on direct
    // paths the relay does not reap. close() is idempotent, so the constructor's
    // `pipe.closed -> shutdown` path does not loop.
    this.pipe.close(reason);
    this.resolveDone({ reason });
  }
}
