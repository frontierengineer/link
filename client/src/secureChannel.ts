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
// Version 1 is the original header. Version 2 differs in ONE way: a Pair header
// carries an 8-byte code id (below). A host accepts both, so a v1 client keeps
// pairing against a v2 host forever; a client only sends v2 when it was actually
// given a code id to send.
export const VERSION = 1;
export const VERSION_CODE_ID = 2;

// — why a pairing code needs a public id —
//
// A host can only run SPAKE2 with ONE password per handshake: it must commit to
// `w` before it sends its share, so it cannot try several codes against one
// attempt. That is why a host used to hold exactly one live pairing code, and
// why opening a second silently killed the first.
//
// The fix is for the CLIENT to say which code it holds. The id is public,
// random, and — critically — has NOTHING to do with the code: it is not derived
// from it, so it leaks no guessing advantage to a relay that watches every byte
// of it. SPAKE2's online-guessing bound is untouched. The id travels with the
// code wherever the code already travels (the pairing URL, the installer
// one-liner), because it is not a second secret to keep.
//
// It rides in the header, which is the SPAKE2 AAD, so it is bound into the
// transcript: a relay that swapped the id would break the handshake rather than
// silently steer the client onto a different code.
export const CODE_ID_LEN = 8;

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
  codeId?: Uint8Array; // present iff mode === Pair AND the client was given one
}

export function encodeHeader(h: Header): Uint8Array {
  // The version is a FUNCTION of the content, so encode(decode(x)) === x for
  // every header on the wire. That identity is load-bearing: this output is the
  // SPAKE2 AAD, rebuilt independently on both sides from their own decoded
  // header, and a byte of disagreement fails the handshake with no clue why.
  const carriesCodeId = h.mode === Mode.Pair && !!h.codeId;
  const w = new Writer().bytes(MAGIC).u8(carriesCodeId ? VERSION_CODE_ID : VERSION).u8(h.mode);
  if (h.mode === Mode.Reconnect) {
    if (!h.keyId || h.keyId.length !== KEY_ID_LEN) throw new Error('reconnect header needs a 16-byte keyId');
    w.bytes(h.keyId);
  }
  if (carriesCodeId) {
    if (h.codeId!.length !== CODE_ID_LEN) throw new Error(`a pair header's code id must be ${CODE_ID_LEN} bytes`);
    w.bytes(h.codeId!);
  }
  return w.finish();
}

// — reconnect refusal signal —
//
// When the host refuses a reconnect (the device was revoked / is unknown), it
// must tell the CLIENT so, distinguishably from "the relay briefly dropped us".
// A WebSocket close reason cannot carry that: the relay splices two sockets and
// rewrites the close code/reason to its own `peer gone` when either end drops. So
// the signal has to be a DATA frame, which the relay forwards verbatim. This frame
// is sent where the host's Noise msg2 would go; it is unambiguous because a real
// msg2 is a >=48-byte Noise message, never a 6-byte `MAGIC ‖ 0x00 ‖ reason`.
const REFUSE = 0x00; // discriminator after MAGIC (a header uses VERSION=1 here)
export const RefuseReason = { revoked: 1 } as const;

export function encodeRefusal(reason: number): Uint8Array {
  return new Writer().bytes(MAGIC).u8(REFUSE).u8(reason).finish();
}

// Return the refusal reason if `frame` is a refusal control frame, else null (so a
// genuine Noise msg2 falls through to the handshake). A real handshake message is
// far larger than this and does not begin with MAGIC+REFUSE.
export function parseRefusal(frame: Uint8Array): number | null {
  if (frame.length !== MAGIC.length + 2) return null;
  if (!equalCt(frame.subarray(0, MAGIC.length), MAGIC)) return null;
  if (frame[MAGIC.length] !== REFUSE) return null;
  return frame[MAGIC.length + 1]!;
}

export function decodeHeader(frame: Uint8Array): Header {
  const r = new Reader(frame);
  const magic = r.bytes(MAGIC.length);
  if (!equalCt(magic, MAGIC)) throw new Error('bad protocol magic');
  const version = r.u8();
  if (version !== VERSION && version !== VERSION_CODE_ID) throw new Error(`unsupported protocol version ${version}`);
  const mode = r.u8();
  if (mode === Mode.Reconnect) {
    const keyId = r.bytes(KEY_ID_LEN).slice();
    return { mode, keyId };
  }
  if (mode === Mode.Pair) {
    // A v1 client names no code, and a v2 host still serves it from its legacy
    // single slot — which is what keeps every daemon already in the field
    // pairing after this ships.
    if (version !== VERSION_CODE_ID) return { mode };
    return { mode, codeId: r.bytes(CODE_ID_LEN).slice() };
  }
  if (mode === Mode.Recover) {
    // Recovery has one high-entropy key, never a set, so a code id is
    // meaningless here and is refused rather than quietly ignored.
    if (version === VERSION_CODE_ID) throw new Error('a recover header cannot carry a code id');
    return { mode };
  }
  throw new Error(`unknown mode ${mode}`);
}

// — the sealed transport —

export class SealedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SealedError';
  }
}

// The host refused the reconnect because this device's credential is unknown or
// was REVOKED. Unlike a transient drop, this is terminal: the same credential will
// be refused at every uplink (revocation lives at the host, not the Link), so the
// managed connection stops retrying and the app should forget the credential and
// re-pair. It extends SealedError so any handshake-error catch still treats it as a
// failed handshake; callers that care distinguish it by type.
export class DeviceRevokedError extends SealedError {
  constructor(message = 'reconnect refused: unknown or revoked device') {
    super(message);
    this.name = 'DeviceRevokedError';
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
  // Before treating it as Noise msg2: a refusal frame here means the host declined
  // to authenticate us (revoked / unknown device) — a typed, terminal error.
  if (parseRefusal(msg2) === RefuseReason.revoked) throw new DeviceRevokedError();
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
  if (!token) {
    // Tell the client it was revoked (a data frame the relay forwards verbatim; a
    // close reason would be rewritten by the relay), then abort. This is the "failed
    // auth" signal a revoked device needs so it stops retrying and re-pairs.
    pipe.send(encodeRefusal(RefuseReason.revoked));
    throw new DeviceRevokedError();
  }
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
  // 'cap' is the capability hello, consumed by the session itself and never
  // surfaced to the application (see PAYLOAD FRAMING below).
  t: 'req' | 'res' | 'evt' | 'cap';
  id?: number;
  cmd?: unknown;
  ok?: boolean;
  data?: unknown;
  error?: string;
  // 'cap' only: the envelope versions this peer can READ.
  env?: number[];
}

// — PAYLOAD FRAMING: how bulk rides without base64 —
//
// The sealed plaintext used to be exactly `JSON.stringify(envelope)`. That makes
// every byte of application data JSON, so anything binary — audio, a terminal's
// output, a forwarded port's traffic, a file — has to be base64'd by the caller:
// 33% more bytes through the AEAD, the relay, and both ends' JSON parsers, to
// carry bytes that were already bytes.
//
// So a plaintext may now instead be:
//
//   offset 0        1 byte    ENVELOPE_VERSION (0x01)
//   offset 1        4 bytes   metaLen, unsigned big-endian
//   offset 5        metaLen   the JSON envelope, UTF-8 — unchanged in shape
//   offset 5+metaLen …        the payload: raw bytes, to the END of the plaintext
//
// The payload's length is IMPLICIT (plaintext length − 5 − metaLen), so there is
// exactly one length on the wire and no second one that can disagree with it.
// Zero remaining bytes means no payload, which is what every ordinary frame
// sends and is byte-for-byte the case a legacy frame already covered.
//
// A reader tells the two apart from the FIRST BYTE: 0x01 is a framed plaintext,
// and '{' (0x7B) is a legacy JSON one. Unambiguous, one comparison, no state.
//
// NEGOTIATION, and why it is one-directional. Reading both forms is safe and
// unconditional. SENDING the framed form is not: a peer that predates this
// cannot parse it and would fail its JSON.parse — fatally, since an
// unparseable plaintext ends the session. So each end announces what it can
// READ, once, as a legacy-JSON 'cap' frame at session start, and only sends
// framed AFTER it has seen the peer's announcement. A peer that never sends one
// is legacy and simply keeps receiving legacy frames forever. An unknown
// envelope type has always been ignored by dispatch(), so a legacy peer
// discards our hello rather than choking on it.
//
// The legacy READ path is removed one release after this ships stable; the
// removal note lives at the read site in readLoop().

/** The version byte every framed plaintext starts with. */
export const ENVELOPE_VERSION = 0x01;

/** The first byte of a legacy plaintext: '{', the start of its JSON. */
const LEGACY_FIRST_BYTE = 0x7b;

/** The envelope versions this build can READ, announced in the 'cap' hello. */
const READABLE_ENVELOPES = [ENVELOPE_VERSION];

/**
 * Frame one plaintext: version, meta length, meta, payload. Exported because it
 * is the definition of the wire — the tests assert against it, and the native
 * shells port it byte for byte.
 */
export function frameSealedPlaintext(metaJson: string, payload: Uint8Array): Uint8Array {
  const meta = utf8(metaJson);
  return new Writer().u8(ENVELOPE_VERSION).u32(meta.length).bytes(meta).bytes(payload).finish();
}

/**
 * The inverse. Returns the JSON meta and the payload (a view's copy, so the
 * caller owns it), or null when this plaintext is not framed — which is how a
 * legacy frame is recognised rather than guessed at.
 */
export function parseSealedPlaintext(plain: Uint8Array): { meta: string; payload: Uint8Array } | null {
  if (plain.length < 1 || plain[0] !== ENVELOPE_VERSION) return null;
  if (plain.length < 5) throw new SealedError('framed plaintext is too short for its length prefix');
  const r = new Reader(plain);
  r.u8();
  const metaLen = r.u32();
  // A length that runs past the plaintext is a corrupt or hostile frame. It
  // cannot be tolerated quietly: the AEAD already proved the bytes are authentic,
  // so a bad length here means the PEER built a bad frame, which is a bug worth
  // failing loudly rather than reading a truncated envelope.
  if (5 + metaLen > plain.length) throw new SealedError('framed plaintext meta length runs past the frame');
  const meta = fromUtf8(r.bytes(metaLen));
  return { meta, payload: plain.slice(5 + metaLen) };
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
  private readonly listeners = new Set<(data: unknown, payload?: Uint8Array) => void>();
  private readonly onRequest: RequestHandler | undefined;
  private readonly requestTimeoutMs: number;
  private readonly idleTimeoutMs: number;
  private idleTimer: NodeJS.Timeout | undefined;
  private alive = true;
  // Set when the peer has announced it can READ framed plaintexts. Until then
  // every frame we send is legacy JSON, because a peer that predates the
  // envelope dies on one it cannot parse.
  private peerReadsFramed = false;
  private resolveDone!: (info: { reason?: string }) => void;
  readonly done: Promise<{ reason?: string }> = new Promise((r) => (this.resolveDone = r));

  constructor(private readonly pipe: Pipe, private readonly transport: Transport, opts: SessionOptions = {}) {
    this.onRequest = opts.onRequest;
    this.requestTimeoutMs = opts.requestTimeoutMs ?? 30_000;
    this.idleTimeoutMs = opts.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT_MS;
    this.bumpIdle(); // arm the idle window; it resets on every frame either direction
    void this.readLoop();
    // Announce what we can read, before anything else goes out. Always as legacy
    // JSON: at this instant we know nothing about the peer, and this frame is
    // precisely what teaches it. A legacy peer ignores an unknown envelope type.
    this.safeSend(this.encodeLegacy({ t: 'cap', env: READABLE_ENVELOPES }));
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

  /**
   * True once the peer has announced it can read framed plaintexts, i.e. once
   * sendWithPayload will work. Callers that have a fallback (send the bulk some
   * slower way) read this and choose; callers that do not can let
   * sendWithPayload throw.
   *
   * It is false at session start and flips once, early — the peer's hello is the
   * first thing it sends. A caller deciding per stream rather than per frame
   * should read it when the stream STARTS.
   */
  get supportsPayload(): boolean {
    return this.peerReadsFramed;
  }

  /**
   * Fire-and-forget event whose bulk rides as RAW BYTES beside the JSON, instead
   * of base64 inside it.
   *
   * Throws when the peer has not announced support, rather than silently
   * base64-ing into `data`: a caller reaching for this has bytes worth not
   * encoding, and quietly doing the thing it asked to avoid — at a size where it
   * costs most — is the wrong answer. Check supportsPayload first.
   */
  sendWithPayload(data: unknown, payload: Uint8Array): void {
    if (!this.alive) return;
    if (!this.peerReadsFramed) {
      throw new SealedError('the peer has not announced the binary envelope; check supportsPayload first');
    }
    this.safeSend(this.encode({ t: 'evt', data }, payload));
  }

  // Subscribe to peer events; returns an unsubscribe function. `payload` is
  // present only for a peer that sent one, and is undefined for every ordinary
  // frame — so an existing one-argument listener is unaffected.
  onMessage(fn: (data: unknown, payload?: Uint8Array) => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  close(reason = 'closed by application'): void {
    this.shutdown(reason);
  }

  /**
   * Encode one envelope for the wire: framed once the peer has announced it can
   * read that, legacy JSON until then. A payload is only ever possible on the
   * framed path, which is why sendWithPayload gates on the same flag.
   */
  private encode(env: Envelope, payload: Uint8Array = EMPTY): Uint8Array {
    if (!this.peerReadsFramed) {
      if (payload.length) throw new SealedError('cannot send a payload to a peer that has not announced the binary envelope');
      return this.encodeLegacy(env);
    }
    return seal(this.transport.send, frameSealedPlaintext(JSON.stringify(env), payload));
  }

  /** The pre-envelope encoding: the bare JSON, sealed. Also what the capability
   *  hello itself always uses, since it is what teaches the peer the other form. */
  private encodeLegacy(env: Envelope): Uint8Array {
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
      let payload: Uint8Array | undefined;
      try {
        const plain = open(this.transport.recv, frame);
        // Both forms are read, always: the first byte says which (0x01 framed,
        // '{' legacy) and there is no state to get wrong.
        //
        // REMOVAL TRIGGER: the legacy branch goes one release after the release
        // that first carried this reaches stable — by then no peer in the window
        // can still be sending it. Deleting it means dropping the else-branch
        // below and making a non-0x01 first byte a hard error.
        const framed = parseSealedPlaintext(plain);
        if (framed) {
          env = JSON.parse(framed.meta) as Envelope;
          if (framed.payload.length) payload = framed.payload;
        } else {
          if (plain.length && plain[0] !== LEGACY_FIRST_BYTE) {
            throw new SealedError('plaintext is neither a framed envelope nor JSON');
          }
          env = JSON.parse(fromUtf8(plain)) as Envelope;
        }
      } catch (e) {
        // An authentication failure is fatal and security-relevant: stop.
        this.shutdown(e instanceof Error ? e.message : 'bad frame');
        return;
      }
      await this.dispatch(env, payload);
    }
  }

  private async dispatch(env: Envelope, payload?: Uint8Array): Promise<void> {
    switch (env.t) {
      case 'cap': {
        // The peer announced what it can read. Upgrade only on a version we
        // actually emit; anything else leaves us on the legacy path, which is
        // always readable. Never surfaced to the application.
        const versions = Array.isArray(env.env) ? env.env : [];
        if (versions.includes(ENVELOPE_VERSION)) this.peerReadsFramed = true;
        return;
      }
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
            fn(env.data, payload);
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
