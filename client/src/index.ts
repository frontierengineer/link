// Public API. Two calls cover the whole model:
//   • connect()   — a client opens an already-secure, auto-reconnecting channel
//                   to a host (first-pair with a code, or reconnect with a stored
//                   credential).
//   • serveHost() — a host registers with N uplinks, accepts introduced clients,
//                   runs the host handshake, issues/verifies credentials, revokes.
// Everything below composes the audited layers: linkClient (transport),
// secureChannel (Noise + sealed stream), pairing (SPAKE2 + credentials).

import { establish, HostUplinks, type Reach, type DialOptions, type LinkUsage, type OpenSocket } from './linkClient.js';
import {
  Mode,
  reconnectInitiator,
  reconnectResponder,
  SecureSession,
  SessionClosedError,
  DeviceRevokedError,
  decodeHeader,
  CODE_ID_LEN,
  type Header,
  type RequestHandler,
  type SessionOptions,
} from './secureChannel.js';
import {
  spakeClient,
  spakeHost,
  TokenStore,
  CodeLockout,
  PairingAuthError,
  credentialToString,
  credentialFromString,
  type DeviceCredential,
  type IssuedDevice,
} from './pairing.js';
import { x25519Keygen, type KeyPair } from './crypto.js';
import { registerSignerFromStatic, addressForRegisterKey } from './registerAuth.js';
import type { Pipe } from './pipe.js';
import { utf8, toB64url, fromB64url, randomBytes } from './bytes.js';

export { Mode, SecureSession } from './secureChannel.js';
// The envelope's framing, exported because a peer that FORWARDS these frames
// needs the same definition of them the sealed channel uses. The desktop edge is
// exactly that peer: it receives a meta+payload frame over the sealed channel and
// re-emits it to a browser on its own socket, and a second, hand-written copy of
// the wire in the component whose whole job is passing the bytes through
// unchanged is the copy most likely to drift and the hardest place to notice it.
// docs/PROTOCOL.md §6 is the normative description; these are its implementation.
export { ENVELOPE_VERSION, frameSealedPlaintext, parseSealedPlaintext } from './secureChannel.js';
export {
  TokenStore,
  CodeLockout,
  PairingAuthError,
  credentialToString,
  credentialFromString,
  type DeviceCredential,
  type IssuedDevice,
} from './pairing.js';
export { memoryPipePair, type Pipe } from './pipe.js';
export type { KeyPair } from './crypto.js';
// Authenticated address registration (anti-squat). serveHost wires this in
// automatically; the named exports let a host that manages its own uplink sockets
// sign its registers the same way, so every address it owns is registered signed.
export {
  registerSignerFromStatic,
  makeRegisterAuth,
  registerSigningMessage,
  addressForRegisterKey,
  type RegisterSigner,
  type RegisterAuth,
} from './registerAuth.js';
// A revoked/unknown device's reconnect surfaces this (terminal, not transient).
export { DeviceRevokedError } from './secureChannel.js';
// Per-connection relay usage (fractions / unlimited) — see serveHost onUsage.
export type { LinkUsage } from './linkClient.js';
// The transport seam. A caller in a realm `ws` does not serve — a browser — says
// what dials instead of the package deciding for it: pass `openSocket` on
// `ConnectOptions.dial` or `ServeHostOptions`, and `ws` is never loaded.
export type { LinkWebSocket, OpenSocket } from './linkClient.js';

// Generate a fresh host static identity (x25519). The host persists the private
// key; clients pin the public key on first pair. This is the host's long-term
// cryptographic identity — generate once, store securely, reuse forever.
export function generateHostIdentity(): KeyPair {
  return x25519Keygen();
}

// 'revoked' is terminal like 'failed', but specifically means the host refused this
// device's credential (revoked / unknown) — the app should forget the credential
// and drive the user back to pairing rather than retry.
export type ConnState = 'connecting' | 'connected' | 'reconnecting' | 'closed' | 'failed' | 'revoked';

export interface ConnectOptions {
  uplinks: string[];
  // The host's address: its high-entropy, public routing handle. Always required.
  // Knowing it lets a client ASK to be introduced — entry is still gated by the
  // end-to-end handshake below, which the Link cannot see.
  address: string;
  // FIRST PAIR: the short pairing code. Used ONLY as the SPAKE2 secret end-to-end
  // (deriveW); it is NEVER sent to the Link in any form (raw OR hashed), so even a
  // malicious Link cannot recover it or MITM the pairing. Provide it alongside the
  // address (a QR/deep-link payload carries the address; the code is scanned/typed
  // with it). Omit on reconnect/recover.
  code?: string;
  // FIRST PAIR, optional: which of the host's live pairing codes `code` is. The
  // host issues it beside the code and it travels with it (the pairing URL, the
  // installer one-liner). It is public and unrelated to the code — see CODE_ID_LEN
  // in secureChannel.ts — so it can be sent in the clear without weakening SPAKE2.
  // Omit it and the host serves this pair from its single legacy slot, which is
  // what every client built before this does.
  codeId?: string;
  // RECONNECT: a stored credential (token + pinned host static key + address).
  // Omit on first pair; the returned connection carries the new credential to
  // persist.
  credential?: DeviceCredential;
  // RECOVER: a high-entropy secret for cold-start recovery (from-scratch on a new
  // device with no stored credential).
  recoveryKey?: string;
  onState?: (s: ConnState) => void;
  // Optional: handle host-initiated requests/events on this client.
  onRequest?: RequestHandler;
  autoReconnect?: boolean; // default true (ignored for first-pair until paired)
  dial?: DialOptions;
  handshakeTimeoutMs?: number;
  requestTimeoutMs?: number;
  // Reap a session after this many ms with no inbound frame (defense-in-depth;
  // the managed connection auto-reconnects, so an idle-reaped session is
  // transparent). Default 10 min — see SessionOptions.idleTimeoutMs.
  idleTimeoutMs?: number;
  reconnectBackoffMs?: number;
  reconnectMaxBackoffMs?: number;
}

export interface Connection {
  request(cmd: unknown, timeoutMs?: number): Promise<unknown>;
  send(evt: unknown): void;
  /**
   * True when the far end has announced it can read the binary envelope, so
   * sendWithPayload will work. Read it per STREAM rather than caching it: a
   * reconnect builds a fresh session, which re-negotiates, and a peer that was
   * upgraded between two connections changes the answer.
   */
  readonly supportsPayload: boolean;
  /**
   * Fire-and-forget event whose bulk rides as raw bytes beside the JSON rather
   * than base64 inside it. Throws when the far end has not announced support
   * (check supportsPayload) or when the connection has no live session.
   */
  sendWithPayload(evt: unknown, payload: Uint8Array): void;
  onMessage(fn: (data: unknown, payload?: Uint8Array) => void): () => void;
  // The credential to persist. Defined after a successful pair/recovery (or if
  // one was supplied). Pin this and reuse it as `credential` next time.
  readonly credential: DeviceCredential | undefined;
  readonly address: string;
  readonly state: ConnState;
  readonly via: string;
  close(): void;
}

type HandshakeOutcome = { session: SecureSession; credential?: DeviceCredential };

// Open a secure, auto-reconnecting connection. Resolves once the first secure
// session is live; thereafter it transparently fails over across uplinks and
// re-handshakes on drop, using the (possibly newly minted) credential.
export async function connect(opts: ConnectOptions): Promise<Connection> {
  const mc = new ManagedConnection(opts);
  await mc.startFirst();
  return mc;
}

class ManagedConnection implements Connection {
  private _state: ConnState = 'connecting';
  private _credential: DeviceCredential | undefined;
  private _address: string;
  private _via = '';
  private session: SecureSession | undefined;
  private epoch = 0; // bumps on every successful (re)connection
  private readonly listeners = new Set<(data: unknown, payload?: Uint8Array) => void>();
  private readonly connectedWaiters: { resolve: () => void; reject: (e: Error) => void; timer: NodeJS.Timeout }[] = [];
  private readonly epochWaiters: { minEpoch: number; resolve: () => void; reject: (e: Error) => void; timer: NodeJS.Timeout }[] = [];
  private userClosed = false;
  private readonly autoReconnect: boolean;

  constructor(private readonly opts: ConnectOptions) {
    this._credential = opts.credential;
    this.autoReconnect = opts.autoReconnect ?? true;
    this._address = opts.address;
  }

  get state(): ConnState {
    return this._state;
  }
  get credential(): DeviceCredential | undefined {
    return this._credential;
  }
  get address(): string {
    return this._address;
  }
  get via(): string {
    return this._via;
  }

  // First connection: uses the initial mode (pair/recover/reconnect). A failure
  // here rejects connect() — there is no silent retry on the very first attempt,
  // so a wrong code surfaces immediately to the caller.
  async startFirst(): Promise<void> {
    const initial = this.initialMode();
    let outcome: { outcome: HandshakeOutcome; via: string };
    try {
      outcome = await this.attempt(initial.reach, initial.runHandshake);
    } catch (e) {
      // A revoked credential on the very first connect is terminal: reflect it in the
      // state (for onState observers) before rejecting connect().
      if (e instanceof DeviceRevokedError) this.setState('revoked');
      throw e;
    }
    this.adopt(outcome);
    void this.monitor();
  }

  private initialMode(): { reach: Reach; runHandshake: (pipe: Pipe) => Promise<HandshakeOutcome> } {
    const address = this._address;
    if (this.opts.code !== undefined) {
      // First-pair: rendezvous on the address; the code only keys SPAKE2 (deriveW)
      // end-to-end and is NEVER handed to the Link in any form — raw or hashed.
      const code = this.opts.code;
      const codeId = this.opts.codeId;
      return { reach: { address }, runHandshake: (p) => this.runSpake(p, code, Mode.Pair, codeId) };
    }
    if (this._credential) {
      return { reach: { address }, runHandshake: (p) => this.runReconnect(p, this._credential!) };
    }
    if (this.opts.recoveryKey) {
      const rk = this.opts.recoveryKey;
      return { reach: { address }, runHandshake: (p) => this.runSpake(p, rk, Mode.Recover) };
    }
    throw new Error('connect: need a code (first pair), a credential (reconnect), or a recoveryKey (recover)');
  }

  // onRequest + the optional idle-timeout override, shared by every session this
  // connection builds (pair, recover, reconnect).
  private sessionOpts(): SessionOptions {
    return {
      ...(this.opts.onRequest ? { onRequest: this.opts.onRequest } : {}),
      ...(this.opts.idleTimeoutMs !== undefined ? { idleTimeoutMs: this.opts.idleTimeoutMs } : {}),
    };
  }

  private async runSpake(pipe: Pipe, password: string, mode: Mode.Pair | Mode.Recover, codeId?: string): Promise<HandshakeOutcome> {
    const { transport, credential } = await spakeClient(
      pipe, utf8(password), mode, this.opts.handshakeTimeoutMs, codeId ? fromB64url(codeId) : undefined,
    );
    const session = new SecureSession(pipe, transport, this.sessionOpts());
    return { session, credential };
  }

  private async runReconnect(pipe: Pipe, cred: DeviceCredential): Promise<HandshakeOutcome> {
    const transport = await reconnectInitiator(pipe, {
      hostStaticPub: fromB64url(cred.hostStaticPub),
      token: fromB64url(cred.token),
      keyId: fromB64url(cred.keyId),
      ...(this.opts.handshakeTimeoutMs !== undefined ? { handshakeTimeoutMs: this.opts.handshakeTimeoutMs } : {}),
    });
    const session = new SecureSession(pipe, transport, this.sessionOpts());
    return { session };
  }

  private async attempt(reach: Reach, runHandshake: (pipe: Pipe) => Promise<HandshakeOutcome>): Promise<{ outcome: HandshakeOutcome; via: string }> {
    const { result, via } = await establish(this.opts.uplinks, reach, runHandshake, this.opts.dial ?? {});
    return { outcome: result, via };
  }

  private adopt(r: { outcome: HandshakeOutcome; via: string }): void {
    this.session = r.outcome.session;
    this.epoch++;
    this._via = r.via;
    if (r.outcome.credential) {
      this._credential = r.outcome.credential;
      this._address = r.outcome.credential.address;
    }
    for (const fn of this.listeners) this.session.onMessage(fn);
    this.setState('connected');
    for (const w of this.connectedWaiters.splice(0)) {
      clearTimeout(w.timer);
      w.resolve();
    }
    const stillWaiting = this.epochWaiters.filter((w) => {
      if (this.epoch >= w.minEpoch) {
        clearTimeout(w.timer);
        w.resolve();
        return false;
      }
      return true;
    });
    this.epochWaiters.length = 0;
    this.epochWaiters.push(...stillWaiting);
  }

  // Resolve once a connection newer than `prevEpoch` is live (i.e. a reconnect
  // has completed), or reject on close/fail/timeout. Lets request() ride out a
  // mid-flight drop and retry on the fresh session instead of failing.
  private waitForEpochAfter(prevEpoch: number, timeoutMs: number): Promise<void> {
    if (this._state === 'connected' && this.epoch > prevEpoch) return Promise.resolve();
    if (this._state === 'closed' || this._state === 'failed') return Promise.reject(new Error(`connection ${this._state}`));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const i = this.epochWaiters.findIndex((w) => w.timer === timer);
        if (i >= 0) this.epochWaiters.splice(i, 1);
        reject(new Error('reconnect timed out'));
      }, Math.max(0, timeoutMs));
      this.epochWaiters.push({ minEpoch: prevEpoch + 1, resolve, reject, timer });
    });
  }

  // Background supervisor: when the live session drops, re-establish in reconnect
  // mode (failing over across uplinks) until it comes back or the caller closes.
  // The first successful pair/recovery yields a credential, so every reconnect
  // from here on authenticates by token + pinned key.
  private async monitor(): Promise<void> {
    for (;;) {
      const s = this.session;
      if (!s) return;
      await s.done;
      if (this.userClosed) return;
      if (!this.autoReconnect || !this._credential) {
        this.setState('failed');
        this.failWaiters(new Error('connection lost and auto-reconnect is unavailable'));
        return;
      }
      this.setState('reconnecting');
      const cred = this._credential;
      let delay = this.opts.reconnectBackoffMs ?? 400;
      const maxDelay = this.opts.reconnectMaxBackoffMs ?? 8_000;
      while (!this.userClosed) {
        try {
          const r = await this.attempt({ address: this._address }, (p) => this.runReconnect(p, cred));
          this.adopt(r);
          break;
        } catch (e) {
          // Revocation is terminal: the credential is refused at every uplink, so
          // stop retrying, go to 'revoked', and let waiters fail instead of looping
          // forever on a device the host has cut off.
          if (e instanceof DeviceRevokedError) {
            this.setState('revoked');
            this.failWaiters(new Error('device revoked: the host refused this credential'));
            return;
          }
          await sleep(delay);
          delay = Math.min(delay * 2, maxDelay);
        }
      }
      if (this.userClosed) return;
    }
  }

  private whenConnected(timeoutMs: number): Promise<void> {
    if (this._state === 'connected') return Promise.resolve();
    if (this._state === 'closed' || this._state === 'failed') return Promise.reject(new Error(`connection ${this._state}`));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const i = this.connectedWaiters.findIndex((w) => w.timer === timer);
        if (i >= 0) this.connectedWaiters.splice(i, 1);
        reject(new Error('not connected (timed out waiting for reconnect)'));
      }, timeoutMs);
      this.connectedWaiters.push({ resolve, reject, timer });
    });
  }

  // Send a request, transparently riding out a reconnect: if the live session
  // drops mid-flight (e.g. the current uplink was killed), wait for failover to
  // complete and retry on the fresh session, all within the time budget.
  // Application-level errors and timeouts are NOT retried — they surface as-is.
  //
  // DELIVERY SEMANTICS — this is AT-LEAST-ONCE. If the host executes a request but
  // the session drops before its response reaches us, the retry re-sends and the
  // host may execute it AGAIN. Keep `cmd`s idempotent, or carry an app-level
  // idempotency key the host dedupes on. (We deliberately do not add wire-level
  // dedup here; the app owns that policy.)
  async request(cmd: unknown, timeoutMs?: number): Promise<unknown> {
    const budget = timeoutMs ?? this.opts.requestTimeoutMs ?? 30_000;
    const deadline = Date.now() + budget;
    for (;;) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new Error('request timed out');
      await this.whenConnected(remaining);
      const session = this.session;
      if (!session) throw new Error('not connected');
      const epochAtSend = this.epoch;
      try {
        return await session.request(cmd, remaining);
      } catch (e) {
        if (this.userClosed) throw e;
        if (!(e instanceof SessionClosedError)) throw e; // app error / timeout
        await this.waitForEpochAfter(epochAtSend, deadline - Date.now());
      }
    }
  }

  send(evt: unknown): void {
    this.session?.send(evt);
  }

  get supportsPayload(): boolean {
    return this.session?.supportsPayload ?? false;
  }

  sendWithPayload(evt: unknown, payload: Uint8Array): void {
    const session = this.session;
    // A dropped session is the ordinary case here, not an error: the managed
    // connection reconnects and the caller's next frame rides the new one. But a
    // payload send has no queue behind it, so say so rather than discard bytes
    // the caller believes were sent.
    if (!session) throw new Error('no live session; the connection is reconnecting');
    session.sendWithPayload(evt, payload);
  }

  onMessage(fn: (data: unknown, payload?: Uint8Array) => void): () => void {
    this.listeners.add(fn);
    const off = this.session?.onMessage(fn);
    return () => {
      this.listeners.delete(fn);
      off?.();
    };
  }

  close(): void {
    this.userClosed = true;
    this.setState('closed');
    this.session?.close('closed by application');
    this.failWaiters(new Error('connection closed'));
  }

  private failWaiters(err: Error): void {
    for (const w of this.connectedWaiters.splice(0)) {
      clearTimeout(w.timer);
      w.reject(err);
    }
    for (const w of this.epochWaiters.splice(0)) {
      clearTimeout(w.timer);
      w.reject(err);
    }
  }

  private setState(s: ConnState): void {
    if (this._state === s) return;
    this._state = s;
    this.opts.onState?.(s);
  }
}

// ── host ──

export interface ServeHostOptions {
  uplinks: string[];
  // The host's static identity (x25519). Defaults to a fresh keypair — persist
  // the private key; clients pin the public key on first pair.
  hostStatic?: KeyPair;
  // Enable recovery cold-start with this high-entropy secret.
  recoveryKey?: string;
  // The current single-use pairing code, if pairing is open right now. It keys
  // SPAKE2 end-to-end ONLY: it is NEVER registered with the Link in any form (raw
  // or hashed). Clients rendezvous on the address (the QR carries it) and
  // authenticate with the code, so even a malicious Link learns nothing that lets
  // it pair. (A 6-char code is brute-forceable, so it can never be a Link
  // rendezvous key — only a SPAKE2 secret.)
  pairingCode?: string;
  // Pre-existing issued devices (persisted token store). Defaults to empty.
  tokens?: TokenStore;
  onRequest?: RequestHandler;
  // `codeId` is set only on a Pair that named one, and tells the host WHICH of
  // its live pairing codes admitted this device. Without it a host holding
  // several codes cannot attribute a new device to the code it came in on —
  // which is exactly what anything parked on a code (a name to christen it, the
  // machine it was provisioned for) needs in order to reach the right worker.
  onConnect?: (session: SecureSession, info: { keyId?: string; via: string; mode: Mode; codeId?: string }) => void;
  onLog?: (event: string, detail: Record<string, unknown>) => void;
  // Relay usage telemetry for this host's connections, as RELATIVE fractions (or
  // `unlimited` when the operator set no quota) — never absolute bytes. Fires both
  // on Link's unprompted pushes and in answer to requestUsage() pulls, with the
  // same per-connection shape.
  onUsage?: (connections: LinkUsage[]) => void;
  maxPairAttempts?: number; // default 5
  handshakeTimeoutMs?: number;
  // Reap an accepted session after this many ms with no inbound frame (defense-
  // in-depth against half-dead/idle sessions lingering host-side). Default 10 min
  // — see SessionOptions.idleTimeoutMs.
  idleTimeoutMs?: number;
  // Cap concurrent relay dial-backs per uplink (an untrusted Link could otherwise
  // drive unbounded outbound sockets). Default 64 — see HostUplinksOptions.
  maxConcurrentDialBacks?: number;
  // What dials. Defaults to `ws`, which is what a Node host wants; a realm `ws`
  // does not serve supplies its own and `ws` is never loaded.
  openSocket?: OpenSocket;
}

export interface Host {
  readonly address: string;
  readonly hostStatic: KeyPair;
  readonly hostStaticPub: string; // base64url
  readonly tokens: TokenStore;
  readonly sessions: ReadonlySet<SecureSession>;
  readonly registeredCount: number;
  // Open / close / rotate the LEGACY single pairing code (single-use; cleared on
  // a successful pair or after too many wrong guesses). It serves clients that
  // send no code id, which is every client built before code ids existed.
  setPairingCode(code: string | null): void;
  // Open one of MANY live pairing codes, and get back the public id that tells
  // this one apart. Hand the id to whoever gets the code — it travels with the
  // code, is not derived from it, and is safe in the clear.
  //
  // Several may be open at once, each single-use and each burned independently:
  // that is the whole point. A host holding one code could not admit two workers
  // being set up at the same time, and opening a second used to silently kill the
  // first, stranding whoever held it.
  openPairingCode(code: string, opts?: { ttlMs?: number }): { codeId: string };
  // Close one by its id (it is already gone after a successful pair). Returns
  // whether it was still open.
  closePairingCode(codeId: string): boolean;
  // The ids of every code open right now, so a caller can report or expire them.
  livePairingCodes(): { codeId: string; expiresInMs: number | null }[];
  // Cut a device off: drop its token so its next reconnect fails auth and is
  // refused with a typed DeviceRevokedError (and any live session it holds ends when
  // its pipe next turns over). Returns whether the device existed. This is the
  // single revocation point — the host consults the token store on every reconnect.
  revoke(keyId: string | Uint8Array): boolean;
  // Pull the current usage of every connection this host owns, on every uplink. The
  // answer(s) arrive via onUsage (same shape as an unprompted push).
  requestUsage(): void;
  stop(): Promise<void>;
}

// Stand up a host: register with every uplink and accept introduced clients.
export async function serveHost(opts: ServeHostOptions): Promise<Host> {
  const hostStatic = opts.hostStatic ?? x25519Keygen();
  // Sign every registration with a key derived from the host static identity, so the
  // Link pins it (TOFU) and refuses any squatter that does not hold the same key.
  const registerSigner = registerSignerFromStatic(hostStatic.priv);
  // The address IS the commitment to that register key (base64url(sha256(pub))).
  // Link enforces address-key binding always, so this is the only address a host can
  // register — it cannot be squatted or raced at all. There is no opaque-address model.
  const address = addressForRegisterKey(registerSigner.pub);
  const tokens = opts.tokens ?? new TokenStore();
  const lockout = new CodeLockout(opts.maxPairAttempts ?? 5);
  const sessions = new Set<SecureSession>();
  let pairingCode: string | null = opts.pairingCode ?? null;
  // The codes opened by id, alongside the legacy single slot above. A host can
  // hold as many as it likes; each is single-use and burns on its own success or
  // its own K wrong guesses, so one worker's fumbled setup never costs another
  // its code. Keyed by the base64url id the client echoes back in its header.
  const codesById = new Map<string, { code: string; expiresAt: number | null }>();
  const codeExpired = (e: { expiresAt: number | null }) => e.expiresAt !== null && e.expiresAt <= Date.now();
  // Sweep on touch rather than on a timer: a host with no pairing traffic should
  // hold no timers, and an expired code must never authenticate even if a sweep
  // has not run.
  function liveCode(codeId: string): string | null {
    const entry = codesById.get(codeId);
    if (!entry) return null;
    if (codeExpired(entry)) { codesById.delete(codeId); return null; }
    return entry.code;
  }
  const handshakeTimeout = opts.handshakeTimeoutMs ?? 15_000;
  // Lockout key for the recovery path. Recovery is gated by `reserve()` purely
  // for concurrency / CPU-DoS bounding; a wrong recovery guess is refunded
  // (never permanently counted), because a high-entropy recovery key needs no
  // lockout and a permanent one would only let an attacker DoS recovery.
  const RECOVERY_LOCK_KEY = ' recovery';

  async function onIntroduced(pipe: Pipe, via: string): Promise<void> {
    try {
      const header = decodeHeader(await pipe.recv(handshakeTimeout));
      if (header.mode === Mode.Reconnect) {
        const { transport, keyId } = await reconnectResponder(pipe, header, {
          hostStatic,
          resolveToken: (id) => tokens.resolve(id),
          handshakeTimeoutMs: handshakeTimeout,
        });
        registerSession(new SecureSession(pipe, transport, sessionOpts()), { keyId: toB64url(keyId), via, mode: header.mode });
        return;
      }
      if (header.mode === Mode.Pair || header.mode === Mode.Recover) {
        await handleSpake(pipe, header, via);
        return;
      }
      pipe.close('unknown mode');
    } catch (e) {
      opts.onLog?.('introduce-failed', { via, error: e instanceof Error ? e.message : String(e) });
      pipe.close('handshake failed');
    }
  }

  async function handleSpake(pipe: Pipe, header: Header, via: string): Promise<void> {
    const isPair = header.mode === Mode.Pair;
    // A client that named a code gets THAT code and no other. Falling back to
    // some other live code would be worse than refusing: it would run SPAKE2
    // with a password the client never had, and report the resulting failure as
    // a wrong code — a lie about which of the two ends is broken.
    const namedId = isPair && header.codeId ? toB64url(header.codeId) : null;
    const secret = isPair ? (namedId !== null ? liveCode(namedId) : pairingCode) : opts.recoveryKey ?? null;
    if (secret === null) {
      opts.onLog?.('pairing-closed', { mode: header.mode, ...(namedId !== null ? { codeId: namedId } : {}) });
      pipe.close(isPair ? 'pairing not open' : 'recovery not enabled');
      return;
    }
    // Reserve a guess slot ATOMICALLY, at entry, BEFORE the multi-round-trip
    // handshake. This is the fix for the lockout TOCTOU: there is no await between
    // this check and its increment, so N concurrent attempts can no longer all
    // slip past a stale `available()`. In-flight reservations count toward K, which
    // also caps concurrent unauthenticated handshakes per code.
    const lockKey = isPair ? `pair:${secret}` : RECOVERY_LOCK_KEY;
    if (!lockout.reserve(lockKey)) {
      opts.onLog?.(isPair ? 'pairing-locked-out' : 'recovery-busy', {});
      pipe.close(isPair ? 'pairing locked out' : 'recovery busy');
      return;
    }
    let settled = false;
    try {
      const { transport, device } = await spakeHost(pipe, header as never, {
        hostStatic,
        address,
        password: utf8(secret),
        tokens,
        timeoutMs: handshakeTimeout,
      });
      // Success.
      if (isPair) {
        lockout.clear(lockKey);
        // Single-use: burn THIS code, and only this one. Every other live code
        // belongs to a different worker's setup and is untouched.
        if (namedId !== null) codesById.delete(namedId);
        else pairingCode = null;
      } else {
        lockout.refund(lockKey); // recovery success: release the slot (not single-use)
      }
      settled = true;
      opts.onLog?.('paired', { keyId: toB64url(device.keyId), mode: header.mode, ...(namedId !== null ? { codeId: namedId } : {}) });
      registerSession(new SecureSession(pipe, transport, sessionOpts()), {
        keyId: toB64url(device.keyId), via, mode: header.mode,
        ...(namedId !== null ? { codeId: namedId } : {}),
      });
    } catch (e) {
      if (e instanceof PairingAuthError) {
        // A real (wrong) guess. For pairing it permanently counts toward K; for
        // recovery it is refunded (the high-entropy key needs no lockout).
        settled = true;
        if (isPair) {
          const { lockedOut } = lockout.recordFailure(lockKey);
          if (lockedOut) {
            // Burn after K wrong guesses — again only the one that was guessed
            // at, so an attacker cannot lock every code out by attacking one.
            if (namedId !== null) codesById.delete(namedId);
            else pairingCode = null;
            opts.onLog?.('pairing-burned', { ...(namedId !== null ? { codeId: namedId } : {}) });
          }
        } else {
          lockout.refund(lockKey);
        }
        opts.onLog?.('pairing-auth-failed', { mode: header.mode });
      } else {
        opts.onLog?.('pairing-error', { error: e instanceof Error ? e.message : String(e) });
      }
      pipe.close('pairing failed');
    } finally {
      // Network error / timeout / disconnect before any verdict: not a guess —
      // release the slot so it never counts toward the budget.
      if (!settled) lockout.refund(lockKey);
    }
  }

  function sessionOpts(): SessionOptions {
    return {
      ...(opts.onRequest ? { onRequest: opts.onRequest } : {}),
      ...(opts.idleTimeoutMs !== undefined ? { idleTimeoutMs: opts.idleTimeoutMs } : {}),
    };
  }

  function registerSession(session: SecureSession, info: { keyId?: string; via: string; mode: Mode; codeId?: string }): void {
    sessions.add(session);
    void session.done.then(() => sessions.delete(session));
    opts.onConnect?.(session, info);
  }

  const uplinkMgr = new HostUplinks(opts.uplinks, {
    address,
    registerSigner,
    ...(opts.maxConcurrentDialBacks !== undefined ? { maxConcurrentDialBacks: opts.maxConcurrentDialBacks } : {}),
    ...(opts.openSocket ? { openSocket: opts.openSocket } : {}),
    // Return the handshake promise (don't `void` it) so HostUplinks holds the
    // dial-back slot for the whole introduced handshake — a hard concurrency cap.
    onIntroduced: (pipe, via) => onIntroduced(pipe, via),
    ...(opts.onUsage ? { onUsage: opts.onUsage } : {}),
    ...(opts.onLog ? { onLog: opts.onLog } : {}),
  });
  await uplinkMgr.start();

  return {
    address,
    hostStatic,
    hostStaticPub: toB64url(hostStatic.pub),
    tokens,
    sessions,
    get registeredCount() {
      return uplinkMgr.registeredCount;
    },
    openPairingCode(code: string, o?: { ttlMs?: number }): { codeId: string } {
      // The id is fresh randomness, never a function of the code: derive it from
      // the code and a relay watching the wire would get a free oracle for
      // guessing it offline, which is exactly what SPAKE2 exists to deny.
      const codeId = toB64url(randomBytes(CODE_ID_LEN));
      const ttl = o?.ttlMs;
      codesById.set(codeId, { code, expiresAt: ttl !== undefined ? Date.now() + ttl : null });
      lockout.clear(`pair:${code}`);
      return { codeId };
    },
    closePairingCode(codeId: string): boolean {
      return codesById.delete(codeId);
    },
    livePairingCodes(): { codeId: string; expiresInMs: number | null }[] {
      const out: { codeId: string; expiresInMs: number | null }[] = [];
      for (const [codeId, entry] of codesById) {
        if (codeExpired(entry)) { codesById.delete(codeId); continue; }
        out.push({ codeId, expiresInMs: entry.expiresAt === null ? null : entry.expiresAt - Date.now() });
      }
      return out;
    },
    setPairingCode(code: string | null): void {
      // Set (or clear) the SPAKE2 secret the host handshake uses. The code is NEVER
      // registered with the Link in any form — clients rendezvous on the address
      // and authenticate with the code end-to-end (deriveW), so a malicious Link
      // learns nothing that lets it pair.
      pairingCode = code;
      if (code) lockout.clear(`pair:${code}`);
    },
    revoke(keyId: string | Uint8Array): boolean {
      return tokens.revoke(keyId);
    },
    requestUsage(): void {
      uplinkMgr.requestUsage();
    },
    async stop(): Promise<void> {
      uplinkMgr.stop();
      for (const s of sessions) s.close('host stopping');
      sessions.clear();
    },
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
