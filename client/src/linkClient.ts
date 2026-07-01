// The multi-uplink transport. It speaks the Link wire verbatim (register /
// registered / resolve / found / relay / relaying / accept / arrived — see
// link/server) and adds the model's generalization:
//   • Host: hold an outbound control socket to every uplink and (re-)register its
//     address on each; re-register automatically when an uplink drops or restarts.
//     A Link going away is a non-event.
//   • Client: try uplinks in order; on each, resolve the address then relay; fail
//     over to the next uplink on any error or timeout.
// Every connection goes through a Link relay — there is no direct/candidate path,
// so a host never listens on a port. Link only ever sees ciphertext spliced
// between two sockets; this file never looks inside a relayed frame.

import { WebSocket, type RawData } from 'ws';
import { type Pipe, type CloseInfo, PipeClosedError, PipeTimeoutError } from './pipe.js';
import { makeRegisterAuth, type RegisterSigner } from './registerAuth.js';

// Match the Link server's hard frame cap (16 MiB). ws defaults to 100 MiB, which
// would let a peer pin far more memory than the relay ever would; cap every socket
// we create at the same ceiling as the server.
const MAX_FRAME_BYTES = 16 * 1024 * 1024;

function toBuffer(data: RawData): Buffer {
  if (Array.isArray(data)) return Buffer.concat(data);
  if (data instanceof ArrayBuffer) return Buffer.from(data);
  return data as Buffer;
}

interface ControlMsg {
  type: string;
  [k: string]: unknown;
}

interface Waiter<T> {
  resolve: (v: T) => void;
  reject: (e: Error) => void;
  timer?: NodeJS.Timeout;
}

// One Link WebSocket, presented two ways: a JSON control channel during
// introduction, and a raw frame Pipe once the splice is live. A socket plays
// exactly one role and transitions control -> piping exactly once (on the
// 'relaying' message), matching the server's own state machine.
export class LinkSocket implements Pipe {
  private piping: boolean;
  private readonly controlQueue: ControlMsg[] = [];
  private readonly controlWaiters: Waiter<ControlMsg>[] = [];
  private controlHandler: ((m: ControlMsg) => void) | undefined;
  private readonly frameQueue: Uint8Array[] = [];
  private readonly frameWaiters: Waiter<Uint8Array>[] = [];
  private closeInfo: CloseInfo | undefined;
  private resolveClosed!: (info: CloseInfo) => void;
  readonly closed: Promise<CloseInfo> = new Promise((r) => (this.resolveClosed = r));

  constructor(private readonly ws: WebSocket, opts: { piping?: boolean } = {}) {
    this.piping = opts.piping ?? false;
    ws.binaryType = 'nodebuffer';
    ws.on('message', (data: RawData, isBinary: boolean) => this.onMessage(toBuffer(data), isBinary));
    ws.on('close', (code: number, reason: Buffer) => {
      const r = reason.toString();
      this.onClose(r ? { code, reason: r } : { code });
    });
    ws.on('error', () => this.onClose({ reason: 'socket error' }));
  }

  get isOpen(): boolean {
    return this.closeInfo === undefined && this.ws.readyState === WebSocket.OPEN;
  }

  private onMessage(buf: Buffer, isBinary: boolean): void {
    if (this.piping) {
      this.deliverFrame(new Uint8Array(buf));
      return;
    }
    if (!isBinary) {
      try {
        const parsed: unknown = JSON.parse(buf.toString('utf8'));
        if (parsed && typeof parsed === 'object' && typeof (parsed as ControlMsg).type === 'string') {
          const msg = parsed as ControlMsg;
          // Flip to piping the instant the splice goes live, so the frames that
          // follow 'relaying' are treated as opaque payload, never reparsed.
          if (msg.type === 'relaying') this.piping = true;
          this.deliverControl(msg);
          return;
        }
      } catch {
        /* fall through */
      }
    }
    // Binary (or non-JSON) before the splice is live is a protocol violation.
    this.onClose({ reason: 'unexpected pre-relay frame' });
    this.ws.terminate();
  }

  private deliverControl(msg: ControlMsg): void {
    if (this.controlHandler) {
      this.controlHandler(msg);
      return;
    }
    const w = this.controlWaiters.shift();
    if (w) {
      if (w.timer) clearTimeout(w.timer);
      w.resolve(msg);
    } else {
      this.controlQueue.push(msg);
    }
  }

  private deliverFrame(frame: Uint8Array): void {
    const w = this.frameWaiters.shift();
    if (w) {
      if (w.timer) clearTimeout(w.timer);
      w.resolve(frame);
    } else {
      this.frameQueue.push(frame);
    }
  }

  private onClose(info: CloseInfo): void {
    if (this.closeInfo) return;
    this.closeInfo = info;
    const err = new PipeClosedError(info);
    for (const w of this.controlWaiters.splice(0)) {
      if (w.timer) clearTimeout(w.timer);
      w.reject(err);
    }
    for (const w of this.frameWaiters.splice(0)) {
      if (w.timer) clearTimeout(w.timer);
      w.reject(err);
    }
    this.resolveClosed(info);
  }

  // — control plane —

  sendControl(msg: ControlMsg): void {
    if (this.ws.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(msg));
  }

  // Route unsolicited control messages to a handler (used by the host control
  // socket, which receives 'arrived'/'relay'/'usage' asynchronously).
  setControlHandler(fn: (m: ControlMsg) => void): void {
    this.controlHandler = fn;
    for (const m of this.controlQueue.splice(0)) fn(m);
  }

  waitControl(timeoutMs: number): Promise<ControlMsg> {
    const queued = this.controlQueue.shift();
    if (queued) return Promise.resolve(queued);
    if (this.closeInfo) return Promise.reject(new PipeClosedError(this.closeInfo));
    return new Promise((resolve, reject) => {
      const waiter: Waiter<ControlMsg> = { resolve, reject };
      waiter.timer = setTimeout(() => {
        const i = this.controlWaiters.indexOf(waiter);
        if (i >= 0) this.controlWaiters.splice(i, 1);
        reject(new PipeTimeoutError(timeoutMs));
      }, timeoutMs);
      this.controlWaiters.push(waiter);
    });
  }

  // — Pipe (after the splice is live) —

  send(frame: Uint8Array): void {
    if (this.ws.readyState === WebSocket.OPEN) this.ws.send(frame, { binary: true });
  }

  recv(timeoutMs?: number): Promise<Uint8Array> {
    const queued = this.frameQueue.shift();
    if (queued) return Promise.resolve(queued);
    if (this.closeInfo) return Promise.reject(new PipeClosedError(this.closeInfo));
    return new Promise((resolve, reject) => {
      const waiter: Waiter<Uint8Array> = { resolve, reject };
      if (timeoutMs !== undefined) {
        waiter.timer = setTimeout(() => {
          const i = this.frameWaiters.indexOf(waiter);
          if (i >= 0) this.frameWaiters.splice(i, 1);
          reject(new PipeTimeoutError(timeoutMs));
        }, timeoutMs);
      }
      this.frameWaiters.push(waiter);
    });
  }

  close(reason?: string): void {
    if (this.closeInfo === undefined) this.closeInfo = reason !== undefined ? { reason } : {};
    try {
      if (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING) {
        this.ws.close(1000, reason);
      }
    } catch {
      /* ignore */
    }
    this.resolveClosed(this.closeInfo);
  }
}

function openWs(url: string, timeoutMs: number): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    let ws: WebSocket;
    try {
      ws = new WebSocket(url, { maxPayload: MAX_FRAME_BYTES });
    } catch (e) {
      reject(e instanceof Error ? e : new Error('bad url'));
      return;
    }
    ws.binaryType = 'nodebuffer';
    const timer = setTimeout(() => {
      ws.terminate();
      reject(new PipeTimeoutError(timeoutMs));
    }, timeoutMs);
    ws.once('open', () => {
      clearTimeout(timer);
      resolve(ws);
    });
    ws.once('error', (e: Error) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}

export interface DialOptions {
  connectTimeoutMs?: number;
  controlTimeoutMs?: number;
}

// Rendezvous is ALWAYS by address (high-entropy, anti-squat-signed). A short
// pairing code is NEVER a Link lookup key — it is brute-forceable, so it stays a
// SPAKE2 secret used end-to-end, never sent to the Link in any form.
export type Reach = { address: string };

export class AllUplinksFailedError extends Error {
  constructor(readonly attempts: { url: string; error: string }[]) {
    super(`all ${attempts.length} uplink(s) failed: ${attempts.map((a) => `${a.url} (${a.error})`).join('; ')}`);
    this.name = 'AllUplinksFailedError';
  }
}

// Establish a secure session over the best available uplink. For each uplink in
// order: resolve the address, then relay; the injected `runHandshake` is what
// decides success (a failed handshake just moves on). Returns the winning pipe +
// handshake result; every other socket is closed.
export async function establish<T>(
  uplinks: string[],
  reach: Reach,
  runHandshake: (pipe: Pipe) => Promise<T>,
  opts: DialOptions = {},
): Promise<{ result: T; pipe: Pipe; via: string }> {
  const connectTimeout = opts.connectTimeoutMs ?? 8_000;
  const controlTimeout = opts.controlTimeoutMs ?? 8_000;
  const attempts: { url: string; error: string }[] = [];

  for (const url of uplinks) {
    let sock: LinkSocket;
    try {
      sock = new LinkSocket(await openWs(url, connectTimeout));
    } catch (e) {
      attempts.push({ url, error: `connect: ${errMsg(e)}` });
      continue;
    }
    let found: ControlMsg;
    try {
      sock.sendControl({ type: 'resolve', ...reach });
      const msg = await sock.waitControl(controlTimeout);
      if (msg.type !== 'found') throw new Error(typeof msg.error === 'string' ? msg.error : `unexpected ${msg.type}`);
      found = msg;
    } catch (e) {
      attempts.push({ url, error: `resolve: ${errMsg(e)}` });
      sock.close('resolve failed');
      continue;
    }

    // Relay on this uplink.
    try {
      const linkId = found.linkId as string;
      sock.sendControl({ type: 'relay', linkId });
      const relaying = await sock.waitControl(controlTimeout);
      if (relaying.type !== 'relaying') {
        throw new Error(typeof relaying.error === 'string' ? relaying.error : `unexpected ${relaying.type}`);
      }
      const result = await runHandshake(sock); // sock is now a live Pipe
      return { result, pipe: sock, via: `relay:${url}` };
    } catch (e) {
      attempts.push({ url, error: `relay: ${errMsg(e)}` });
      sock.close('relay failed');
      continue;
    }
  }
  throw new AllUplinksFailedError(attempts);
}

// — host side: register with N uplinks, dial back relays —

export interface HostUplinksOptions {
  // The host's routing address. Re-registered on every uplink (re)connect.
  address: string;
  // Signs every `register` frame so the Link pins this host's key (TOFU) and
  // refuses any squatter that re-registers the same address without it. REQUIRED:
  // Link refuses an unsigned register, so there is no insecure path to take.
  registerSigner: RegisterSigner;
  // Handle an introduced pipe (run the host handshake over it). MUST resolve in
  // bounded time (its own handshake timeout) — HostUplinks awaits it to hold the
  // dial-back slot for the whole handshake (see maxConcurrentDialBacks / dialBack).
  onIntroduced: (pipe: Pipe, via: string) => void | Promise<void>;
  connectTimeoutMs?: number;
  controlTimeoutMs?: number;
  // Reconnect backoff for a dropped uplink.
  reconnectBaseMs?: number;
  reconnectMaxMs?: number;
  // Hard cap on concurrent relay dial-backs IN FLIGHT, PER UPLINK. Every
  // {type:'relay'} control message from a Link makes the host open a fresh outbound
  // socket, wait for the 'relaying' splice, AND run the introduced handshake; the
  // slot is held for that WHOLE span (see dialBack), so the cap is a hard ceiling on
  // concurrent unauthenticated work — not just on the brief accept phase. An
  // untrusted Link could otherwise drive unbounded dial-backs → FD/memory
  // exhaustion; past the cap, further relay requests are dropped (and logged), not
  // queued. The PER-UPLINK scope means one malicious Link can exhaust only its own
  // budget, never starve an honest uplink's. Default 64 (far above honest load).
  maxConcurrentDialBacks?: number;
  onLog?: (event: string, detail: Record<string, unknown>) => void;
}

// Holds the host's outbound control sockets and keeps them registered. This is
// the piece that makes "a Link going away is a non-event" true: each uplink
// reconnects and re-registers independently.
export class HostUplinks {
  private readonly sockets = new Map<string, LinkSocket>();
  private readonly timers = new Map<string, NodeJS.Timeout>();
  private readonly backoff = new Map<string, number>();
  private stopped = false;
  private readonly maxDialBacks: number;
  // Concurrent in-flight dial-backs PER UPLINK (url → count). A slot is held for the
  // whole dial-back + introduced handshake, and the cap is per-uplink, so a single
  // malicious/compromised Link can exhaust only ITS OWN budget — it can never starve
  // an honest uplink's dial-backs, nor push total concurrent work past maxDialBacks.
  private readonly inFlightDialBacks = new Map<string, number>();

  constructor(private readonly uplinks: string[], private readonly opts: HostUplinksOptions) {
    this.maxDialBacks = Math.max(1, opts.maxConcurrentDialBacks ?? 64);
  }

  async start(): Promise<void> {
    await Promise.all(this.uplinks.map((u) => this.connectAndRegister(u).catch(() => this.scheduleReconnect(u))));
  }

  // Build a signed `register` frame. A fresh signature (new ts + nonce) is minted
  // per call, so every (re)connect carries a unique, replay-resistant frame the
  // server can verify against the pinned key.
  private addressRegister(): ControlMsg {
    return {
      type: 'register',
      address: this.opts.address,
      auth: makeRegisterAuth(this.opts.registerSigner, this.opts.address),
    };
  }

  private async connectAndRegister(url: string): Promise<void> {
    if (this.stopped) return;
    const ws = await openWs(url, this.opts.connectTimeoutMs ?? 8_000);
    const sock = new LinkSocket(ws);
    sock.sendControl(this.addressRegister());
    const ack = await sock.waitControl(this.opts.controlTimeoutMs ?? 8_000);
    if (ack.type !== 'registered') {
      sock.close('register rejected');
      throw new Error(`register rejected: ${ack.type}`);
    }
    this.backoff.delete(url);
    this.sockets.set(url, sock);
    this.opts.onLog?.('uplink-registered', { url, address: this.opts.address });
    sock.setControlHandler((m) => this.onControl(url, m));
    void sock.closed.then(() => {
      this.sockets.delete(url);
      this.opts.onLog?.('uplink-dropped', { url });
      this.scheduleReconnect(url);
    });
  }

  private onControl(url: string, msg: ControlMsg): void {
    // The only control message that needs action: the relay dial-back request.
    // 'arrived' is informational; 'usage' is quota telemetry — both ignored.
    if (msg.type === 'relay' && typeof msg.linkId === 'string') {
      // Bound concurrent dial-backs PER UPLINK: a compromised/malicious Link
      // (UNTRUSTED) could otherwise fire relay control messages faster than they
      // complete and pin one outbound socket + introduced handshake each. The slot
      // is held for the WHOLE dial-back + handshake (see dialBack), so the cap is a
      // hard ceiling on concurrent unauthenticated work, not just on the brief
      // accept phase. Over the cap we drop the request (the client just fails this
      // attempt and retries) rather than queue unboundedly.
      const inFlight = this.inFlightDialBacks.get(url) ?? 0;
      if (inFlight >= this.maxDialBacks) {
        this.opts.onLog?.('dialback-throttled', { url, inFlight, max: this.maxDialBacks });
        return;
      }
      this.inFlightDialBacks.set(url, inFlight + 1);
      void this.dialBack(url, msg.linkId).finally(() => {
        const n = this.inFlightDialBacks.get(url) ?? 1;
        if (n <= 1) this.inFlightDialBacks.delete(url);
        else this.inFlightDialBacks.set(url, n - 1);
      });
    }
  }

  private async dialBack(url: string, linkId: string): Promise<void> {
    try {
      const ws = await openWs(url, this.opts.connectTimeoutMs ?? 8_000);
      const relay = new LinkSocket(ws);
      relay.sendControl({ type: 'accept', linkId });
      const relaying = await relay.waitControl(this.opts.controlTimeoutMs ?? 8_000);
      if (relaying.type !== 'relaying') {
        relay.close('accept failed');
        return;
      }
      // HOLD the dial-back slot until the introduced handshake RESOLVES: serveHost's
      // onIntroduced reads the header + runs Noise/SPAKE2 under its own bounded
      // handshakeTimeout, registers the session, then returns. Awaiting it keeps a
      // socket parked in the host's handshake-wait counted against the cap, so the
      // ceiling is a true maxDialBacks, not maxDialBacks × (handshakeTimeout / RTT).
      await this.opts.onIntroduced(relay, `relay:${url}`);
    } catch (e) {
      this.opts.onLog?.('dialback-failed', { url, linkId, error: errMsg(e) });
    }
  }

  private scheduleReconnect(url: string): void {
    if (this.stopped || this.timers.has(url)) return;
    const base = this.opts.reconnectBaseMs ?? 500;
    const max = this.opts.reconnectMaxMs ?? 10_000;
    const prev = this.backoff.get(url) ?? base;
    const delay = Math.min(prev, max);
    this.backoff.set(url, Math.min(prev * 2, max));
    const timer = setTimeout(() => {
      this.timers.delete(url);
      void this.connectAndRegister(url).catch(() => this.scheduleReconnect(url));
    }, delay);
    if (typeof timer.unref === 'function') timer.unref();
    this.timers.set(url, timer);
  }

  stop(): void {
    this.stopped = true;
    for (const t of this.timers.values()) clearTimeout(t);
    this.timers.clear();
    for (const s of this.sockets.values()) s.close('host stopping');
    this.sockets.clear();
  }

  get registeredCount(): number {
    return this.sockets.size;
  }
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
