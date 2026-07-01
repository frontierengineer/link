import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { WebSocketServer, WebSocket, type RawData } from 'ws';
import type { Config } from './config';
import { Registry, type CloseReason, type Link } from './registry';
import { Close, type ServerMessage } from './types';
import { verifyRegisterAuth } from './registerAuth';

const MAX_CONTROL_BYTES = 4096;
const MAX_FRAME_BYTES = 16 * 1024 * 1024;
const MAX_KEY_LEN = 128; // addresses + link ids
// A relay peer that stops draining backs its frames up in our send buffer; past
// this we cut the link rather than hold unbounded ciphertext in memory.
const SLOW_PEER_BUFFER = 64 * 1024 * 1024;
const PING_MS = 30_000;
const SWEEP_MS = 500;

type Role = 'new' | 'control' | 'client' | 'relay';

// Frames held back by the shaper for one direction of a relay, FIFO with a due
// time each. Normally empty: it only fills while the source socket is paused, and
// then only with frames TCP had already delivered before the pause landed — so it
// is bounded by the kernel buffers, not by the sender.
interface Shaped {
  frames: { data: Buffer; isBinary: boolean }[];
  dueAt: number[];
  timer?: NodeJS.Timeout;
}

interface Ctx {
  ip: string;
  role: Role;
  link?: Link<WebSocket>;
  alive: boolean;
  shaped?: Shaped;
}

// Fixed one-minute window per IP across register/resolve. Pure control-plane DoS
// protection: it bounds how fast one source can spam introductions. It is NOT
// what protects the pairing code — the code never reaches Link; an online code
// guess is rated and locked out by the HOST, end to end.
class IpRateLimiter {
  private readonly hits = new Map<string, { count: number; resetAt: number }>();
  constructor(private readonly perMin: number) {}

  allow(ip: string, now: number): boolean {
    if (this.perMin === 0) return true;
    const h = this.hits.get(ip);
    if (!h || now >= h.resetAt) {
      this.hits.set(ip, { count: 1, resetAt: now + 60_000 });
      return true;
    }
    return ++h.count <= this.perMin;
  }

  sweep(now: number): void {
    for (const [ip, h] of this.hits) {
      if (now >= h.resetAt) this.hits.delete(ip);
    }
  }
}

function isKey(v: unknown): v is string {
  return typeof v === 'string' && v.length > 0 && v.length <= MAX_KEY_LEN;
}

function toBuffer(data: RawData): Buffer {
  if (Array.isArray(data)) return Buffer.concat(data);
  if (data instanceof ArrayBuffer) return Buffer.from(data);
  return data;
}

function sendJson(ws: WebSocket, msg: ServerMessage): void {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg));
}

function sendHttp(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

export interface LinkServer {
  server: Server;
  registry: Registry<WebSocket>;
  stop(): Promise<void>;
}

export function createLinkServer(config: Config): LinkServer {
  const registry = new Registry<WebSocket>({
    relayIdleSec: config.relayIdleSec,
    relayMaxBps: config.relayMaxBps,
    relayHourlyBytes: config.relayHourlyBytes,
    relayTrickleBps: config.relayTrickleBps,
  });
  const limiter = new IpRateLimiter(config.ipRatePerMin);
  const ctxOf = new Map<WebSocket, Ctx>();
  const startedAt = Date.now();

  function close(ws: WebSocket, code: number, reason: string): void {
    // A socket the shaper paused cannot read the peer's close reply; resume it so
    // the closing handshake completes instead of timing out.
    if (ws.isPaused) ws.resume();
    if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
      ws.close(code, reason);
    }
  }

  // Tear a link down and tell both relay parties why, with the same close code on
  // both ends. The host control socket is never one of those parties.
  function closeLinkEnds(link: Link<WebSocket>, reason: CloseReason, code: number, detail: string): void {
    registry.closeLink(link, reason);
    close(link.client, code, detail);
    if (link.hostRelay) close(link.hostRelay, code, detail);
  }

  // — control plane —

  // A host registers (or re-registers) the address it can be reached at. Every
  // register is signed: the frame must carry a valid signature over (address, ts,
  // nonce) by the address's pinned key (anti-squat, TOFU). There is no other way
  // to register — and there is no `code` here at all.
  function handleRegister(ws: WebSocket, ctx: Ctx, msg: Record<string, unknown>): void {
    if (ctx.role !== 'new' && ctx.role !== 'control') {
      close(ws, Close.badRequest, 'register: wrong socket role');
      return;
    }
    if (!limiter.allow(ctx.ip, Date.now())) {
      close(ws, Close.rateLimited, 'rate limited');
      return;
    }
    if (!isKey(msg.address)) {
      close(ws, Close.badRequest, 'register: address required');
      return;
    }
    const verified = verifyRegisterAuth(msg.address, msg.auth, Date.now());
    if (!verified) {
      close(ws, Close.registerAuth, 'register: a valid signed auth is required');
      return;
    }
    ctx.role = 'control';
    const result = registry.registerAddress(ws, msg.address, verified);
    if (!result.ok) {
      // A registrant signed by the WRONG key (address_pinned) or replaying a stale
      // frame (register_stale): refuse WITHOUT disturbing the genuine holder.
      sendJson(ws, { type: 'error', error: result.reason });
      return;
    }
    if (result.replaced) close(result.replaced, Close.replaced, 'address re-registered by a newer socket');
    sendJson(ws, { type: 'registered', address: msg.address });
  }

  // A client asks to be introduced to the host at an address. Link creates a link
  // id, tells the client, and tells the host a client arrived. Knowing the address
  // is enough to ASK — entry is gated by the end-to-end handshake Link can't see.
  function handleResolve(ws: WebSocket, ctx: Ctx, msg: Record<string, unknown>): void {
    if (ctx.role !== 'new') {
      close(ws, Close.badRequest, 'resolve: wrong socket role');
      return;
    }
    if (!limiter.allow(ctx.ip, Date.now())) {
      close(ws, Close.rateLimited, 'rate limited');
      return;
    }
    if (!isKey(msg.address)) {
      close(ws, Close.badRequest, 'resolve: address required');
      return;
    }
    const found = registry.lookupAddress(ws, msg.address as string);
    if (!found) {
      sendJson(ws, { type: 'error', error: 'unknown_address' });
      return;
    }
    ctx.role = 'client';
    ctx.link = found.link;
    sendJson(ws, { type: 'found', linkId: found.link.id });
    // The other half of the introduction: the host learns a client showed up.
    sendJson(found.link.hostControl, { type: 'arrived', linkId: found.link.id, address: msg.address as string });
  }

  // Client side: "relay me". Link asks the host's control socket to dial back a
  // dedicated relay socket for this link.
  function handleRelay(ws: WebSocket, ctx: Ctx, msg: Record<string, unknown>): void {
    if (ctx.role !== 'client' || !ctx.link || msg.linkId !== ctx.link.id
      || !registry.requestRelay(ctx.link)) {
      close(ws, Close.badRequest, 'relay: only the client of an introduced link');
      return;
    }
    if (ctx.link.hostControl.readyState !== WebSocket.OPEN) {
      closeLinkEnds(ctx.link, 'peer_gone', Close.peerGone, 'host gone');
      return;
    }
    sendJson(ctx.link.hostControl, { type: 'relay', linkId: ctx.link.id });
  }

  // Host side: the dial-back. A fresh socket whose first message names the pending
  // link becomes the host's relay end, and the splice starts.
  function handleAccept(ws: WebSocket, ctx: Ctx, msg: Record<string, unknown>): void {
    if (ctx.role !== 'new') {
      close(ws, Close.badRequest, 'accept: needs a fresh socket');
      return;
    }
    if (!isKey(msg.linkId)) {
      close(ws, Close.badRequest, 'accept: linkId required');
      return;
    }
    const link = registry.acceptRelay(msg.linkId as string, ws);
    if (!link) {
      sendJson(ws, { type: 'error', error: 'unknown_link' });
      return;
    }
    ctx.role = 'relay';
    ctx.link = link;
    sendJson(link.client, { type: 'relaying', linkId: link.id });
    sendJson(ws, { type: 'relaying', linkId: link.id });
  }

  // The relay itself: frames are spliced verbatim between the two sockets. Nothing
  // here parses, inspects, or logs a frame — Link is content-blind by
  // construction, and the only things it keeps are the byte counters.
  //
  // The rate caps shape instead of closing: a frame the buckets cannot pay for yet
  // is held, the source socket is paused (so TCP backpressure stalls the real
  // sender), and the frame goes out when the bucket math says it is paid for. ws
  // keeps emitting frames it had already buffered when pause() landed; those just
  // join the queue, which is therefore bounded by the kernel buffers — never by
  // the sender's enthusiasm.

  function forward(link: Link<WebSocket>, from: 'host' | 'client', data: Buffer, isBinary: boolean): boolean {
    const peer = from === 'host' ? link.client : link.hostRelay!;
    if (peer.bufferedAmount > SLOW_PEER_BUFFER) {
      closeLinkEnds(link, 'slow_peer', Close.slowPeer, 'peer not draining');
      return false;
    }
    if (peer.readyState === WebSocket.OPEN) peer.send(data, { binary: isBinary });
    return true;
  }

  function scheduleDrain(ws: WebSocket, ctx: Ctx): void {
    const q = ctx.shaped!;
    q.timer = setTimeout(() => {
      q.timer = undefined;
      drainShaped(ws, ctx);
    }, Math.max(0, q.dueAt[0] - Date.now()));
  }

  function drainShaped(ws: WebSocket, ctx: Ctx): void {
    const q = ctx.shaped!;
    const link = ctx.link!;
    const from = ctx.role === 'relay' ? 'host' : 'client';
    while (q.frames.length > 0 && q.dueAt[0] <= Date.now()) {
      if (link.state !== 'relaying') {
        q.frames.length = 0;
        q.dueAt.length = 0;
        return;
      }
      const frame = q.frames.shift()!;
      q.dueAt.shift();
      if (!forward(link, from, frame.data, frame.isBinary)) {
        q.frames.length = 0;
        q.dueAt.length = 0;
        return;
      }
    }
    if (q.frames.length > 0) scheduleDrain(ws, ctx);
    else ws.resume();
  }

  function splice(ws: WebSocket, ctx: Ctx, data: Buffer, isBinary: boolean): void {
    const link = ctx.link!;
    const from = ctx.role === 'relay' ? 'host' : 'client';
    const { waitMs, usage } = registry.chargeFrame(link, from, data.length);
    if (usage) sendJson(link.hostControl, { type: 'usage', linkId: link.id, ...usage });
    const q = ctx.shaped ?? (ctx.shaped = { frames: [], dueAt: [] });
    if (waitMs === 0 && q.frames.length === 0) {
      forward(link, from, data, isBinary);
      return;
    }
    q.frames.push({ data, isBinary });
    // Due times stay monotonic so the queue drains strictly FIFO.
    q.dueAt.push(Math.max(Date.now() + waitMs, q.dueAt[q.dueAt.length - 1] ?? 0));
    ws.pause();
    if (!q.timer) scheduleDrain(ws, ctx);
  }

  function handleControlMessage(ws: WebSocket, ctx: Ctx, data: Buffer): void {
    if (data.length > MAX_CONTROL_BYTES) {
      close(ws, Close.badRequest, 'control message too large');
      return;
    }
    let msg: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse(data.toString('utf8'));
      if (typeof parsed !== 'object' || parsed === null) throw new Error('not an object');
      msg = parsed as Record<string, unknown>;
    } catch {
      close(ws, Close.badRequest, 'control messages are JSON objects');
      return;
    }
    switch (msg.type) {
      case 'register': handleRegister(ws, ctx, msg); return;
      case 'resolve': handleResolve(ws, ctx, msg); return;
      case 'relay': handleRelay(ws, ctx, msg); return;
      case 'accept': handleAccept(ws, ctx, msg); return;
      default: close(ws, Close.badRequest, 'unknown message type');
    }
  }

  // — wiring —

  const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_FRAME_BYTES });

  wss.on('connection', (ws: WebSocket, req: IncomingMessage) => {
    const forwarded = config.trustProxy ? req.headers['x-forwarded-for'] : undefined;
    const ip = (Array.isArray(forwarded) ? forwarded[0] : forwarded)?.split(',')[0]?.trim()
      || req.socket.remoteAddress
      || 'unknown';
    const ctx: Ctx = { ip, role: 'new', alive: true };
    ctxOf.set(ws, ctx);

    ws.on('pong', () => { ctx.alive = true; });
    ws.on('message', (data: RawData, isBinary: boolean) => {
      // On a relaying link every frame — text or binary — is opaque payload.
      if (ctx.link?.state === 'relaying' && (ctx.role === 'client' || ctx.role === 'relay')) {
        splice(ws, ctx, toBuffer(data), isBinary);
        return;
      }
      if (isBinary) {
        close(ws, Close.badRequest, 'binary frames are only valid on a relaying link');
        return;
      }
      handleControlMessage(ws, ctx, toBuffer(data));
    });
    ws.on('error', () => ws.terminate());
    ws.on('close', () => {
      ctxOf.delete(ws);
      if (ctx.shaped?.timer) clearTimeout(ctx.shaped.timer);
      for (const link of registry.dropSocket(ws)) {
        if (link.client !== ws) close(link.client, Close.peerGone, 'peer gone');
        if (link.hostRelay && link.hostRelay !== ws) close(link.hostRelay, Close.peerGone, 'peer gone');
      }
    });
  });

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = req.url ?? '/';
    if (req.method === 'GET' && (url === '/health' || url === '/healthz')) {
      sendHttp(res, 200, { status: 'ok' });
      return;
    }
    if (req.method === 'GET' && url === '/v1/stats') {
      sendHttp(res, 200, { uptimeSec: Math.round((Date.now() - startedAt) / 1000), ...registry.stats() });
      return;
    }
    sendHttp(res, 404, { error: 'not_found' });
  });

  server.on('upgrade', (req, socket, head) => {
    if ((req.url ?? '').split('?')[0] !== '/v1/link') {
      socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
  });

  // Liveness: a host's address registration is only as good as its socket, so dead
  // sockets must be detected, not just waited out.
  const pinger = setInterval(() => {
    for (const ws of wss.clients) {
      const ctx = ctxOf.get(ws);
      if (!ctx) continue;
      // A socket the shaper paused cannot deliver pongs — not reading it is the
      // whole point — so liveness judgement is suspended until it resumes.
      if (ws.isPaused) { ctx.alive = true; continue; }
      if (!ctx.alive) { ws.terminate(); continue; }
      ctx.alive = false;
      ws.ping();
    }
  }, PING_MS);

  const sweeper = setInterval(() => {
    for (const link of registry.sweep()) {
      close(link.client, Close.idleTimeout, 'link idle');
      if (link.hostRelay) close(link.hostRelay, Close.idleTimeout, 'link idle');
    }
    limiter.sweep(Date.now());
  }, SWEEP_MS);

  return {
    server,
    registry,
    stop(): Promise<void> {
      clearInterval(pinger);
      clearInterval(sweeper);
      for (const ws of wss.clients) ws.close(1001, 'link shutting down');
      return new Promise((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
    },
  };
}
