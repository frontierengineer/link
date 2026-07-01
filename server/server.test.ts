import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { WebSocket, WebSocketServer } from 'ws';
import type { Config } from './config';
import { createLinkServer, type LinkServer } from './server';
import { registerSigningMessage } from './registerAuth';

// A test host: a fresh Ed25519 keypair + an `auth` builder that mirrors the
// client (link/client/src/registerAuth.ts). Signing here with Node's crypto and
// verifying in the server with Node's crypto exercises that interop; the e2e
// self-test exercises @noble-sign ↔ Node-verify.
function makeSigner(): {
  pub: string;
  auth: (address: string, ts?: number, nonce?: string) => { alg: 'ed25519'; pub: string; ts: number; nonce: string; sig: string };
} {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = (publicKey.export({ format: 'jwk' }) as { x: string }).x;
  return {
    pub,
    auth(address, ts = Date.now(), nonce = crypto.randomBytes(16).toString('base64url')) {
      const sig = crypto.sign(null, registerSigningMessage(address, ts, nonce), privateKey).toString('base64url');
      return { alg: 'ed25519', pub, ts, nonce, sig };
    },
  };
}

function config(overrides: Partial<Config> = {}): Config {
  return {
    port: 0,
    relayMaxBps: 0,
    relayHourlyBytes: 0,
    relayTrickleBps: 16_384,
    relayIdleSec: 300,
    ipRatePerMin: 0,
    trustProxy: false,
    ...overrides,
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

interface Frame { data: Buffer; isBinary: boolean }

// A tiny protocol client: JSON control messages land in a queue keyed off
// `type`; anything else (binary, or text that is not JSON — i.e. relayed
// payload) lands in a frame queue.
class Client {
  readonly closed: Promise<number>;
  private readonly messages: Record<string, unknown>[] = [];
  private readonly frames: Frame[] = [];
  private readonly waiters: (() => void)[] = [];

  private constructor(readonly ws: WebSocket) {
    this.closed = new Promise((resolve) => ws.on('close', (code: number) => resolve(code)));
    ws.on('message', (data, isBinary) => {
      const buf = Array.isArray(data) ? Buffer.concat(data)
        : data instanceof ArrayBuffer ? Buffer.from(data) : data;
      if (!isBinary) {
        try {
          this.messages.push(JSON.parse(buf.toString('utf8')) as Record<string, unknown>);
          this.flush();
          return;
        } catch { /* relayed text frame */ }
      }
      this.frames.push({ data: buf, isBinary });
      this.flush();
    });
  }

  static connect(port: number): Promise<Client> {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/v1/link`);
    return new Promise((resolve, reject) => {
      ws.on('open', () => resolve(new Client(ws)));
      ws.on('error', reject);
    });
  }

  private flush(): void {
    for (const w of this.waiters.splice(0)) w();
  }

  private waitUntil<T>(pick: () => T | undefined, what: string, timeoutMs: number): Promise<T> {
    return new Promise((resolve, reject) => {
      const deadline = Date.now() + timeoutMs;
      const check = (): void => {
        const got = pick();
        if (got !== undefined) { resolve(got); return; }
        if (Date.now() > deadline) { reject(new Error(`timed out waiting for ${what}`)); return; }
        this.waiters.push(check);
      };
      check();
    });
  }

  send(msg: unknown): void {
    this.ws.send(JSON.stringify(msg));
  }

  sendFrame(data: Buffer | string, binary = true): void {
    this.ws.send(data, { binary });
  }

  next(type: string, timeoutMs = 5000): Promise<Record<string, unknown>> {
    return this.waitUntil(() => {
      const i = this.messages.findIndex((m) => m.type === type);
      return i === -1 ? undefined : this.messages.splice(i, 1)[0];
    }, `message ${type}`, timeoutMs);
  }

  nextFrame(timeoutMs = 5000): Promise<Frame> {
    return this.waitUntil(() => this.frames.shift(), 'frame', timeoutMs);
  }

  frameCount(): number {
    return this.frames.length;
  }

  has(type: string): boolean {
    return this.messages.some((m) => m.type === type);
  }
}

async function start(overrides: Partial<Config> = {}): Promise<{
  port: number;
  link: LinkServer;
  connect: () => Promise<Client>;
  stats: () => Promise<Record<string, any>>;
  stop: () => Promise<void>;
}> {
  const link = createLinkServer(config(overrides));
  await new Promise<void>((resolve) => link.server.listen(0, '127.0.0.1', resolve));
  const port = (link.server.address() as AddressInfo).port;
  const clients: Client[] = [];
  return {
    port,
    link,
    connect: async () => {
      const c = await Client.connect(port);
      clients.push(c);
      return c;
    },
    stats: async () => {
      const res = await fetch(`http://127.0.0.1:${port}/v1/stats`);
      return await res.json() as Record<string, any>;
    },
    stop: async () => {
      for (const c of clients) c.ws.terminate();
      await link.stop();
    },
  };
}

// Establish a relaying link: host registers an address (signed), a client
// resolves it and asks for a relay, the host dials back the dedicated relay
// socket.
async function establishRelay(s: Awaited<ReturnType<typeof start>>): Promise<{
  hostControl: Client; hostRelay: Client; client: Client; linkId: string;
}> {
  const hostControl = await s.connect();
  const host = makeSigner();
  hostControl.send({ type: 'register', address: 'addr-1', auth: host.auth('addr-1') });
  await hostControl.next('registered');

  const client = await s.connect();
  client.send({ type: 'resolve', address: 'addr-1' });
  const found = await client.next('found');
  const linkId = found.linkId as string;

  client.send({ type: 'relay', linkId });
  const ask = await hostControl.next('relay');
  assert.equal(ask.linkId, linkId);

  const hostRelay = await s.connect();
  hostRelay.send({ type: 'accept', linkId });
  await hostRelay.next('relaying');
  await client.next('relaying');
  return { hostControl, hostRelay, client, linkId };
}

test('introduction: signed address register, resolve, both sides learn; addresses are reusable', async () => {
  const s = await start();
  try {
    const host = await s.connect();
    const signer = makeSigner();
    host.send({ type: 'register', address: 'host-abc', auth: signer.auth('host-abc') });
    assert.equal((await host.next('registered')).address, 'host-abc');

    const client = await s.connect();
    client.send({ type: 'resolve', address: 'host-abc' });
    const found = await client.next('found');
    assert.ok(typeof found.linkId === 'string' && (found.linkId as string).length > 0);
    assert.equal(found.candidates, undefined); // candidates are not part of the protocol

    const arrived = await host.next('arrived');
    assert.equal(arrived.linkId, found.linkId);
    assert.equal(arrived.address, 'host-abc');

    // An address is a REUSABLE routing handle (not single-use like the old codes):
    // a second client resolves the same address and gets its own distinct link.
    const second = await s.connect();
    second.send({ type: 'resolve', address: 'host-abc' });
    const found2 = await second.next('found');
    assert.notEqual(found2.linkId, found.linkId);
    await host.next('arrived');

    // An unknown address resolves to an error, not a hang.
    const miss = await s.connect();
    miss.send({ type: 'resolve', address: 'no-such-host' });
    assert.equal((await miss.next('error')).error, 'unknown_address');

    const health = await fetch(`http://127.0.0.1:${s.port}/health`);
    assert.equal(health.status, 200);
    const stats = await s.stats();
    assert.equal(stats.addressRegistrations, 1);
    assert.equal(stats.links.live, 2);
    assert.equal(stats.liveLinks[0].state, 'introduced');
  } finally {
    await s.stop();
  }
});

test('register auth: unsigned refused; TOFU-pinned; squatter refused; same key replaces; replay + forgery refused', async () => {
  const s = await start();
  try {
    // An unsigned register is refused outright with 4007 — there is no unsigned path.
    const old = await s.connect();
    old.send({ type: 'register', address: 'addr-x' });
    assert.equal(await old.closed, 4007);

    // The first signed register pins the host's key (trust-on-first-use).
    const host = makeSigner();
    const a = await s.connect();
    a.send({ type: 'register', address: 'addr-x', auth: host.auth('addr-x') });
    await a.next('registered');

    // A SQUATTER that knows the address but signs with a DIFFERENT key is refused,
    // and the genuine registration still resolves.
    const squatter = makeSigner();
    const b = await s.connect();
    b.send({ type: 'register', address: 'addr-x', auth: squatter.auth('addr-x') });
    assert.equal((await b.next('error')).error, 'address_pinned');
    const probe = await s.connect();
    probe.send({ type: 'resolve', address: 'addr-x' });
    assert.ok((await probe.next('found')).linkId);

    // The genuine host reconnects (SAME key, newer ts, new socket): it replaces the
    // prior socket (closed 4005) and now holds the address.
    const reconnectAuth = host.auth('addr-x', Date.now() + 1);
    const c = await s.connect();
    c.send({ type: 'register', address: 'addr-x', auth: reconnectAuth });
    await c.next('registered');
    assert.equal(await a.closed, 4005);

    // A REPLAY of that very frame on a fresh socket is refused (timestamp not newer).
    const d = await s.connect();
    d.send({ type: 'register', address: 'addr-x', auth: reconnectAuth });
    assert.equal((await d.next('error')).error, 'register_stale');

    // A FORGED signature (valid shape, wrong bytes) is refused with 4007.
    const e = await s.connect();
    const forged = host.auth('addr-x', Date.now() + 2);
    forged.sig = crypto.randomBytes(64).toString('base64url');
    e.send({ type: 'register', address: 'addr-x', auth: forged });
    assert.equal(await e.closed, 4007);

    // A stale CLOCK (timestamp outside the skew window) is refused with 4007.
    const f = await s.connect();
    f.send({ type: 'register', address: 'addr-y', auth: host.auth('addr-y', Date.now() - 30 * 60 * 1000) });
    assert.equal(await f.closed, 4007);
  } finally {
    await s.stop();
  }
});

test('relay: frames splice verbatim both ways and are counted per link', async () => {
  const s = await start();
  try {
    const { hostRelay, client, linkId } = await establishRelay(s);

    const fromClient = Buffer.from([0, 1, 2, 253, 254, 255]);
    client.sendFrame(fromClient);
    const gotAtHost = await hostRelay.nextFrame();
    assert.deepEqual(gotAtHost.data, fromClient);
    assert.equal(gotAtHost.isBinary, true);

    hostRelay.sendFrame('not json, just relayed text', false);
    const gotAtClient = await client.nextFrame();
    assert.equal(gotAtClient.data.toString(), 'not json, just relayed text');
    assert.equal(gotAtClient.isBinary, false);

    const stats = await s.stats();
    assert.equal(stats.links.relaying, 1);
    assert.equal(stats.links.totalRelayed, 1);
    assert.deepEqual(stats.bytesRelayed, { fromHost: 27, fromClient: 6 });
    const live = stats.liveLinks[0];
    assert.equal(live.linkId, linkId);
    assert.equal(live.state, 'relaying');
    assert.equal(live.bytesFromClient, 6);
    assert.equal(live.bytesFromHost, 27);
    assert.ok(live.relayStartedAt >= live.startedAt);

    // Peer gone: one end vanishing closes the other with 4003, and the finished
    // relay's totals stay visible on the stats surface.
    client.ws.terminate();
    assert.equal(await hostRelay.closed, 4003);
    const after = await s.stats();
    assert.equal(after.links.live, 0);
    assert.equal(after.recentlyClosed[0].linkId, linkId);
    assert.equal(after.recentlyClosed[0].reason, 'peer_gone');
    assert.equal(after.recentlyClosed[0].bytesFromClient, 6);
  } finally {
    await s.stop();
  }
});

test('relay: the rate cap shapes — bytes beyond the burst arrive paced, in order, and nothing closes', async () => {
  const s = await start({ relayMaxBps: 8192 }); // burst capacity 16384
  try {
    const { hostControl, hostRelay, client } = await establishRelay(s);

    // 6 x 4096 = 24576 bytes: the first 16384 ride the burst, the last 8192 must
    // wait for refill — bucket math says the final frame is due at +1000ms, where
    // the old behaviour was a 4008 close.
    const sentAt = Date.now();
    for (let i = 0; i < 6; i++) client.sendFrame(Buffer.alloc(4096, i));
    for (let i = 0; i < 6; i++) {
      const got = await hostRelay.nextFrame(10_000);
      assert.equal(got.data.length, 4096);
      assert.equal(got.data[0], i); // verbatim and strictly FIFO
    }
    const elapsed = Date.now() - sentAt;
    assert.ok(elapsed >= 900, `paced delivery took ${elapsed}ms, expected >= ~1000ms`);
    assert.ok(elapsed < 5000, `paced delivery took ${elapsed}ms, expected ~1000ms`);

    assert.equal(client.ws.readyState, WebSocket.OPEN);
    assert.equal(hostRelay.ws.readyState, WebSocket.OPEN);
    const stats = await s.stats();
    assert.equal(stats.links.relaying, 1);
    assert.deepEqual(stats.recentlyClosed, []);
    assert.equal(stats.bytesRelayed.fromClient, 24576);
    assert.equal(hostControl.has('usage'), false); // quota knob off: no usage events, ever
  } finally {
    await s.stop();
  }
});

test('relay: a frame bigger than the whole burst just waits for tokens instead of closing', async () => {
  const s = await start({ relayMaxBps: 16_384 }); // burst capacity 32768
  try {
    const { hostRelay, client } = await establishRelay(s);
    const sentAt = Date.now();
    client.sendFrame(Buffer.alloc(49_152, 7)); // 1.5x the burst -> 16384 in debt -> due at +1000ms
    const got = await hostRelay.nextFrame(10_000);
    const elapsed = Date.now() - sentAt;
    assert.equal(got.data.length, 49_152);
    assert.equal(got.data[100], 7);
    assert.ok(elapsed >= 900, `over-burst frame took ${elapsed}ms, expected >= ~1000ms`);
    assert.equal(client.ws.readyState, WebSocket.OPEN);
    assert.equal((await s.stats()).recentlyClosed.length, 0);
  } finally {
    await s.stop();
  }
});

test('relay: quota exhaustion drops to the trickle floor — frames keep flowing and the host control socket hears about it', async () => {
  const s = await start({ relayHourlyBytes: 2000, relayTrickleBps: 1024 }); // trickle burst 2048
  try {
    const { hostControl, hostRelay, client } = await establishRelay(s);

    client.sendFrame(Buffer.alloc(1500)); // within quota: instant
    assert.equal((await hostRelay.nextFrame()).data.length, 1500);
    const first = await hostControl.next('usage');
    assert.ok((first.used as number) >= 0.74 && (first.used as number) <= 0.76, `used=${first.used}`);
    assert.equal(first.throttled, false);

    await sleep(1100); // clear the per-link usage event rate limit
    client.sendFrame(Buffer.alloc(2048)); // empties the quota; shortfall rides the trickle burst
    assert.equal((await hostRelay.nextFrame()).data.length, 2048);
    const flip = await hostControl.next('usage');
    assert.equal(flip.used, 1);
    assert.equal(flip.throttled, true);

    // Fully on the floor now: the next frame is paced at ~1024 B/s, where the old
    // behaviour was a 4009 close.
    const sentAt = Date.now();
    client.sendFrame(Buffer.alloc(2048));
    assert.equal((await hostRelay.nextFrame(10_000)).data.length, 2048);
    const elapsed = Date.now() - sentAt;
    assert.ok(elapsed >= 1200, `trickled frame took ${elapsed}ms, expected >= ~1400ms`);

    // Small control-sized traffic keeps flowing — a quota-spent machine never goes
    // dark.
    client.sendFrame(Buffer.from('heartbeat'));
    assert.equal((await hostRelay.nextFrame()).data.length, 9);

    assert.equal(client.ws.readyState, WebSocket.OPEN);
    assert.equal(hostRelay.ws.readyState, WebSocket.OPEN);
    const stats = await s.stats();
    assert.deepEqual(stats.recentlyClosed, []);
    assert.ok(stats.liveLinks[0].usedFraction >= 0.99);
    assert.equal(stats.liveLinks[0].throttled, true);
  } finally {
    await s.stop();
  }
});

test('usage: fraction tier crossings reach the host control socket; same-tier traffic stays quiet', async () => {
  const s = await start({ relayHourlyBytes: 100_000 });
  try {
    const { hostControl, hostRelay, client } = await establishRelay(s);
    const expectUsage = async (bytes: number, around: number) => {
      client.sendFrame(Buffer.alloc(bytes));
      await hostRelay.nextFrame();
      const usage = await hostControl.next('usage');
      assert.ok(Math.abs((usage.used as number) - around) < 0.015,
        `used=${usage.used}, expected ~${around}`);
      assert.equal(usage.throttled, false);
      await sleep(1100); // step past the per-link rate limit between tiers
    };
    await expectUsage(51_000, 0.51); // crosses 0.5
    await expectUsage(30_000, 0.81); // crosses 0.8
    await expectUsage(15_000, 0.96); // crosses 0.95
    client.sendFrame(Buffer.alloc(100)); // same tier: silence
    await hostRelay.nextFrame();
    await sleep(200);
    assert.equal(hostControl.has('usage'), false);
  } finally {
    await s.stop();
  }
});

test('ws@8 pause mechanism: a paused socket stops emitting message events until resume()', async () => {
  const wss = new WebSocketServer({ port: 0, host: '127.0.0.1' });
  await new Promise<void>((resolve) => wss.on('listening', resolve));
  let received = 0;
  let serverWs: WebSocket | undefined;
  wss.on('connection', (ws) => {
    serverWs = ws;
    ws.on('message', () => { received++; });
  });
  const port = (wss.address() as AddressInfo).port;
  const client = new WebSocket(`ws://127.0.0.1:${port}/`);
  await new Promise<void>((resolve) => client.on('open', resolve));
  try {
    client.send('one');
    const firstBy = Date.now() + 2000;
    while (received < 1 && Date.now() < firstBy) await sleep(10);
    assert.equal(received, 1);
    serverWs!.pause();
    assert.equal(serverWs!.isPaused, true);

    for (let i = 0; i < 5; i++) {
      client.send(`more-${i}`);
      await sleep(30);
    }
    await sleep(300);
    assert.equal(received, 1); // nothing emitted while paused

    serverWs!.resume();
    const deadline = Date.now() + 2000;
    while (received < 6 && Date.now() < deadline) await sleep(10);
    assert.equal(received, 6); // everything the sender pushed arrives on resume
  } finally {
    client.terminate();
    await new Promise<void>((resolve) => wss.close(() => resolve()));
  }
});

test('relay: an idle link is reaped with 4004 on both ends', async () => {
  const s = await start({ relayIdleSec: 1 });
  try {
    const { hostRelay, client } = await establishRelay(s);
    assert.equal(await client.closed, 4004);
    assert.equal(await hostRelay.closed, 4004);
    const stats = await s.stats();
    assert.equal(stats.links.live, 0);
    assert.equal(stats.recentlyClosed[0].reason, 'idle');
  } finally {
    await s.stop();
  }
});

test('foot-gun guard: Link has no "code" vocabulary — a code-bearing register/resolve is refused', async () => {
  const s = await start();
  try {
    // The brute-forceable code-rendezvous path is GONE from the wire. Link's only
    // rendezvous key is the signed `address`; a frame carrying a `code` but no
    // address is just a malformed register/resolve and is refused. So NO client —
    // careless or malicious — can ever put a pairing secret in front of Link. The
    // code lives only inside the two endpoints' SPAKE2 handshake.
    const reg = await s.connect();
    reg.send({ type: 'register', code: 'ABC123', candidates: ['x:1'], ttlSec: 900 });
    assert.equal(await reg.closed, 4000, 'a code-bearing register (no address) is a bad request');

    const res = await s.connect();
    res.send({ type: 'resolve', code: 'ABC123' });
    assert.equal(await res.closed, 4000, 'a code-bearing resolve (no address) is a bad request');
  } finally {
    await s.stop();
  }
});

test('per-IP rate limit closes register/resolve abuse with 4002', async () => {
  const s = await start({ ipRatePerMin: 2 });
  try {
    const probe = await s.connect();
    probe.send({ type: 'resolve', address: 'addr-guess-1' });
    assert.equal((await probe.next('error')).error, 'unknown_address');
    probe.send({ type: 'resolve', address: 'addr-guess-2' });
    assert.equal((await probe.next('error')).error, 'unknown_address');
    probe.send({ type: 'resolve', address: 'addr-guess-3' });
    assert.equal(await probe.closed, 4002);
  } finally {
    await s.stop();
  }
});
