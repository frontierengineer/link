// Backward-compatibility contract for the Link wire protocol.
//
// WHY THIS EXISTS. A released Frontier app embeds a FROZEN copy of the link client
// (vendored at build time). You cannot re-pin an app already on someone's machine,
// so the relay MUST keep accepting the frames older clients send — forever, or
// until you deliberately negotiate a new version. This is the real compatibility
// guarantee (a version "pin" cannot provide it: it only syncs a fresh build).
//
// HOW IT WORKS. This file freezes the **v1 wire protocol as its OWN copy** — the
// signing-message layout, the address commitment, and the frame shapes — and
// asserts the CURRENT relay (createLinkServer, imported live) still accepts it,
// end to end. Everything a "v1 client" sends is built from the frozen copy below;
// the live modules are imported ONLY to prove they still match v1. The moment a
// change breaks v1, a test here goes red — forcing you to keep backward compat or
// to add an explicit new version.
//
// ADDING A PROTOCOL VERSION. Never edit the frozen v1 block to track new behaviour
// (that silently drops the guarantee). Add a `v2` block beside it and keep v1 —
// released clients still speak v1, so the relay must still accept it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { WebSocket } from 'ws';
import type { Config } from './config';
import { createLinkServer } from './server';
// LIVE canonical protocol — imported ONLY to assert it still equals frozen v1.
// A v1 client is NEVER built from these; it is built from the frozen copy below.
import { registerSigningMessage, addressForRegisterKey } from './registerAuth';

// ─────────────────────────────────────────────────────────────────────────────
// FROZEN v1 WIRE PROTOCOL — a byte-for-byte copy of what a v1 client sends.
// DO NOT edit to match new behaviour. To evolve the protocol, add a v2 block.
// ─────────────────────────────────────────────────────────────────────────────
const V1_ORIGIN = 'compat.v1.link';
const V1_REGISTER_DOMAIN = Buffer.from('frontier-link-register-v1', 'utf8');

function v1LenStr(s: string): Buffer {
  const body = Buffer.from(s, 'utf8');
  const head = Buffer.alloc(4);
  head.writeUInt32BE(body.length, 0);
  return Buffer.concat([head, body]);
}
function v1SigningMessage(address: string, ts: number, nonce: string, origin: string): Buffer {
  return Buffer.concat([
    V1_REGISTER_DOMAIN,
    v1LenStr(address),
    v1LenStr(String(ts)),
    v1LenStr(nonce),
    v1LenStr(origin),
  ]);
}
function v1AddressForKey(pubRaw: Buffer): string {
  return crypto.createHash('sha256').update(pubRaw).digest('base64url');
}
// A v1 host: a fresh key, and register frames shaped exactly as a v1 client emits.
function v1Host(origin: string): { address: string; registerFrame: () => unknown } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = (publicKey.export({ format: 'jwk' }) as { x: string }).x;
  const address = v1AddressForKey(Buffer.from(pub, 'base64url'));
  return {
    address,
    registerFrame() {
      const ts = Date.now();
      const nonce = crypto.randomBytes(16).toString('base64url');
      const sig = crypto.sign(null, v1SigningMessage(address, ts, nonce, origin), privateKey).toString('base64url');
      return { type: 'register', address, auth: { alg: 'ed25519', pub, ts, nonce, sig } };
    },
  };
}
const v1ResolveFrame = (address: string): unknown => ({ type: 'resolve', address });

// ── minimal self-contained harness (deliberately NOT shared with server.test.ts) ──
function config(overrides: Partial<Config> = {}): Config {
  return {
    port: 0,
    relayMaxBps: 0,
    relayHourlyBytes: 0,
    relayTrickleBps: 16_384,
    relayIdleSec: 300,
    ipRatePerMin: 0,
    trustProxy: false,
    allowedRegisterKeys: new Set<string>(),
    origin: V1_ORIGIN,
    ...overrides,
  };
}
class Peer {
  readonly closed: Promise<number>;
  private readonly msgs: Record<string, unknown>[] = [];
  private readonly frames: Buffer[] = [];
  private readonly waiters: (() => void)[] = [];
  private constructor(readonly ws: WebSocket) {
    this.closed = new Promise((r) => ws.on('close', (c: number) => r(c)));
    ws.on('message', (data: Buffer | ArrayBuffer | Buffer[], isBinary: boolean) => {
      const buf = Array.isArray(data) ? Buffer.concat(data) : data instanceof ArrayBuffer ? Buffer.from(data) : data;
      if (!isBinary) {
        try {
          this.msgs.push(JSON.parse(buf.toString('utf8')) as Record<string, unknown>);
          this.wake();
          return;
        } catch { /* relayed text frame */ }
      }
      this.frames.push(buf);
      this.wake();
    });
  }
  static connect(port: number): Promise<Peer> {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/v1/link`);
    return new Promise((res, rej) => {
      ws.on('open', () => res(new Peer(ws)));
      ws.on('error', rej);
    });
  }
  private wake(): void { for (const w of this.waiters.splice(0)) w(); }
  private until<T>(pick: () => T | undefined, what: string, ms: number): Promise<T> {
    return new Promise((res, rej) => {
      const deadline = Date.now() + ms;
      const check = (): void => {
        const g = pick();
        if (g !== undefined) return res(g);
        if (Date.now() > deadline) return rej(new Error(`timeout waiting for ${what}`));
        this.waiters.push(check);
      };
      check();
    });
  }
  send(m: unknown): void { this.ws.send(JSON.stringify(m)); }
  sendFrame(b: Buffer): void { this.ws.send(b, { binary: true }); }
  next(type: string, ms = 5000): Promise<Record<string, unknown>> {
    return this.until(() => {
      const i = this.msgs.findIndex((m) => m.type === type);
      return i === -1 ? undefined : this.msgs.splice(i, 1)[0];
    }, `message ${type}`, ms);
  }
  frame(ms = 5000): Promise<Buffer> { return this.until(() => this.frames.shift(), 'binary frame', ms); }
}
async function start(overrides: Partial<Config> = {}): Promise<{ port: number; connect: () => Promise<Peer>; stop: () => Promise<void> }> {
  const link = createLinkServer(config(overrides));
  await new Promise<void>((r) => link.server.listen(0, '127.0.0.1', r));
  const port = (link.server.address() as AddressInfo).port;
  const peers: Peer[] = [];
  return {
    port,
    connect: async () => { const p = await Peer.connect(port); peers.push(p); return p; },
    stop: async () => { for (const p of peers) p.ws.terminate(); await link.stop(); },
  };
}

// ── the guarantee ────────────────────────────────────────────────────────────

test('v1 signing message + address commitment still equal the live protocol', () => {
  // If the live canonical protocol drifts from frozen v1, every released client
  // breaks. These fail the moment it does — keep v1 compatible or add a real v2.
  for (let i = 0; i < 64; i++) {
    const address = crypto.randomBytes(8).toString('base64url');
    const ts = Date.now() - i * 1000;
    const nonce = crypto.randomBytes(12).toString('base64url');
    const origin = i % 3 === 0 ? '' : `host-${i}.link:443`;
    assert.ok(
      registerSigningMessage(address, ts, nonce, origin).equals(v1SigningMessage(address, ts, nonce, origin)),
      'live registerSigningMessage must be byte-identical to frozen v1',
    );
  }
  const pub = Buffer.from(
    (crypto.generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }) as { x: string }).x,
    'base64url',
  );
  assert.equal(addressForRegisterKey(pub), v1AddressForKey(pub), 'address commitment must equal frozen v1');
});

test('the current relay accepts a v1-built register', async () => {
  const s = await start();
  try {
    const host = await s.connect();
    const v1 = v1Host(V1_ORIGIN);
    host.send(v1.registerFrame());
    const reg = await host.next('registered');
    assert.equal(reg.address, v1.address);
  } finally { await s.stop(); }
});

test('the current relay accepts a v1 resolve and introduces host↔client', async () => {
  const s = await start();
  try {
    const hostC = await s.connect();
    const v1 = v1Host(V1_ORIGIN);
    hostC.send(v1.registerFrame());
    await hostC.next('registered');

    const client = await s.connect();
    client.send(v1ResolveFrame(v1.address));
    const found = await client.next('found');
    assert.ok(typeof found.linkId === 'string' && (found.linkId as string).length > 0);
    assert.equal((await hostC.next('arrived')).linkId, found.linkId);
  } finally { await s.stop(); }
});

test('a v1 host + v1 client complete a full relay splice (bytes both directions)', async () => {
  const s = await start();
  try {
    const hostControl = await s.connect();
    const v1 = v1Host(V1_ORIGIN);
    hostControl.send(v1.registerFrame());
    await hostControl.next('registered');

    const client = await s.connect();
    client.send(v1ResolveFrame(v1.address));
    const linkId = (await client.next('found')).linkId as string;

    client.send({ type: 'relay', linkId });
    assert.equal((await hostControl.next('relay')).linkId, linkId);

    const hostRelay = await s.connect();
    hostRelay.send({ type: 'accept', linkId });
    await hostRelay.next('relaying');
    await client.next('relaying');

    // content-blind splice, both directions
    client.sendFrame(Buffer.from('ping-from-client'));
    assert.equal((await hostRelay.frame()).toString('utf8'), 'ping-from-client');
    hostRelay.sendFrame(Buffer.from('pong-from-host'));
    assert.equal((await client.frame()).toString('utf8'), 'pong-from-host');
  } finally { await s.stop(); }
});
