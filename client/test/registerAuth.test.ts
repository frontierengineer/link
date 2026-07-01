// Authenticated reach registration — the anti-squat trust boundary, end to end.
//
// These tests spawn a REAL Link server (link/server) and drive it with raw
// WebSocket register frames, so they exercise the actual sign (client) → verify
// (server) path and the server's trust-on-first-use pin. They are written to
// FAIL on the old last-writer-wins server (a squatter's register would displace
// the genuine host) and PASS on the authenticated one (the squatter is refused).
//
// Run under: npm run test:unit  (node --import tsx --test)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
import net from 'node:net';
import { WebSocket } from 'ws';

import { serveHost, generateHostIdentity } from '../src/index.js';
import { makeRegisterAuth, registerSignerFromStatic } from '../src/registerAuth.js';
import { randomBytes } from '../src/bytes.js';

// 4007: a reach register without a valid signed auth is refused (link/server types.ts).
const CLOSE_REGISTER_AUTH = 4007;
const CLOSE_REPLACED = 4005;

const SERVER_ENTRY = fileURLToPath(new URL('../../server/index.ts', import.meta.url));
const CLIENT_ROOT = fileURLToPath(new URL('..', import.meta.url));

function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const port = (srv.address() as net.AddressInfo).port;
      srv.close(() => resolve(port));
    });
  });
}
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

function health(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const req = http.get({ host: '127.0.0.1', port, path: '/health', timeout: 1500 }, (res) => {
      res.resume();
      resolve(res.statusCode === 200);
    });
    req.on('error', () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
  });
}

interface LinkProc { port: number; url: string; kill: () => void }
async function spawnLink(): Promise<LinkProc> {
  const port = await getFreePort();
  const proc: ChildProcess = spawn(process.execPath, ['--import', 'tsx', SERVER_ENTRY], {
    cwd: CLIENT_ROOT,
    env: { ...process.env, LINK_PORT: String(port), LINK_IP_RATE_PER_MIN: '0', LINK_RELAY_IDLE_SEC: '120' },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  let stderr = '';
  proc.stderr?.on('data', (d: Buffer) => (stderr += d.toString()));
  const deadline = Date.now() + 9000;
  while (Date.now() < deadline) {
    if (await health(port)) return { port, url: `ws://127.0.0.1:${port}/v1/link`, kill: () => proc.kill('SIGKILL') };
    await sleep(150);
  }
  proc.kill('SIGKILL');
  throw new Error(`link did not become healthy; stderr=${stderr.slice(0, 500)}`);
}

// A tiny raw protocol client: JSON control messages queue by `type`; close code resolves.
class Raw {
  readonly closed: Promise<number>;
  private readonly msgs: Record<string, unknown>[] = [];
  private readonly waiters: (() => void)[] = [];
  private constructor(readonly ws: WebSocket) {
    this.closed = new Promise((resolve) => ws.on('close', (code: number) => resolve(code)));
    ws.on('message', (data: Buffer, isBinary: boolean) => {
      if (isBinary) return;
      try { this.msgs.push(JSON.parse(data.toString())); } catch { return; }
      for (const w of this.waiters.splice(0)) w();
    });
  }
  static connect(url: string): Promise<Raw> {
    const ws = new WebSocket(url);
    return new Promise((resolve, reject) => {
      ws.on('open', () => resolve(new Raw(ws)));
      ws.on('error', reject);
    });
  }
  send(msg: unknown): void { this.ws.send(JSON.stringify(msg)); }
  next(type: string, timeoutMs = 5000): Promise<Record<string, unknown>> {
    return new Promise((resolve, reject) => {
      const deadline = Date.now() + timeoutMs;
      const check = (): void => {
        const i = this.msgs.findIndex((m) => m.type === type);
        if (i !== -1) { resolve(this.msgs.splice(i, 1)[0]!); return; }
        if (Date.now() > deadline) { reject(new Error(`timed out waiting for ${type}`)); return; }
        this.waiters.push(check);
      };
      check();
    });
  }
}

test('anti-squat (raw frames): unsigned refused, TOFU-pinned, wrong key refused, same key replaces, replay refused', async () => {
  const link = await spawnLink();
  const address = 'addr-squat-test';
  const genuine = registerSignerFromStatic(randomBytes(32));
  const squatter = registerSignerFromStatic(randomBytes(32)); // a DIFFERENT key

  try {
    // 1) Unsigned register is refused outright (4007).
    const old = await Raw.connect(link.url);
    old.send({ type: 'register', address });
    assert.equal(await old.closed, CLOSE_REGISTER_AUTH, 'unsigned register is refused with 4007');

    // 2) The genuine host registers signed → pinned (TOFU).
    const a = await Raw.connect(link.url);
    a.send({ type: 'register', address, auth: makeRegisterAuth(genuine, address) });
    await a.next('registered');

    // 3) A squatter that KNOWS the address but signs with a different key is
    //    refused, and the genuine registration is untouched (still resolves to it).
    const b = await Raw.connect(link.url);
    b.send({ type: 'register', address, auth: makeRegisterAuth(squatter, address) });
    assert.equal((await b.next('error')).error, 'address_pinned', 'a wrong-key re-register is rejected');
    const probe = await Raw.connect(link.url);
    probe.send({ type: 'resolve', address });
    assert.ok((await probe.next('found')).linkId, 'the genuine host still holds the address');

    // 4) The genuine host reconnects (SAME key, fresh frame, new socket): accepted,
    //    and the prior socket is retired with 4005.
    const reAuth = makeRegisterAuth(genuine, address);
    const c = await Raw.connect(link.url);
    c.send({ type: 'register', address, auth: reAuth });
    await c.next('registered');
    assert.equal(await a.closed, CLOSE_REPLACED, 'the genuine host re-registers and retires its ghost (4005)');

    // 5) A replay of that very frame on a fresh socket is refused (stale timestamp).
    const d = await Raw.connect(link.url);
    d.send({ type: 'register', address, auth: reAuth });
    assert.equal((await d.next('error')).error, 'register_stale', 'a replayed register frame is rejected');
  } finally {
    link.kill();
    await sleep(100);
  }
});

test('anti-squat (real serveHost): a live host cannot be displaced by a squatter who knows its address', async () => {
  const link = await spawnLink();
  // The genuine host uses the real production path: serveHost → HostUplinks signs
  // each register with a key derived from its static identity. @noble signs; the
  // server verifies with Node crypto — the cross-stack interop that matters most.
  const host = await serveHost({
    uplinks: [link.url],
    hostStatic: generateHostIdentity(),
    onRequest: (cmd) => cmd,
  });
  try {
    assert.equal(host.registeredCount, 1, 'the host registered (signed) with the uplink');

    // A squatter that learned the address tries to take it over with its own key.
    const squatter = registerSignerFromStatic(randomBytes(32));
    const s = await Raw.connect(link.url);
    s.send({ type: 'register', address: host.address, auth: makeRegisterAuth(squatter, host.address) });
    assert.equal((await s.next('error')).error, 'address_pinned', 'the squatter is refused');

    // The live host is undisturbed: it still registers, and a resolve still finds
    // the genuine host (not the squatter's).
    assert.equal(host.registeredCount, 1, 'the host is still registered after the squat attempt');
    const probe = await Raw.connect(link.url);
    probe.send({ type: 'resolve', address: host.address });
    assert.ok((await probe.next('found')).linkId, 'resolve still returns the genuine host');
  } finally {
    await host.stop();
    link.kill();
    await sleep(100);
  }
});
