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
import { makeRegisterAuth, registerSignerFromStatic, addressForRegisterKey } from '../src/registerAuth.js';
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

interface LinkProc { port: number; url: string; origin: string; kill: () => void }
async function spawnLink(env: Record<string, string> = {}): Promise<LinkProc> {
  const port = await getFreePort();
  const proc: ChildProcess = spawn(process.execPath, ['--import', 'tsx', SERVER_ENTRY], {
    cwd: CLIENT_ROOT,
    env: { ...process.env, LINK_PORT: String(port), LINK_IP_RATE_PER_MIN: '0', LINK_RELAY_IDLE_SEC: '120', ...env },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  let stderr = '';
  proc.stderr?.on('data', (d: Buffer) => (stderr += d.toString()));
  const deadline = Date.now() + 9000;
  while (Date.now() < deadline) {
    if (await health(port)) {
      return { port, url: `ws://127.0.0.1:${port}/v1/link`, origin: `127.0.0.1:${port}`, kill: () => proc.kill('SIGKILL') };
    }
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
  // Binding is always on: the address IS the commitment to the genuine host's key
  // (base64url(sha256(pub))), so the genuine signer's own committed address is the
  // only address any of these frames can legally carry.
  const link = await spawnLink();
  const o = link.origin;
  const genuine = registerSignerFromStatic(randomBytes(32));
  const squatter = registerSignerFromStatic(randomBytes(32)); // a DIFFERENT key
  const address = addressForRegisterKey(genuine.pub);

  try {
    // 1) Unsigned register is refused outright (4007).
    const old = await Raw.connect(link.url);
    old.send({ type: 'register', address });
    assert.equal(await old.closed, CLOSE_REGISTER_AUTH, 'unsigned register is refused with 4007');

    // 2) The genuine host registers signed → pinned (TOFU).
    const a = await Raw.connect(link.url);
    a.send({ type: 'register', address, auth: makeRegisterAuth(genuine, address, o) });
    await a.next('registered');

    // 3) A squatter that KNOWS the address but signs with a different key cannot even
    //    form a valid frame for it: binding requires address === commitment(key), so
    //    its register for the victim's address fails auth (4007). The genuine
    //    registration is untouched (still resolves to it).
    const b = await Raw.connect(link.url);
    b.send({ type: 'register', address, auth: makeRegisterAuth(squatter, address, o) });
    assert.equal(await b.closed, CLOSE_REGISTER_AUTH, 'a wrong-key register is refused at the binding check (4007)');
    const probe = await Raw.connect(link.url);
    probe.send({ type: 'resolve', address });
    assert.ok((await probe.next('found')).linkId, 'the genuine host still holds the address');

    // 4) The genuine host reconnects (SAME key, fresh frame, new socket): accepted,
    //    and the prior socket is retired with 4005.
    const reAuth = makeRegisterAuth(genuine, address, o);
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

test('address-key binding (raw frames): the committed address is required; a mismatched address (and any squatter) is refused', async () => {
  // Default mode: the server binds the address to the register key.
  const link = await spawnLink();
  const o = link.origin;
  const genuine = registerSignerFromStatic(randomBytes(32));
  const boundAddress = addressForRegisterKey(genuine.pub);
  try {
    // An arbitrary (non-committed) address is refused even with a valid signature.
    const bad = await Raw.connect(link.url);
    bad.send({ type: 'register', address: 'not-the-commitment', auth: makeRegisterAuth(genuine, 'not-the-commitment', o) });
    assert.equal(await bad.closed, CLOSE_REGISTER_AUTH, 'a non-committed address is refused with 4007');

    // The committed address base64url(sha256(pub)) registers.
    const a = await Raw.connect(link.url);
    a.send({ type: 'register', address: boundAddress, auth: makeRegisterAuth(genuine, boundAddress, o) });
    await a.next('registered');

    // A squatter cannot produce a key that hashes to the victim's address, so it can
    // never even craft a passable frame for it — the squat race is impossible.
    const squatter = registerSignerFromStatic(randomBytes(32));
    const s = await Raw.connect(link.url);
    s.send({ type: 'register', address: boundAddress, auth: makeRegisterAuth(squatter, boundAddress, o) });
    assert.equal(await s.closed, CLOSE_REGISTER_AUTH, 'a squatter is refused at the binding check');
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
    // serveHost derives its address as the commitment to its register key, so on a
    // binding-enforcing Link (the default) the address is spoof-PROOF.
    assert.equal(host.address, addressForRegisterKey(registerSignerFromStatic(host.hostStatic.priv).pub));

    // A squatter that learned the address tries to take it over with its own key. It
    // cannot even craft a frame that passes binding (its key does not hash to the
    // address), so it is refused at the binding check (4007) — the squat never lands.
    const squatter = registerSignerFromStatic(randomBytes(32));
    const s = await Raw.connect(link.url);
    s.send({ type: 'register', address: host.address, auth: makeRegisterAuth(squatter, host.address, link.origin) });
    assert.equal(await s.closed, CLOSE_REGISTER_AUTH, 'the squatter is refused');

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
