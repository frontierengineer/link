// End-to-end self-test (the headline). Spawns TWO real Link server processes,
// stands up a host registered to both, and walks a client through the whole
// lifecycle: pair with a 6-character code over uplink A, sealed request, kill A
// and fail over to uplink B by token reconnect, an explicit fresh token
// reconnect, and finally revoke -> next connect refused. Prints PASS/FAIL per
// stage; exits non-zero on any fail.
//
// Run: npm run test:e2e   (or: node --import tsx test/e2e.selftest.ts)

import { spawn, type ChildProcess } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import http from 'node:http';
import net from 'node:net';
import assert from 'node:assert/strict';

import {
  connect,
  serveHost,
  generateHostIdentity,
  DeviceRevokedError,
  type Connection,
  type Host,
  type ConnState,
  type LinkUsage,
} from '../src/index.js';

// ── tiny stage harness ──
let failures = 0;
const t0 = Date.now();
async function stage(name: string, fn: () => Promise<void> | void): Promise<void> {
  const started = Date.now();
  try {
    await fn();
    console.log(`PASS  ${name}  (${Date.now() - started}ms)`);
  } catch (e) {
    failures++;
    const msg = e instanceof Error ? e.stack ?? e.message : String(e);
    console.log(`FAIL  ${name}\n      ${msg.replace(/\n/g, '\n      ')}`);
  }
}

// ── helpers ──
function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      srv.close(() => resolve(port));
    });
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function health(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const req = http.get({ host: '127.0.0.1', port, path: '/health', timeout: 1500 }, (res) => {
      res.resume();
      resolve(res.statusCode === 200);
    });
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
  });
}

async function waitForHealth(port: number, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await health(port)) return;
    await sleep(150);
  }
  throw new Error(`link on :${port} did not become healthy`);
}

interface LinkProc {
  name: string;
  port: number;
  url: string;
  proc: ChildProcess;
  kill: () => void;
}

const SERVER_ENTRY = fileURLToPath(new URL('../../server/index.ts', import.meta.url));
const CLIENT_ROOT = fileURLToPath(new URL('..', import.meta.url));

async function spawnLink(name: string): Promise<LinkProc> {
  const port = await getFreePort();
  const proc = spawn(process.execPath, ['--import', 'tsx', SERVER_ENTRY], {
    cwd: CLIENT_ROOT,
    env: { ...process.env, LINK_PORT: String(port), LINK_IP_RATE_PER_MIN: '0', LINK_RELAY_IDLE_SEC: '120' },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  let stderr = '';
  proc.stderr?.on('data', (d: Buffer) => (stderr += d.toString()));
  try {
    await waitForHealth(port, 9000);
  } catch (e) {
    proc.kill('SIGKILL');
    throw new Error(`${name} failed to start: ${(e as Error).message}; stderr=${stderr.slice(0, 500)}`);
  }
  return { name, port, url: `ws://127.0.0.1:${port}/v1/link`, proc, kill: () => proc.kill('SIGKILL') };
}

// ── the run ──
async function main(): Promise<void> {
  const PAIR_CODE = 'K7P2QX'; // exactly 6 characters
  assert.equal(PAIR_CODE.length, 6, 'pairing code is 6 characters');

  let linkA: LinkProc | undefined;
  let linkB: LinkProc | undefined;
  let host: Host | undefined;
  let conn: Connection | undefined;
  const states: ConnState[] = [];
  const usageReports: LinkUsage[][] = [];

  await stage('1. spawn two Link server instances (A, B)', async () => {
    [linkA, linkB] = await Promise.all([spawnLink('A'), spawnLink('B')]);
    assert.ok(await health(linkA.port), 'A healthy');
    assert.ok(await health(linkB.port), 'B healthy');
  });

  await stage('2. host registers with BOTH uplinks', async () => {
    host = await serveHost({
      uplinks: [linkA!.url, linkB!.url],
      hostStatic: generateHostIdentity(),
      pairingCode: PAIR_CODE,
      maxPairAttempts: 5,
      onRequest: (cmd) => cmd, // echo
      onUsage: (conns) => usageReports.push(conns),
    });
    assert.equal(host.registeredCount, 2, 'registered to both uplinks');
  });

  await stage('3. client first-pairs (address rendezvous + 6-char code) over uplink A', async () => {
    // The "QR" path: rendezvous on the high-entropy address; the 6-char code keys
    // SPAKE2 only, so it is never exposed to the Link in any form (raw or hashed).
    conn = await connect({
      uplinks: [linkA!.url, linkB!.url],
      address: host!.address,
      code: PAIR_CODE,
      onState: (s) => states.push(s),
      dial: { connectTimeoutMs: 4000, controlTimeoutMs: 4000 },
    });
    assert.equal(conn.state, 'connected', 'connected');
    assert.ok(conn.via.startsWith(`relay:${linkA!.url}`), `paired via uplink A (got ${conn.via})`);
    assert.ok(conn.credential, 'a credential was issued');
    assert.equal(conn.credential!.address, host!.address, 'credential pins the host address');
    assert.equal(host!.sessions.size, 1, 'host sees one live session');
  });

  await stage('3b. TWO live pairing codes admit two clients concurrently, each burning only its own', async () => {
    // The capability one-code-at-a-time could not offer. Two workers are set up
    // at the same moment — the common real case is the host's own colocated
    // worker enrolling at boot while an operator mints their first code — and
    // neither may displace or invalidate the other.
    const a = host!.openPairingCode('AAA111');
    const b = host!.openPairingCode('BBB222');
    assert.notEqual(a.codeId, b.codeId, 'each open gets its own id');
    assert.equal(host!.livePairingCodes().length, 2, 'both are live at once');

    const dial = { connectTimeoutMs: 4000, controlTimeoutMs: 4000 };
    // Concurrently, deliberately: serialising them would hide exactly the race
    // that made this necessary.
    const [ca, cb] = await Promise.all([
      connect({ uplinks: [linkA!.url], address: host!.address, code: 'AAA111', codeId: a.codeId, dial }),
      connect({ uplinks: [linkA!.url], address: host!.address, code: 'BBB222', codeId: b.codeId, dial }),
    ]);
    assert.equal(ca.state, 'connected', 'the first code paired');
    assert.equal(cb.state, 'connected', 'the second code paired, and did not kill the first');
    assert.notEqual(ca.credential!.keyId, cb.credential!.keyId, 'two distinct devices were enrolled');
    assert.equal(host!.livePairingCodes().length, 0, 'each code is single-use and burned on its own success');

    // A third client presenting a burned id is refused rather than served some
    // other live code.
    let refused = false;
    await connect({ uplinks: [linkA!.url], address: host!.address, code: 'AAA111', codeId: a.codeId, dial, autoReconnect: false })
      .catch(() => { refused = true; });
    assert.ok(refused, 'a spent code id pairs nothing');

    await ca.close();
    await cb.close();
  });

  await stage('4. sealed request round-trips', async () => {
    const reply = await conn!.request({ echo: 'hello-1', n: 7 });
    assert.deepEqual(reply, { echo: 'hello-1', n: 7 }, 'host echoed the sealed request');
  });

  await stage('4b. host pulls usage: one connection, reported "unlimited" (no quota configured)', async () => {
    host!.requestUsage();
    // The pull answers on onUsage, once per uplink; find the uplink that owns the
    // live connection. No quota is set on these relays, so it must be `unlimited`
    // (never a zero fraction, which would leak that a limit exists).
    const deadline = Date.now() + 4000;
    let owned: LinkUsage[] | undefined;
    while (Date.now() < deadline && !owned) {
      owned = usageReports.find((r) => r.length > 0);
      if (!owned) await sleep(50);
    }
    assert.ok(owned, 'a usage report named at least one connection');
    assert.equal(owned!.length, 1, 'the host owns exactly one live connection');
    assert.equal('unlimited' in owned![0]! && owned![0]!.unlimited, true, 'reported as unlimited, not a byte count or a zero fraction');
  });

  await stage('5. kill uplink A -> client fails over to B and token-reconnects', async () => {
    linkA!.kill();
    // The live session drops; the supervisor re-handshakes over the next uplink
    // using the token + pinned key. request() transparently awaits that.
    const reply = await conn!.request({ echo: 'after-failover' }, 12_000);
    assert.deepEqual(reply, { echo: 'after-failover' }, 'request round-trips after failover');
    assert.ok(conn!.via.startsWith(`relay:${linkB!.url}`), `now connected via uplink B (got ${conn!.via})`);
    assert.ok(states.includes('reconnecting'), 'state passed through reconnecting');
    assert.equal(conn!.state, 'connected', 'reconnected');
  });

  await stage('6. explicit fresh token reconnect (new connection, no code)', async () => {
    const cred = conn!.credential!;
    conn!.close();
    conn = await connect({
      uplinks: [linkB!.url],
      address: cred.address,
      credential: cred,
      dial: { connectTimeoutMs: 4000, controlTimeoutMs: 4000 },
    });
    assert.equal(conn.state, 'connected', 'reconnected by token');
    const reply = await conn.request({ echo: 'reconnected' });
    assert.deepEqual(reply, { echo: 'reconnected' });
  });

  await stage('7. revoke the device -> the reconnect fails auth: typed DeviceRevokedError + terminal "revoked", no endless retry', async () => {
    const cred = conn!.credential!;
    conn!.close();
    assert.equal(host!.revoke(cred.keyId), true, 'token revoked');
    // autoReconnect is ON (default): a revoked device used to retry forever. Now the
    // host's typed refusal makes the client STOP — connect() rejects with a
    // DeviceRevokedError and the state surfaces the terminal 'revoked'.
    const seen: ConnState[] = [];
    await assert.rejects(
      connect({
        uplinks: [linkB!.url],
        address: cred.address,
        credential: cred,
        onState: (st) => seen.push(st),
        dial: { connectTimeoutMs: 4000, controlTimeoutMs: 4000 },
      }),
      (e: unknown) => e instanceof DeviceRevokedError,
      'a revoked credential is refused with a typed DeviceRevokedError',
    );
    assert.ok(seen.includes('revoked'), 'the client surfaced the terminal "revoked" state');
  });

  // cleanup
  conn?.close();
  await host?.stop();
  linkA?.kill();
  linkB?.kill();

  await sleep(150);
  console.log(`\n${failures === 0 ? 'ALL STAGES PASSED' : `${failures} STAGE(S) FAILED`}  (total ${Date.now() - t0}ms)`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.log(`FATAL  ${e instanceof Error ? e.stack : e}`);
  process.exit(1);
});
