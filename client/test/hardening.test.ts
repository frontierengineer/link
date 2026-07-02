// Hardening tests for the adversarial-review fixes:
//   • HIGH  — pairing-lockout TOCTOU: a reserve() that caps concurrent attempts.
//   • HIGH  — dial-back cap: an untrusted Link can't drive unbounded outbound
//             sockets via a flood of {type:'relay'} control messages.
//   • LOW   — session idle reaper: a silent session is torn down; periodic
//             traffic keeps it alive.
// Includes the reviewers' repros, which must now FAIL to get through.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { WebSocketServer } from 'ws';

import { memoryPipePair, registerSignerFromStatic } from '../src/index.js';
import { HostUplinks } from '../src/linkClient.js';
import { CodeLockout } from '../src/pairing.js';
import { SecureSession, transportFromSecret } from '../src/secureChannel.js';
import { randomBytes } from '../src/bytes.js';

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

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

// ── HIGH: lockout reserve() is atomic and caps concurrency ──
//
// reserve() is what makes online guessing the ONLY attack on a pairing code and
// bounds it: a slot is taken ATOMICALLY at attempt entry (no await between read
// and write, so indivisible on a single-threaded runtime), and an in-flight
// reservation counts toward K. That closes the TOCTOU race AND caps concurrent
// unauthenticated SPAKE2 handshakes per code. (The end-to-end pairing path — a
// real client pairing through a real Link relay — is exercised by the e2e
// self-test; here we prove the mechanism directly.)

test('CodeLockout.reserve caps total reservations at K regardless of failures', () => {
  const lock = new CodeLockout(5);
  let granted = 0;
  for (let i = 0; i < 50; i++) if (lock.reserve('code')) granted++;
  assert.equal(granted, 5, 'only K slots are ever reserved');
  lock.refund('code');
  assert.equal(lock.reserve('code'), true, 'a refund frees exactly one slot');
  assert.equal(lock.reserve('code'), false, 'and no more');
});

test('CodeLockout: in-flight reservations count toward K (closes the TOCTOU gap)', () => {
  const lock = new CodeLockout(3);
  assert.ok(lock.reserve('c') && lock.reserve('c') && lock.reserve('c'));
  assert.equal(lock.available('c'), false, 'three in-flight already exhausts the budget');
  assert.equal(lock.reserve('c'), false, 'a 4th concurrent attempt is refused before it can run');
  // Turn the in-flight ones into permanent failures; still locked out.
  lock.recordFailure('c');
  assert.equal(lock.available('c'), false);
});

// ── HIGH: relay dial-back cap ──
//
// A malicious/compromised Link is UNTRUSTED. A single {type:'relay',linkId} it
// sends makes the host open a fresh outbound socket and wait for the splice; with
// no bound it could fire thousands and exhaust FDs/memory. This stands up a fake
// Link that floods relay requests and PARKS every dial-back (never splices), then
// asserts the host opened at most maxConcurrentDialBacks of them.

test('dial-back cap: a flood of relay control messages opens at most N concurrent dial-backs', async () => {
  const CAP = 4;
  const FLOOD = 50;
  const port = await getFreePort();

  let dialBacks = 0; // total 'accept' (dial-back) sockets the host opened
  let concurrent = 0; // currently-open dial-back sockets
  let peakConcurrent = 0;

  const wss = new WebSocketServer({ port, path: '/v1/link' });
  wss.on('connection', (ws) => {
    ws.binaryType = 'nodebuffer';
    ws.on('message', (data: Buffer, isBinary: boolean) => {
      if (isBinary) return;
      let msg: { type?: string; address?: string };
      try {
        msg = JSON.parse(data.toString());
      } catch {
        return;
      }
      if (msg.type === 'register' && typeof msg.address === 'string') {
        // The host's control socket: ack the registration, then blast FLOOD relay
        // dial-back requests at it.
        ws.send(JSON.stringify({ type: 'registered' }));
        for (let i = 0; i < FLOOD; i++) ws.send(JSON.stringify({ type: 'relay', linkId: `lnk-${i}` }));
      } else if (msg.type === 'accept') {
        // A dial-back socket: count it and PARK (never reply 'relaying'), so it
        // holds its in-flight slot for the whole test window.
        dialBacks++;
        concurrent++;
        peakConcurrent = Math.max(peakConcurrent, concurrent);
        ws.on('close', () => {
          concurrent--;
        });
      }
    });
  });
  await new Promise<void>((r) => wss.on('listening', () => r()));

  let introduced = 0;
  const uplinks = new HostUplinks([`ws://127.0.0.1:${port}/v1/link`], {
    address: 'flood-test-address',
    registerSigner: registerSignerFromStatic(randomBytes(32)),
    maxConcurrentDialBacks: CAP,
    connectTimeoutMs: 3000,
    controlTimeoutMs: 3000, // a parked dial-back holds its slot this long (> settle below)
    onIntroduced: () => {
      introduced++;
    },
  });
  await uplinks.start();

  await sleep(800); // let the flood propagate and the (capped) dial-backs connect + park

  // Tear down FIRST (so a failed assertion still cleans up): a parked dial-back is
  // never closed by the host on the splice-wait timeout, and ws's close() does NOT
  // drop already-accepted connections — so terminate them explicitly, else the 4
  // open sockets keep the event loop (and the test runner) alive forever.
  uplinks.stop();
  for (const c of wss.clients) c.terminate();
  await new Promise<void>((r) => wss.close(() => r()));

  assert.ok(dialBacks >= 1, 'the host did dial back (the mechanism is live, not just refusing everything)');
  assert.ok(
    peakConcurrent <= CAP,
    `never more than CAP=${CAP} concurrent dial-backs; peaked at ${peakConcurrent} for ${FLOOD} relay msgs`,
  );
  assert.equal(
    dialBacks,
    CAP,
    `exactly CAP=${CAP} of ${FLOOD} relay requests were dialed (the rest dropped); got ${dialBacks}`,
  );
  assert.equal(introduced, 0, 'no real introduction happened (the fake Link never splices)');
});

// The dial-back slot must be held until the introduced HANDSHAKE resolves — not
// released the instant dialBack hands the pipe off. Otherwise a fast Link recycles
// the slot in ~1 RTT and parks unbounded sockets in the host's handshake-wait
// (ceiling = cap × handshakeTimeout/RTT). This fake Link DOES splice ('relaying'),
// but onIntroduced is PARKED, and we assert only CAP introductions are ever
// concurrently in flight (the rest dropped, not let through).
test('dial-back cap: the slot is HELD through the introduced handshake (not released at hand-off)', async () => {
  const CAP = 4;
  const FLOOD = 50;
  const port = await getFreePort();

  let accepts = 0;
  const wss = new WebSocketServer({ port, path: '/v1/link' });
  wss.on('connection', (ws) => {
    ws.binaryType = 'nodebuffer';
    ws.on('message', (data: Buffer, isBinary: boolean) => {
      if (isBinary) return;
      let msg: { type?: string; address?: string; linkId?: string };
      try {
        msg = JSON.parse(data.toString());
      } catch {
        return;
      }
      if (msg.type === 'register' && typeof msg.address === 'string') {
        ws.send(JSON.stringify({ type: 'registered' }));
        for (let i = 0; i < FLOOD; i++) ws.send(JSON.stringify({ type: 'relay', linkId: `lnk-${i}` }));
      } else if (msg.type === 'accept') {
        // Splice the dial-back live → the host enters onIntroduced (parked below).
        accepts++;
        ws.send(JSON.stringify({ type: 'relaying', linkId: msg.linkId }));
      }
    });
  });
  await new Promise<void>((r) => wss.on('listening', () => r()));

  let introduced = 0;
  let release!: () => void;
  const parked = new Promise<void>((r) => {
    release = r;
  });
  const uplinks = new HostUplinks([`ws://127.0.0.1:${port}/v1/link`], {
    address: 'held-test-address',
    registerSigner: registerSignerFromStatic(randomBytes(32)),
    maxConcurrentDialBacks: CAP,
    connectTimeoutMs: 3000,
    controlTimeoutMs: 3000,
    // Model the host reading the device header + running Noise/SPAKE2: PARK here.
    // The slot must stay held for this whole span, so only CAP ever get this far.
    onIntroduced: () => {
      introduced++;
      return parked;
    },
  });
  await uplinks.start();
  await sleep(1000); // let the flood propagate; the capped dial-backs splice + park

  assert.equal(introduced, CAP, `exactly CAP=${CAP} introductions held in-flight through the handshake; got ${introduced}`);
  assert.equal(accepts, CAP, `only CAP=${CAP} dial-backs spliced; the rest dropped; got ${accepts}`);

  // Cleanup: release the parked handshakes, stop, drop sockets, close the server.
  release();
  uplinks.stop();
  for (const c of wss.clients) c.terminate();
  await new Promise<void>((r) => wss.close(() => r()));
});

// ── LOW: session idle reaper ──

function matchedSessions(idleTimeoutMs: number): { client: SecureSession; host: SecureSession } {
  const [c, h] = memoryPipePair();
  const secret = randomBytes(32);
  const salt = randomBytes(32);
  const client = new SecureSession(c, transportFromSecret(secret, true, salt), { idleTimeoutMs });
  const host = new SecureSession(h, transportFromSecret(secret, false, salt), { idleTimeoutMs, onRequest: (cmd) => cmd });
  return { client, host };
}

test('idle reaper: a silent session is torn down after idleTimeoutMs', async () => {
  const IDLE = 200;
  const { client, host } = matchedSessions(IDLE);
  const t0 = Date.now();
  // The reaper's timer is unref'd (reaping an idle session must never, on its own,
  // keep a host process alive). In this isolated test nothing else holds the event
  // loop open, so a clean runner can drain before the reaper fires and `client.done`
  // would never settle ("Promise resolution is still pending but the event loop has
  // already resolved"). A ref'd keepalive holds the loop open until the reaper
  // resolves `done` — it does NOT change WHEN the reaper fires.
  const keepalive = setInterval(() => {}, 50);
  try {
    const { reason } = await client.done; // resolves when the idle reaper fires
    const elapsed = Date.now() - t0;
    assert.ok(elapsed >= IDLE - 50, `did not close before the idle window (closed at ${elapsed}ms, window ${IDLE}ms)`);
    assert.ok(elapsed < 5000, `closed promptly once idle (closed at ${elapsed}ms)`);
    assert.equal(client.isOpen, false, 'the idle session is closed');
    assert.ok(typeof reason === 'string' && reason.length > 0, 'a close reason was recorded');
  } finally {
    clearInterval(keepalive);
    host.close('cleanup');
  }
});

test('idle reaper: periodic inbound frames keep a session alive past idleTimeoutMs', async () => {
  const IDLE = 300;
  const { client, host } = matchedSessions(IDLE);
  // Round-trip a request every 80ms for ~720ms (> IDLE); each response is an
  // inbound frame that restarts the client's idle window, so it must stay open.
  for (let i = 0; i < 9; i++) {
    const reply = await client.request({ ping: i }, 1000);
    assert.deepEqual(reply, { ping: i }, 'host echoed the sealed request');
    await sleep(80);
  }
  assert.equal(client.isOpen, true, 'still open: periodic traffic resets the idle window');
  assert.equal(host.isOpen, true, 'host side likewise kept alive by the inbound requests');
  client.close('cleanup');
  host.close('cleanup');
});

test('idle reaper: periodic OUTBOUND frames keep a session alive past idleTimeoutMs', async () => {
  const IDLE = 300;
  const { client, host } = matchedSessions(IDLE);
  // The client only SENDS (fire-and-forget events) and the host never replies, so
  // the client RECEIVES nothing for the whole run. Under the old inbound-only reaper
  // this client would be reaped at IDLE; the window must now reset on OUTBOUND
  // frames too (a host streaming an event feed to a quiet client is alive).
  for (let i = 0; i < 9; i++) {
    client.send({ tick: i }); // outbound only — nothing comes back
    await sleep(80); // ~720ms total, well past IDLE=300
  }
  assert.equal(client.isOpen, true, 'still open: OUTBOUND traffic resets the idle window');
  client.close('cleanup');
  host.close('cleanup');
});
