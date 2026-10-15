// The relay connection's state machine (sections 4.1, 10, 11) against a
// scripted socket: the register message, backoff, its reset, and 4008.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { b64u, fromB64u } from '../src/bytes.js';
import { ed25519Verify } from '../src/crypto.js';
import { identityFromSeed } from '../src/identity.js';
import { RelayConnection, type RelayState } from '../src/relay.js';
import { createNetwork } from '../src/roster.js';
import { registerSigningBytes } from '../src/signed.js';
import type { WebSocketLike } from '../src/socket.js';

class ScriptedSocket implements WebSocketLike {
  static all: ScriptedSocket[] = [];
  binaryType = 'blob';
  readyState = 0;
  bufferedAmount = 0;
  sent: (string | Uint8Array)[] = [];
  onopen: ((ev: unknown) => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onclose: ((ev: { code: number; reason: string }) => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;
  readonly at = Date.now();
  constructor(readonly url: string) {
    ScriptedSocket.all.push(this);
  }
  open(): void {
    this.readyState = 1;
    this.onopen?.({});
  }
  text(msg: unknown): void {
    this.onmessage?.({ data: JSON.stringify(msg) });
  }
  send(data: string | Uint8Array): void {
    this.sent.push(data);
  }
  close(): void {
    this.serverClose(1000);
  }
  serverClose(code: number): void {
    this.readyState = 3;
    this.onclose?.({ code, reason: '' });
  }
}

const id = identityFromSeed(new Uint8Array(32).fill(4));
const roster = createNetwork({ identity: id, relay: 'wss://Relay.Example:443/v1', now: 1 });

function connection(opts: Partial<ConstructorParameters<typeof RelayConnection>[0]> = {}) {
  ScriptedSocket.all = [];
  const rc = new RelayConnection({
    url: roster.relay,
    identity: id,
    roster: () => roster,
    WebSocket: ScriptedSocket,
    now: () => 1790000000000,
    backoffInitialMs: 20,
    backoffMaxMs: 100,
    ...opts,
  });
  const states: RelayState[] = [];
  rc.on('state', (s) => states.push(s));
  return { rc, states };
}

const tick = (ms: number) => new Promise((r) => setTimeout(r, ms));

test('hello -> signed register -> registered; nothing else is sent before registered', async () => {
  const { rc, states } = connection();
  rc.start();
  const ws = ScriptedSocket.all[0]!;
  assert.equal(ws.url, 'wss://Relay.Example:443/v1');
  assert.equal(ws.binaryType, 'arraybuffer');
  ws.open();
  assert.equal(rc.sendBinary(new Uint8Array(18)), false);
  assert.equal(rc.sendControl({ type: 'usage', id: 'x' }), false);
  const challenge = new Uint8Array(32).fill(7);
  ws.text({ type: 'hello', version: 1, challenge: b64u(challenge) });
  assert.equal(ws.sent.length, 1);
  const reg = JSON.parse(ws.sent[0] as string);
  assert.deepEqual(Object.keys(reg).sort(), ['ed25519', 'network', 'node', 'roster', 'sig', 'ts', 'type']);
  assert.equal(reg.type, 'register');
  assert.equal(reg.node, id.id);
  assert.equal(reg.network, id.id);
  assert.equal(reg.ts, 1790000000000);
  assert.deepEqual(reg.roster, roster);
  const signed = registerSigningBytes({ network: id.id, node: id.id, challenge, ts: reg.ts, origin: 'relay.example' });
  assert.ok(ed25519Verify(fromB64u(reg.sig), signed, id.ed25519.pub));
  ws.text({ type: 'registered', node: id.id, rosterVersion: 1 });
  assert.equal(rc.state, 'registered');
  assert.equal(rc.sendBinary(new Uint8Array(18)), true);
  assert.deepEqual(states, ['connecting', 'registered']);
  rc.close();
  assert.equal(rc.state, 'closed');
});

test('a relay speaking another version is dropped and retried', async () => {
  const { rc } = connection();
  rc.start();
  const ws = ScriptedSocket.all[0]!;
  ws.open();
  ws.text({ type: 'hello', version: 2, challenge: b64u(new Uint8Array(32)) });
  assert.equal(ws.sent.length, 0);
  await tick(40);
  assert.equal(ScriptedSocket.all.length, 2);
  rc.close();
});

test('backoff doubles from the initial delay to the cap, and resets after registered', async () => {
  const { rc } = connection();
  rc.start();
  for (let i = 0; i < 6; i++) {
    const ws = ScriptedSocket.all[i]!;
    ws.serverClose(1006);
    await new Promise<void>(function wait(resolve) {
      if (ScriptedSocket.all.length > i + 1) resolve();
      else setTimeout(() => wait(resolve), 2);
    });
  }
  const gaps = ScriptedSocket.all.slice(1).map((s, i) => s.at - ScriptedSocket.all[i]!.at);
  // 20, 40, 80, 100, 100, 100 (timer slack allowed upwards only)
  const expected = [20, 40, 80, 100, 100, 100];
  gaps.forEach((g, i) => {
    assert.ok(g >= expected[i]! - 2, `gap ${i} = ${g}, expected about ${expected[i]}`);
    assert.ok(g < expected[i]! + 60, `gap ${i} = ${g}, expected about ${expected[i]}`);
  });
  // Register on the latest socket; the next failure waits the initial delay again.
  const ws = ScriptedSocket.all.at(-1)!;
  ws.open();
  ws.text({ type: 'hello', version: 1, challenge: b64u(new Uint8Array(32)) });
  ws.text({ type: 'registered', node: id.id, rosterVersion: 1 });
  const n = ScriptedSocket.all.length;
  ws.serverClose(1001);
  await tick(45);
  assert.equal(ScriptedSocket.all.length, n + 1);
  rc.close();
});

test('4008 is terminal: no reconnect, state revoked', async () => {
  const { rc, states } = connection();
  rc.start();
  ScriptedSocket.all[0]!.serverClose(4008);
  await tick(80);
  assert.equal(ScriptedSocket.all.length, 1);
  assert.equal(rc.state, 'revoked');
  assert.deepEqual(states, ['connecting', 'revoked']);
  rc.start();
  assert.equal(ScriptedSocket.all.length, 1);
});

test('4009 emits moved, asks for the new location, and dials it', async () => {
  const { rc } = connection({ resolveRelay: async () => 'wss://other.example/v1' });
  const moved: string[] = [];
  rc.on('moved', (m) => moved.push(m.network));
  rc.start();
  ScriptedSocket.all[0]!.serverClose(4009);
  await tick(60);
  assert.deepEqual(moved, [id.id]);
  assert.equal(ScriptedSocket.all[1]!.url, 'wss://other.example/v1');
  assert.equal(rc.relayUrl, 'wss://other.example/v1');
  rc.close();
});

test('4005 is terminal: state replaced, no reconnect', async () => {
  const { rc, states } = connection();
  rc.start();
  ScriptedSocket.all[0]!.serverClose(4005);
  await tick(80);
  assert.equal(ScriptedSocket.all.length, 1);
  assert.deepEqual(states, ['connecting', 'replaced']);
  assert.equal(rc.terminal, true);
});

test('other close codes (1001, 4007, 1000) keep retrying', async () => {
  const { rc } = connection();
  rc.start();
  for (const [i, code] of [1001, 4007, 1000].entries()) {
    ScriptedSocket.all[i]!.serverClose(code);
    await tick(110);
  }
  assert.equal(ScriptedSocket.all.length, 4);
  rc.close();
});

test('a roster in registered is surfaced before the state turns registered', async () => {
  const { rc } = connection();
  const order: string[] = [];
  rc.on('registered', (m) => order.push(`registered:${(m.roster as { version: number }).version}`));
  rc.on('state', (st) => order.push(st));
  rc.start();
  const ws = ScriptedSocket.all[0]!;
  ws.open();
  ws.text({ type: 'hello', version: 1, challenge: b64u(new Uint8Array(32)) });
  ws.text({ type: 'registered', node: id.id, rosterVersion: 5, roster: { ...roster, version: 5 } });
  assert.deepEqual(order, ['connecting', 'registered:5', 'registered']);
  rc.close();
});
