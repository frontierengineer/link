// THE SOCKET IS A DEPENDENCY, AND THIS IS WHAT THAT BOUGHT.
//
// This client used to `import { WebSocket } from 'ws'` and construct its own.
// That decided the transport for every caller, and it decided a Node-only byte
// type with it: frames were converted to `Buffer`, close reasons were read with
// `Buffer.prototype.toString()`. A browser could only run this package by lying
// to its bundler — aliasing the `ws` specifier at a hand-written stand-in that
// reimplemented ws's event API over the realm's own WebSocket, and installing a
// `Buffer` shim on the global object so `toString()` meant text.
//
// So the thing to hold still is not that `ws` still works — `test/e2e.selftest.ts`
// dials two real relays and proves that. It is that a socket which is NOT ws
// works: one that delivers ArrayBuffers rather than Buffers, hands a close
// reason as bytes, and is already open when it is handed over. Each of those
// was a silent wrong answer before, and the third is a real shape (a pooled or
// pre-warmed socket) that `await`ing the factory made reachable.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { LinkSocket, type LinkWebSocket, type OpenSocket, establish } from '../src/linkClient.js';
import { utf8 } from '../src/bytes.js';

const OPEN = 1;

/** A socket that is not `ws`: it speaks ArrayBuffer, as every browser does. */
class BrowserShapedSocket implements LinkWebSocket {
  readyState = OPEN;
  readonly sent: (string | Uint8Array)[] = [];
  closedWith: { code: number | undefined; reason: string | undefined } | undefined;
  terminated = false;
  private readonly handlers = new Map<string, ((...a: never[]) => void)[]>();

  send(data: string | Uint8Array): void { this.sent.push(data); }
  close(code?: number, reason?: string): void { this.closedWith = { code, reason }; }
  terminate(): void { this.terminated = true; }

  on(event: string, fn: (...a: never[]) => void): this {
    this.handlers.set(event, [...(this.handlers.get(event) ?? []), fn]);
    return this;
  }

  once(event: string, fn: (...a: never[]) => void): this { return this.on(event, fn); }

  emit(event: string, ...args: unknown[]): void {
    for (const fn of this.handlers.get(event) ?? []) (fn as (...a: unknown[]) => void)(...args);
  }

  /** A binary frame the way a browser delivers one. */
  deliverBinary(bytes: Uint8Array): void {
    const copy = new ArrayBuffer(bytes.length);
    new Uint8Array(copy).set(bytes);
    this.emit('message', copy, true);
  }

  deliverText(text: string): void { this.emit('message', utf8(text), false); }
}

test('a control message arrives through a socket that delivers ArrayBuffers', async () => {
  const ws = new BrowserShapedSocket();
  const sock = new LinkSocket(ws);
  ws.deliverText(JSON.stringify({ type: 'found', linkId: 'abc' }));
  const msg = await sock.waitControl(1_000);
  assert.equal(msg.type, 'found');
  assert.equal(msg.linkId, 'abc');
});

test('a relayed frame comes back as the exact bytes, from an ArrayBuffer', async () => {
  const ws = new BrowserShapedSocket();
  const sock = new LinkSocket(ws, { piping: true });
  const payload = Uint8Array.of(0x00, 0xff, 0x7f, 0x80, 0x41);
  ws.deliverBinary(payload);
  assert.deepEqual(await sock.recv(1_000), payload);
});

test('the splice flips on `relaying`, and what follows is payload rather than JSON', async () => {
  const ws = new BrowserShapedSocket();
  const sock = new LinkSocket(ws);
  ws.deliverText(JSON.stringify({ type: 'relaying' }));
  assert.equal((await sock.waitControl(1_000)).type, 'relaying');
  // A frame whose bytes happen to be valid JSON must NOT be reparsed as control.
  const looksLikeJson = utf8('{"type":"found"}');
  ws.deliverBinary(looksLikeJson);
  assert.deepEqual(await sock.recv(1_000), looksLikeJson);
});

test('a close reason arrives as text, not as comma-separated byte values', async () => {
  const ws = new BrowserShapedSocket();
  const sock = new LinkSocket(ws);
  ws.emit('close', 1006, utf8('relay went away'));
  assert.deepEqual(await sock.closed, { code: 1006, reason: 'relay went away' });
});

test('a close with no reason keeps the code and invents no text', async () => {
  const ws = new BrowserShapedSocket();
  const sock = new LinkSocket(ws);
  ws.emit('close', 1000, new Uint8Array(0));
  assert.deepEqual(await sock.closed, { code: 1000 });
});

test('openSocket is what dials: `ws` is never reached when a factory is given', async () => {
  const dialled: string[] = [];
  const openSocket: OpenSocket = (url, opts) => {
    assert.equal(opts.maxPayload, 16 * 1024 * 1024, 'the relay frame cap is passed to the factory');
    dialled.push(url);
    return new BrowserShapedSocket();
  };
  // Both uplinks answer nothing, so every attempt fails at `resolve` — which is
  // after the dial, which is the part under test.
  await assert.rejects(
    establish(['wss://one.invalid', 'wss://two.invalid'], { address: 'addr' }, async () => 'never', {
      openSocket,
      controlTimeoutMs: 20,
    }),
  );
  assert.deepEqual(dialled, ['wss://one.invalid', 'wss://two.invalid'], 'each uplink is tried in order');
});

test('a factory may answer with a promise, and may hand back an already-open socket', async () => {
  const openSocket: OpenSocket = async () => new BrowserShapedSocket();
  const dialledInOrder: string[] = [];
  await assert.rejects(
    establish(['wss://only.invalid'], { address: 'addr' }, async () => 'never', {
      openSocket: (url, opts) => { dialledInOrder.push(url); return openSocket(url, opts); },
      controlTimeoutMs: 20,
    }),
  );
  // Reaching `resolve` at all proves `once('open')` was not waited on for a
  // socket that was open before it was handed over.
  assert.deepEqual(dialledInOrder, ['wss://only.invalid']);
});
