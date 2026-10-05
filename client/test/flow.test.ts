// Flow control without a relay: real SessionManagers wired through an in-memory
// socket whose back-pressure the test controls. Credit batching, the two send
// lanes (control overtakes queued data and still decrypts in nonce order), the
// per-session pace, and the WebSocketStream adapter.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createIdentity, createNetwork, memberFromIdentity, signRoster, type Identity, type Roster } from '../src/index.js';
import { FrameType, type SessionMessage } from '../src/frames.js';
import { CREDIT_BATCH_BYTES, DEFAULT_SESSION_TIMING, INITIAL_CREDIT, PACE_FLOOR_BYTES, PACE_MIN_FRAGMENT, SessionManager } from '../src/sessions.js';
import { Channel, SOCKET_LOW_WATER, streamSocket, type WebSocketStreamLike } from '../src/socket.js';

interface Node {
  id: string;
  mgr: SessionManager;
  /** Frames handed to the socket, in order, by type. */
  wire: { type: number; to: string; size: number }[];
  /** Messages delivered, with their release; `auto` releases at once. */
  inbox: { from: string; bytes: Uint8Array; release: () => void }[];
  auto: boolean;
  /** Bytes "in the socket": the test drains it. */
  buffered: number;
  drainWaiters: (() => void)[];
  control: SessionMessage[];
}

/** A network of nodes whose frames cross a microtask hop, in order. */
function mesh(count: number): { nodes: Node[]; drain(n: Node): void } {
  const ids: Identity[] = Array.from({ length: count }, () => createIdentity());
  const unsigned = createNetwork({ identity: ids[0]!, relay: 'wss://relay.test/v1' });
  const roster: Roster = signRoster(
    {
      network: unsigned.network,
      version: 2,
      issuedAt: unsigned.issuedAt,
      relay: unsigned.relay,
      primary: unsigned.primary,
      members: ids.map((id, i) => memberFromIdentity(id, i === 0 ? 'primary' : 'worker')).sort((a, b) => (a.id < b.id ? -1 : 1)),
    },
    ids[0]!,
  );
  const nodes: Node[] = [];
  const byId = new Map<string, Node>();
  for (const identity of ids) {
    const node: Node = { id: identity.id, mgr: undefined as never, wire: [], inbox: [], auto: true, buffered: 0, drainWaiters: [], control: [] };
    node.mgr = new SessionManager({
      identity,
      roster: () => roster,
      now: () => Date.now(),
      creditWindow: INITIAL_CREDIT,
      timing: DEFAULT_SESSION_TIMING,
      sendFrame: (type, peer, body) => {
        node.wire.push({ type, to: peer, size: 18 + body.length });
        node.buffered += 18 + body.length;
        const to = byId.get(peer)!;
        queueMicrotask(() => to.mgr.handleFrame({ type, peer: new Uint8Array(16), body }, node.id));
        return true;
      },
      writable: () => node.buffered <= SOCKET_LOW_WATER,
      whenWritable: (f) => (node.buffered <= SOCKET_LOW_WATER ? f() : node.drainWaiters.push(f)),
      bufferedAmount: () => node.buffered,
      note: () => undefined,
      deliver: (from, bytes, release) => {
        if (node.auto) release();
        node.inbox.push({ from, bytes, release });
      },
      control: (_from, msg) => node.control.push(msg),
      peerVersion: () => undefined,
    });
    nodes.push(node);
    byId.set(node.id, node);
  }
  return {
    nodes,
    drain(n) {
      n.buffered = 0;
      for (const f of n.drainWaiters.splice(0)) f();
    },
  };
}

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));

async function until(cond: () => boolean, what: string, ms = 5000): Promise<void> {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await tick(5);
  }
}

test('credit is batched: a bulk stream of small messages returns well under one credit per ten messages', async () => {
  const { nodes, drain } = mesh(2);
  const [a, b] = nodes as [Node, Node];
  const keepDrained = setInterval(() => drain(a), 1);
  try {
    for (let i = 0; i < 2000; i++) await a.mgr.send(b.id, new Uint8Array(200).fill(i & 0xff));
    await until(() => b.inbox.length === 2000, 'all messages');
    const credits = b.wire.filter((f) => f.type === FrameType.Control).length;
    assert.ok(credits / 2000 < 0.1, `${credits} credits for 2000 messages`);
    assert.equal(b.mgr.stats.creditsSent, credits);
    assert.equal(b.mgr.stats.messagesReceived, 2000);
    // What is still owed below the batch size comes back within the delay.
    await until(() => a.mgr.sessionInfo(b.id)[0]!.sendCredit === INITIAL_CREDIT, 'every byte credited back', 1000);
    assert.equal(a.mgr.sessionInfo(b.id)[0]!.inflight, 0);
  } finally {
    clearInterval(keepDrained);
    for (const n of nodes) n.mgr.close();
  }
});

test('credit: a sender held up by a receiver that takes messages one at a time is never stalled for good', async () => {
  const { nodes, drain } = mesh(2);
  const [a, b] = nodes as [Node, Node];
  b.auto = false;
  const keepDrained = setInterval(() => drain(a), 1);
  // The receiver takes one 1 KiB message every 2 ms: owed credit stays under the batch size
  // for long stretches, and the 250 ms timer returns it.
  let taken = 0;
  const taker = setInterval(() => {
    const m = b.inbox[taken];
    if (m) {
      m.release();
      taken++;
    }
  }, 2);
  try {
    const n = 400;
    const started = Date.now();
    for (let i = 0; i < n; i++) await a.mgr.send(b.id, new Uint8Array(1024));
    assert.ok(Date.now() - started < 8000);
    await until(() => b.inbox.length === n, 'every message');
  } finally {
    clearInterval(keepDrained);
    clearInterval(taker);
    for (const n of nodes) n.mgr.close();
  }
});

test('lanes: control overtakes data waiting on a backed-up socket, and both still decrypt in order', async () => {
  const { nodes, drain } = mesh(2);
  const [a, b] = nodes as [Node, Node];
  try {
    await a.mgr.send(b.id, new Uint8Array(10)); // a session
    drain(a);
    // Back the socket up: data waits in the gate, unencrypted.
    a.buffered = SOCKET_LOW_WATER + 1;
    let sent = false;
    const big = a.mgr.send(b.id, new Uint8Array(100_000).fill(7)).then(() => (sent = true));
    await tick(20);
    assert.equal(sent, false);
    const before = a.wire.length;
    await a.mgr.sendControl(b.id, { type: 'roster-request' });
    assert.equal(a.wire.length, before + 1, 'control went at once');
    assert.equal(a.wire.at(-1)!.type, FrameType.Control);
    const keepDrained = setInterval(() => drain(a), 1);
    await big.finally(() => clearInterval(keepDrained));
    await until(() => b.inbox.length === 2, 'the big message');
    assert.equal(b.inbox[1]!.bytes.length, 100_000);
    assert.deepEqual(b.control, [{ type: 'roster-request' }]);
    // Nothing failed to decrypt: the session that carried all of it is still the one in use.
    assert.equal(b.mgr.sessionInfo(a.id).length, 1);
    assert.ok(a.wire.filter((f) => f.type === FrameType.Data).every((f) => f.size <= 18 + 4 + 65535));
  } finally {
    for (const n of nodes) n.mgr.close();
  }
});

test('lanes: data waits while the socket holds more than its low-water mark, and resumes as it drains', async () => {
  const { nodes, drain } = mesh(2);
  const [a, b] = nodes as [Node, Node];
  try {
    const done = a.mgr.send(b.id, new Uint8Array(1_000_000));
    // Without draining, at most the low-water mark plus one fragment reaches the socket.
    await tick(50);
    assert.ok(a.buffered <= SOCKET_LOW_WATER + 65535 + 4 + 18 + 1024, `${a.buffered} bytes in the socket`);
    for (let i = 0; i < 200 && b.inbox.length === 0; i++) {
      drain(a);
      await tick(2);
    }
    await done;
    await until(() => b.inbox.length === 1, 'the message');
  } finally {
    for (const n of nodes) n.mgr.close();
  }
});

test('pace: a receiver that takes nothing holds its own session to the pace, and another peer is not held up', async () => {
  const { nodes, drain } = mesh(3);
  const [a, slow, fast] = nodes as [Node, Node, Node];
  slow.auto = false;
  const keepDrained = setInterval(() => drain(a), 1);
  try {
    // The receiver holds the first message at once and credits nothing, so the pace stays at
    // its floor: the second message's first fragment is cut to the room left under it, which
    // is less than the smallest fragment, so it is that smallest fragment.
    for (let i = 0; i < 4; i++) void a.mgr.send(slow.id, new Uint8Array(60_000)).catch(() => undefined);
    await tick(100);
    const toSlow = a.mgr.sessionInfo(slow.id)[0]!;
    // The second message crossed the floor; nothing more goes, far under the 1 MiB credit.
    assert.equal(toSlow.inflight, 60_000 + PACE_MIN_FRAGMENT);
    assert.equal(slow.inbox.length, 1);
    for (let i = 0; i < 50; i++) await a.mgr.send(fast.id, new Uint8Array(10_000));
    await until(() => fast.inbox.length === 50, 'the fast peer');
    // The slow receiver takes what it holds: everything else follows.
    const taker = setInterval(() => {
      for (const m of slow.inbox) m.release();
    }, 5);
    await until(() => slow.inbox.length === 4, 'the slow peer, once it reads', 10_000);
    clearInterval(taker);
  } finally {
    clearInterval(keepDrained);
    for (const n of nodes) n.mgr.close();
  }
});

test('a session that ends fails the fragments waiting in the gate', async () => {
  const { nodes } = mesh(2);
  const [a, b] = nodes as [Node, Node];
  try {
    await a.mgr.send(b.id, new Uint8Array(1));
    a.buffered = SOCKET_LOW_WATER + 1;
    const p = a.mgr.send(b.id, new Uint8Array(10));
    await tick(10);
    a.mgr.close();
    await assert.rejects(p, { code: 'closed' });
  } finally {
    for (const n of nodes) n.mgr.close();
  }
});

// ── WebSocketStream through the Channel seam ──

/** A WebSocketStream double: `server` pushes to the client; the client's writes complete when `release` is called. */
function fakeStream(opts: { open: boolean }) {
  const written: unknown[] = [];
  const pendingWrites: (() => void)[] = [];
  let push!: (v: unknown) => void;
  let closedResolve!: (v: { closeCode?: number; reason?: string }) => void;
  let closedReject!: (e: unknown) => void;
  let openedReject!: (e: unknown) => void;
  let openedResolve!: (v: { readable: ReadableStream<unknown>; writable: WritableStream<unknown> }) => void;
  const closeCalls: { closeCode?: number; reason?: string }[] = [];
  class FakeWSS implements WebSocketStreamLike {
    opened = new Promise<{ readable: ReadableStream<unknown>; writable: WritableStream<unknown> }>((res, rej) => {
      openedResolve = res;
      openedReject = rej;
    });
    closed = new Promise<{ closeCode?: number; reason?: string }>((res, rej) => {
      closedResolve = res;
      closedReject = rej;
    });
    constructor(_url: string) {
      const readable = new ReadableStream<unknown>({ start: (c) => void (push = (v) => c.enqueue(v)) });
      const writable = new WritableStream<unknown>(
        { write: (chunk) => new Promise<void>((res) => { written.push(chunk); pendingWrites.push(res); }) },
        { highWaterMark: 64 },
      );
      this.opened.catch(() => undefined);
      this.closed.catch(() => undefined);
      queueMicrotask(() => (opts.open ? openedResolve({ readable, writable }) : undefined));
    }
    close(info?: { closeCode?: number; reason?: string }): void {
      closeCalls.push(info ?? {});
      closedResolve({ closeCode: info?.closeCode ?? 1005, reason: info?.reason ?? '' });
    }
  }
  return {
    FakeWSS,
    written,
    closeCalls,
    push: (v: unknown) => push(v),
    release: () => {
      for (const r of pendingWrites.splice(0)) r();
    },
    fail: () => {
      openedReject(new Error('refused'));
      closedReject(Object.assign(new Error('refused'), { closeCode: 0 }));
    },
    serverClose: (code: number, reason: string) => closedResolve({ closeCode: code, reason }),
  };
}

test('WebSocketStream: opens, carries text and binary both ways, reports back-pressure and the close code', async () => {
  const f = fakeStream({ open: true });
  const got: unknown[] = [];
  let closed: [number, string] | undefined;
  let opened = false;
  const ch = new Channel('wss://x/v1', streamSocket(f.FakeWSS), {
    onOpen: () => (opened = true),
    onControl: (m, n) => got.push([m, n]),
    onBinary: (b) => got.push(b),
    onClose: (code, reason) => (closed = [code, reason]),
  });
  await until(() => opened, 'open');
  f.push(JSON.stringify({ type: 'hello', x: 'é' }));
  f.push(new Uint8Array([1, 2, 3]).buffer);
  await until(() => got.length === 2, 'two messages');
  assert.deepEqual(got[0], [{ type: 'hello', x: 'é' }, 25]);
  assert.deepEqual(got[1], new Uint8Array([1, 2, 3]));

  assert.equal(ch.sendControl({ type: 'usage', id: 'a' }), 25);
  assert.ok(ch.sendBinary(new Uint8Array(SOCKET_LOW_WATER)));
  assert.equal(ch.bufferedAmount, 25 + SOCKET_LOW_WATER);
  assert.equal(ch.writable, false);
  let woke = false;
  ch.whenWritable(() => (woke = true));
  await tick(30);
  assert.equal(woke, false, 'no polling: it waits for writes to complete');
  f.release();
  await until(() => woke, 'drain');
  // The stream hands its sink one chunk at a time: the second completes after the first.
  await until(() => {
    f.release();
    return ch.bufferedAmount === 0;
  }, 'every write to complete');
  assert.equal(f.written.length, 2);

  f.serverClose(4008, 'not a member');
  await until(() => closed !== undefined, 'close');
  assert.deepEqual(closed, [4008, 'not a member']);
});

test('WebSocketStream: one that never opens reports 1006, and a local close reports its own code', async () => {
  const f = fakeStream({ open: false });
  let closed: number | undefined;
  new Channel('wss://x/v1', streamSocket(f.FakeWSS), { onControl: () => undefined, onBinary: () => undefined, onClose: (c) => (closed = c) });
  f.fail();
  await until(() => closed !== undefined, 'close');
  assert.equal(closed, 1006);

  const g = fakeStream({ open: true });
  const codes: number[] = [];
  let opened = false;
  const ch = new Channel('wss://x/v1', streamSocket(g.FakeWSS), { onOpen: () => (opened = true), onControl: () => undefined, onBinary: () => undefined, onClose: (c) => codes.push(c) });
  await until(() => opened, 'open');
  ch.close(1000, 'bye');
  await tick(10);
  assert.deepEqual(codes, [1000], 'reported once');
  assert.deepEqual(g.closeCalls, [{ closeCode: 1000, reason: 'bye' }]);
});
