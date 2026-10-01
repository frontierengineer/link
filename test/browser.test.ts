// The client in a real browser: bundled for the browser with esbuild (which fails on any
// Node import), loaded into headless Chromium from a page on its own origin, where a
// surface pairs with a Node primary through the real relay and exchanges messages with it
// and with a Node worker, using the browser's own WebSocket and crypto.

import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { build } from 'esbuild';
import { chromium, type Browser, type Page } from 'playwright';
import { relayBinary } from './support/relay.js';
import { bytesOf, inbox, startNet, textOf } from './support/net.js';

let bundle: string;
let browser: Browser;
let site: Server;
let origin: string;

before(async () => {
  relayBinary();
  const out = await build({
    stdin: {
      contents: "import * as Link from '@frontierengineer/link-client'; globalThis.Link = Link;",
      resolveDir: import.meta.dirname,
      loader: 'js',
    },
    bundle: true,
    platform: 'browser',
    format: 'iife',
    target: 'es2022',
    write: false,
    logLevel: 'silent',
  });
  bundle = out.outputFiles[0]!.text;
  site = createServer((req, res) => {
    if (req.url === '/link.js') {
      res.writeHead(200, { 'content-type': 'text/javascript' });
      res.end(bundle);
    } else {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<!doctype html><title>link</title><script src="/link.js"></script>');
    }
  });
  await new Promise<void>((r) => site.listen(0, '127.0.0.1', r));
  origin = `http://127.0.0.1:${(site.address() as { port: number }).port}`;
  browser = await chromium.launch();
});

after(async () => {
  await browser?.close();
  await new Promise((r) => site?.close(r));
});

async function openPage(): Promise<Page> {
  const page = await browser.newPage();
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto(origin);
  await page.waitForFunction(() => typeof (globalThis as { Link?: unknown }).Link === 'object');
  assert.deepEqual(errors, []);
  return page;
}

test('a surface in Chromium pairs with a Node primary through the relay and talks to it', async () => {
  const net = await startNet();
  const page = await openPage();
  try {
    const { primary } = net;
    assert.equal(await page.evaluate(() => typeof WebSocket === 'function' && typeof process === 'undefined'), true);

    // Pair in the browser, with the browser's WebSocket, then connect as a member.
    const code = primary.openPairingCode('surface');
    const paired = await page.evaluate(async (link) => {
      const L = (globalThis as any).Link;
      const identity = L.createIdentity();
      const { roster } = await L.pair({ link, identity });
      const member = await L.Member.connect({ identity, roster, timing: { backoffInitialMs: 20, backoffMaxMs: 200 } });
      const g = globalThis as any;
      g.member = member;
      g.received = [];
      g.versions = [];
      member.onMessage((m: { from: string; bytes: Uint8Array }) => g.received.push({ from: m.from, bytes: Array.from(m.bytes.length > 64 ? m.bytes.subarray(0, 0) : m.bytes), length: m.bytes.length, sum: m.bytes.reduce((a, b) => (a + b) % 65521, 0) }));
      member.on('roster', (r: { version: number }) => g.versions.push(r.version));
      return { id: member.id, version: member.roster.version, state: member.state };
    }, code.link);
    assert.equal(paired.version, 2);
    assert.equal(paired.state, 'connected');
    assert.equal(primary.roster.members.find((m) => m.id === paired.id)?.kind, 'surface');

    // Browser to Node, small and several MiB (fragments and credit in the browser).
    const pIn = inbox(primary);
    await page.evaluate(async (to) => {
      const m = (globalThis as any).member;
      await m.send(to, new TextEncoder().encode('hello from chromium'));
      const big = new Uint8Array(3 * 1024 * 1024);
      for (let i = 0; i < big.length; i++) big[i] = (i * 7 + 1) & 0xff;
      await m.send(to, big);
    }, primary.id);
    const [hello, big] = await pIn.next(2, 30_000);
    assert.equal(hello!.from, paired.id);
    assert.equal(textOf(hello!.bytes), 'hello from chromium');
    assert.equal(big!.bytes.length, 3 * 1024 * 1024);
    assert.ok(big!.bytes.every((b, i) => b === ((i * 7 + 1) & 0xff)));

    // Node to browser, small and large.
    await primary.send(paired.id, bytesOf('hello from node'));
    const large = new Uint8Array(2 * 1024 * 1024 + 5).fill(3);
    await primary.send(paired.id, large);
    await page.waitForFunction(() => (globalThis as any).received.length >= 2, null, { timeout: 30_000 });
    const got = await page.evaluate(() => (globalThis as any).received as { from: string; bytes: number[]; length: number; sum: number }[]);
    assert.equal(got[0]!.from, primary.id);
    assert.equal(new TextDecoder().decode(Uint8Array.from(got[0]!.bytes)), 'hello from node');
    assert.equal(got[1]!.length, large.length);
    assert.equal(got[1]!.sum, (3 * large.length) % 65521);

    // A Node worker joins: the browser receives the new roster, and they talk both ways.
    const worker = await net.add('worker');
    assert.deepEqual(await page.evaluate(() => (globalThis as any).versions), [3]);
    const wIn = inbox(worker);
    await page.evaluate((to) => (globalThis as any).member.send(to, new TextEncoder().encode('surface to worker')), worker.id);
    assert.equal(textOf((await wIn.next())[0]!.bytes), 'surface to worker');
    await worker.send(paired.id, bytesOf('worker to surface'));
    await page.waitForFunction(() => (globalThis as any).received.length >= 3);
    const third = await page.evaluate(() => (globalThis as any).received[2]);
    assert.equal(third.from, worker.id);
    assert.equal(new TextDecoder().decode(Uint8Array.from(third.bytes)), 'worker to surface');

    // Revoked from Node: the browser's member ends revoked (closed 4008 by the relay).
    primary.revoke(paired.id);
    await page.waitForFunction(() => (globalThis as any).member.state === 'revoked');
  } finally {
    await page.evaluate(() => (globalThis as any).member?.close()).catch(() => undefined);
    await page.close();
    await net.close();
  }
});
