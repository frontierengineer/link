// Choosing a relay from a directory: the shard hash, the directory's shape, and
// picking the closest accepting region.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseDirectory, pickRelay, shardOf, type RelayDirectory } from '../src/index.js';

test('shardOf: the first four bytes of SHA-256 of the id, modulo the shards, in hex', () => {
  assert.equal(shardOf('aaaaaaaaaaaaaaaaaaaaaaaaaa', 256), '49');
  assert.equal(shardOf('7k3q2m8x4v9b1n6c5z0wtrpyhd', 256), '61');
  assert.equal(shardOf('7k3q2m8x4v9b1n6c5z0wtrpyhd', 16), '1');
  assert.equal(shardOf('7k3q2m8x4v9b1n6c5z0wtrpyhd', 4096), 'd61');
  assert.equal(shardOf('x', 1), '0');
  assert.throws(() => shardOf('x', 0), RangeError);
  assert.throws(() => shardOf('x', 0x10001), RangeError);
});

const dir: RelayDirectory = {
  version: 1,
  regions: [
    { id: 'use1', probe: 'https://use1.test/health', relay: 'wss://{shard}.use1.test/v1', shards: 256, accepting: true },
    { id: 'eu1', probe: 'https://eu1.test/health', relay: 'wss://{shard}.eu1.test/v1', shards: 256, accepting: true },
    { id: 'ap1', probe: 'https://ap1.test/health', relay: 'wss://{shard}.ap1.test/v1', shards: 16, accepting: false },
    { id: 'down', probe: 'https://down.test/health', relay: 'wss://down.test/v1', accepting: true },
  ],
};

// A fetch where each probe URL takes its region's delay, in real ms; down.test never answers.
function fakeNet(delays: Record<string, number[]>) {
  const calls: string[] = [];
  const fetch = (async (url: string, init?: { signal?: AbortSignal }) => {
    calls.push(url);
    const host = new URL(url).host;
    if (host === 'down.test') {
      return new Promise((_, reject) => init?.signal?.addEventListener('abort', () => reject(new Error('aborted'))));
    }
    await new Promise((r) => setTimeout(r, delays[host]!.shift()!));
    return new Response('ok');
  }) as unknown as typeof globalThis.fetch;
  return { fetch, calls };
}

test('pickRelay: the accepting region with the fastest probe, and the shard in its template', async () => {
  const net = fakeNet({ 'use1.test': [150, 120, 130], 'eu1.test': [60, 20, 25] });
  const { rttMs, ...got } = await pickRelay({ network: '7k3q2m8x4v9b1n6c5z0wtrpyhd', directory: dir, fetch: net.fetch, timeoutMs: 1000 });
  assert.deepEqual(got, { url: 'wss://61.eu1.test/v1', region: 'eu1', shard: '61' });
  assert.ok(rttMs >= 19 && rttMs < 60, `the fastest probe counts: ${rttMs}`);
  assert.ok(!net.calls.some((u) => u.includes('ap1')), 'a region not accepting is not timed');
});

test('pickRelay: fetches the directory from a URL', async () => {
  const net = fakeNet({ 'use1.test': [5, 5, 5], 'eu1.test': [80, 80, 80] });
  const inner = net.fetch;
  const fetch = (async (url: string, init?: RequestInit) =>
    url === 'https://relays.test/v1/relays' ? new Response(JSON.stringify(dir)) : inner(url, init)) as unknown as typeof globalThis.fetch;
  const got = await pickRelay({ network: 'aaaaaaaaaaaaaaaaaaaaaaaaaa', directory: 'https://relays.test/v1/relays', fetch, timeoutMs: 1000 });
  assert.equal(got.url, 'wss://49.use1.test/v1');
});

test('pickRelay: each region hashes over its own shard count', async () => {
  const grown: RelayDirectory = { ...dir, regions: [{ ...dir.regions[1]!, shards: 4096 }, { ...dir.regions[2]!, accepting: true }] };
  const near = fakeNet({ 'eu1.test': [5, 5, 5], 'ap1.test': [80, 80, 80] });
  assert.equal((await pickRelay({ network: '7k3q2m8x4v9b1n6c5z0wtrpyhd', directory: grown, fetch: near.fetch, timeoutMs: 1000 })).url, 'wss://d61.eu1.test/v1');
  const far = fakeNet({ 'eu1.test': [80, 80, 80], 'ap1.test': [5, 5, 5] });
  assert.equal((await pickRelay({ network: '7k3q2m8x4v9b1n6c5z0wtrpyhd', directory: grown, fetch: far.fetch, timeoutMs: 1000 })).url, 'wss://1.ap1.test/v1');
  const single: RelayDirectory = { version: 1, regions: [{ id: 'one', probe: 'https://use1.test/health', relay: 'wss://relay.test/v1', accepting: true }] };
  const n = fakeNet({ 'use1.test': [1, 1, 1] });
  assert.deepEqual({ ...(await pickRelay({ network: 'x', directory: single, fetch: n.fetch })), rttMs: 0 }, { url: 'wss://relay.test/v1', region: 'one', shard: '0', rttMs: 0 });
});

test('pickRelay: throws when no accepting region answers', async () => {
  const net = fakeNet({});
  const only: RelayDirectory = { ...dir, regions: [dir.regions[3]!, dir.regions[2]!] };
  await assert.rejects(pickRelay({ network: 'x', directory: only, fetch: net.fetch, timeoutMs: 50 }), /no accepting region/);
});

test('parseDirectory refuses what it cannot use', () => {
  const bad: unknown[] = [
    null,
    { ...dir, version: 2 },
    { ...dir, regions: [{ ...dir.regions[0], shards: 0 }] },
    { ...dir, regions: [{ ...dir.regions[0], shards: 1.5 }] },
    { ...dir, regions: [{ ...dir.regions[0], shards: 0x10001 }] },
    { ...dir, regions: [] },
    { ...dir, regions: [{ ...dir.regions[0], probe: 'ftp://x' }] },
    { ...dir, regions: [{ ...dir.regions[0], relay: 'https://x' }] },
    { ...dir, regions: [{ ...dir.regions[0], accepting: 'yes' }] },
    { ...dir, regions: [{ ...dir.regions[0], id: '' }] },
  ];
  for (const d of bad) assert.throws(() => parseDirectory(d), TypeError, JSON.stringify(d));
  assert.deepEqual(parseDirectory(dir), dir);
});
