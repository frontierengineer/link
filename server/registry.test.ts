import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Registry } from './registry';

type Sock = { name: string };

function clock(): { now: () => number; advance: (ms: number) => void } {
  let t = 1_000_000;
  return { now: () => t, advance: (ms) => { t += ms; } };
}

function makeRegistry(
  c: { now: () => number },
  opts: { relayIdleSec?: number; relayMaxBps?: number; relayHourlyBytes?: number; relayTrickleBps?: number } = {},
): Registry<Sock> {
  return new Registry<Sock>({
    relayIdleSec: 300,
    relayMaxBps: 0,
    relayHourlyBytes: 0,
    relayTrickleBps: 16_384,
    now: c.now,
    ...opts,
  });
}

// Stand up a relaying link with plain object sockets.
function makeRelayingLink(reg: Registry<Sock>) {
  reg.registerAddress({ name: 'control' }, 'addr', { pub: 'pin', ts: 1 });
  const link = reg.lookupAddress({ name: 'client' }, 'addr')!.link;
  reg.requestRelay(link);
  return reg.acceptRelay(link.id, { name: 'relay' })!;
}

// Like makeRelayingLink, but keep a handle on the host control socket so the
// per-host usage aggregate can be queried.
function makeOwnedRelay(reg: Registry<Sock>, address: string, control: Sock) {
  reg.registerAddress(control, address, { pub: `pin-${address}`, ts: 1 });
  const link = reg.lookupAddress({ name: 'client' }, address)!.link;
  reg.requestRelay(link);
  return reg.acceptRelay(link.id, { name: 'relay' })!;
}

test('address: TOFU-pinned, same key renews/replaces, a different key is refused, dropSocket only forgets its own entry', () => {
  const c = clock();
  const reg = makeRegistry(c);
  const s1: Sock = { name: 's1' };
  const s2: Sock = { name: 's2' };
  const client: Sock = { name: 'client' };

  // First register pins key K1 (trust-on-first-use).
  assert.deepEqual(reg.registerAddress(s1, 'addr-1', { pub: 'K1', ts: 10 }), { ok: true });
  // Renewal on the same socket (same key, newer ts): accepted, no replace.
  assert.deepEqual(reg.registerAddress(s1, 'addr-1', { pub: 'K1', ts: 11 }), { ok: true });
  assert.ok(reg.lookupAddress(client, 'addr-1'));

  // A SQUATTER (knows the address, holds a DIFFERENT key K2) is refused, and the
  // genuine registration is untouched (still resolvable).
  assert.deepEqual(reg.registerAddress(s2, 'addr-1', { pub: 'K2', ts: 12 }), { ok: false, reason: 'address_pinned' });
  assert.ok(reg.lookupAddress(client, 'addr-1'));

  // A REPLAYED frame (same key, but ts not newer than the last accepted) is refused.
  assert.deepEqual(reg.registerAddress(s2, 'addr-1', { pub: 'K1', ts: 11 }), { ok: false, reason: 'register_stale' });

  // The genuine host RESTARTS: same key K1, newer ts, new socket → displaces the ghost s1.
  assert.deepEqual(reg.registerAddress(s2, 'addr-1', { pub: 'K1', ts: 13 }), { ok: true, replaced: s1 });
  // The ghost's close handler must not delete the new owner's entry.
  reg.dropSocket(s1);
  assert.ok(reg.lookupAddress(client, 'addr-1'));

  // The pin lives only as long as the registration: once the holder drops, the
  // address is free and re-pins on the next first-register (here, a new key K9).
  reg.dropSocket(s2);
  assert.equal(reg.lookupAddress(client, 'addr-1'), undefined);
  assert.deepEqual(reg.registerAddress(s1, 'addr-1', { pub: 'K9', ts: 14 }), { ok: true });
});

test('idle sweep reaps links; a relaying link dies with its relay ends, not its control socket', () => {
  const c = clock();
  const reg = makeRegistry(c);
  const hostControl: Sock = { name: 'control' };
  const hostRelay: Sock = { name: 'relay' };
  const client: Sock = { name: 'client' };

  reg.registerAddress(hostControl, 'addr', { pub: 'pin', ts: 1 });
  const introduced = reg.lookupAddress(client, 'addr')!.link;
  c.advance(301_000);
  assert.deepEqual(reg.sweep(), [introduced]);
  assert.equal(introduced.state, 'closed');

  const link = reg.lookupAddress(client, 'addr')!.link;
  assert.equal(reg.requestRelay(link), true);
  assert.equal(reg.requestRelay(link), false); // not re-requestable
  assert.equal(reg.acceptRelay(link.id, hostRelay), link);
  assert.deepEqual(reg.chargeFrame(link, 'client', 100), { waitMs: 0 });
  assert.deepEqual(reg.chargeFrame(link, 'host', 40), { waitMs: 0 });

  // Control socket loss leaves the live relay alone (but forgets the address)...
  assert.deepEqual(reg.dropSocket(hostControl), []);
  // ...but losing a relay end kills it and records the per-link totals.
  assert.deepEqual(reg.dropSocket(hostRelay), [link]);
  const stats = reg.stats() as {
    links: { live: number };
    recentlyClosed: { reason: string; bytesFromClient: number; bytesFromHost: number }[];
  };
  assert.equal(stats.links.live, 0);
  assert.equal(stats.recentlyClosed[0].reason, 'peer_gone');
  assert.equal(stats.recentlyClosed[0].bytesFromClient, 100);
  assert.equal(stats.recentlyClosed[0].bytesFromHost, 40);
});

test('shaping: the rate bucket charges debt — waits stack across directions, and a held frame fends off the idle reaper', () => {
  const c = clock();
  const reg = makeRegistry(c, { relayMaxBps: 1000 }); // burst capacity 2000
  const link = makeRelayingLink(reg);

  assert.deepEqual(reg.chargeFrame(link, 'client', 2000), { waitMs: 0 }); // full burst
  assert.deepEqual(reg.chargeFrame(link, 'client', 1000), { waitMs: 1000 });
  // Both directions draw on the same bucket, so debt stacks.
  assert.deepEqual(reg.chargeFrame(link, 'host', 500), { waitMs: 1500 });

  c.advance(1500); // debt cleared
  // A frame far bigger than the burst is a long wait, never a refusal...
  assert.deepEqual(reg.chargeFrame(link, 'client', 400_000), { waitMs: 400_000 });
  // ...and while it is held the link is not idle, even far past relayIdleSec.
  c.advance(350_000);
  assert.deepEqual(reg.sweep(), []);
  // Once it has gone out, the idle clock runs from its due time as usual.
  c.advance(351_000);
  assert.deepEqual(reg.sweep(), [link]);
});

test('quota: exhaustion degrades to the trickle floor; usage events fire on tier crossings and throttled flips, at most ~1/sec', () => {
  const c = clock();
  const reg = makeRegistry(c, { relayHourlyBytes: 10_000, relayTrickleBps: 1000 });
  const link = makeRelayingLink(reg);

  // 0.5 crossed: first event, fraction exact.
  assert.deepEqual(reg.chargeFrame(link, 'client', 5000),
    { waitMs: 0, usage: { used: 0.5, throttled: false } });
  // Still in the same tier: no event.
  assert.deepEqual(reg.chargeFrame(link, 'client', 100), { waitMs: 0 });
  // 0.8 crossed, but within 1s of the last event: suppressed.
  assert.deepEqual(reg.chargeFrame(link, 'client', 3100), { waitMs: 0 });
  // The next charge after the rate-limit window announces the tier.
  c.advance(1100);
  const c4 = reg.chargeFrame(link, 'client', 100);
  assert.equal(c4.waitMs, 0);
  assert.equal(c4.usage?.throttled, false);
  assert.ok(c4.usage!.used > 0.8 && c4.usage!.used < 0.84, `used=${c4.usage!.used}`);

  // Bucket empties: the shortfall is paced by the trickle bucket instead of
  // closing the link, and the event reports used=1 + the throttled flip.
  c.advance(1100);
  const c5 = reg.chargeFrame(link, 'client', 4000);
  assert.ok(c5.waitMs > 250 && c5.waitMs < 350, `waitMs=${c5.waitMs}`); // beyond the 2000 trickle burst, paced at 1000 B/s
  assert.deepEqual(c5.usage, { used: 1, throttled: true });
  assert.equal(link.throttled, true);

  // The rolling refill restores full rate; the flip back is announced.
  c.advance(3_600_000);
  const c6 = reg.chargeFrame(link, 'client', 100);
  assert.equal(c6.waitMs, 0);
  assert.deepEqual(c6.usage, { used: 0.01, throttled: false });
  assert.equal(link.throttled, false);

  // Stats expose the same vocabulary per link.
  const live = (reg.stats() as { liveLinks: { usedFraction: number; throttled: boolean }[] }).liveLinks[0];
  assert.equal(live.usedFraction, 0.01);
  assert.equal(live.throttled, false);
});

test('usage aggregate: per-host, owner-scoped; unlimited without a quota, a fraction with one', () => {
  const c = clock();
  const reg = makeRegistry(c); // no quota configured
  const h1: Sock = { name: 'control-1' };
  const h2: Sock = { name: 'control-2' };
  const l1 = makeOwnedRelay(reg, 'addr-1', h1);
  const l2 = makeOwnedRelay(reg, 'addr-2', h2);

  // No quota ⇒ each connection is reported UNLIMITED, never used:0 (so a byte
  // budget can't be inferred), and a host only ever sees its own connection.
  assert.deepEqual(reg.usageForHost(h1), [{ linkId: l1.id, unlimited: true }]);
  assert.deepEqual(reg.usageForHost(h2), [{ linkId: l2.id, unlimited: true }]);
  // A socket owning nothing gets an empty report.
  assert.deepEqual(reg.usageForHost({ name: 'stranger' }), []);
});

test('usage aggregate: with a quota, reports the per-connection fraction and throttle flag', () => {
  const c = clock();
  const reg = makeRegistry(c, { relayHourlyBytes: 10_000 });
  const control: Sock = { name: 'control' };
  const link = makeOwnedRelay(reg, 'addr', control);

  reg.chargeFrame(link, 'client', 2500); // 25% of the hourly allowance
  assert.deepEqual(reg.usageForHost(control), [{ linkId: link.id, used: 0.25, throttled: false }]);
  assert.deepEqual(reg.usageSnapshot(link), { linkId: link.id, used: 0.25, throttled: false });
});
