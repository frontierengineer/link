import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TokenBucket } from './bucket';

function clock(start = 0): { now: () => number; advance: (ms: number) => void } {
  let t = start;
  return { now: () => t, advance: (ms) => { t += ms; } };
}

test('charge: burst spends down, debt waits out at the configured rate', () => {
  const c = clock();
  const b = new TokenBucket(1000, 2000, c.now);
  assert.equal(b.charge(2000), 0);    // full burst, no wait
  assert.equal(b.charge(500), 500);   // 500 in debt -> 500ms
  c.advance(500);
  assert.equal(b.charge(1000), 1000); // debt cleared, then 1000 over again
  // A frame far bigger than the burst is a long wait, never a refusal.
  c.advance(1000);
  assert.equal(b.charge(10_000), 10_000);
});

test('refill never exceeds capacity', () => {
  const c = clock();
  const b = new TokenBucket(1000, 2000, c.now);
  c.advance(60_000);
  assert.equal(b.charge(2000), 0);
  assert.equal(b.charge(1), 1);
});

test('coverUpTo floors at zero and fraction tracks the fill', () => {
  const c = clock();
  const b = new TokenBucket(1000, 2000, c.now);
  assert.equal(b.fraction(), 1);
  assert.equal(b.coverUpTo(1500), 1500);
  assert.equal(b.fraction(), 0.25);
  assert.equal(b.coverUpTo(800), 500); // only what is left
  assert.equal(b.coverUpTo(100), 0);   // empty covers nothing, no debt
  assert.equal(b.fraction(), 0);
  c.advance(250);
  assert.equal(b.coverUpTo(1000), 250); // exactly the refill
});

test('fraction clamps to 0..1 even when charge() ran the bucket into debt', () => {
  const c = clock();
  const b = new TokenBucket(1000, 2000, c.now);
  assert.equal(b.charge(5000), 3000);
  assert.equal(b.fraction(), 0);
});
