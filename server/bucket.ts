// Continuous-refill token bucket used for relay shaping. Capacity caps how far
// it fills (the burst), never how far it can be spent down. Two spending modes:
//
//   charge(n)    debt model — always spends, tokens may go negative, returns
//                how long until the debt clears. The shaper holds the frame
//                exactly that long, so even a frame far bigger than the burst
//                is just a long wait, never a close.
//   coverUpTo(n) floor-at-zero model — spends only what the bucket holds and
//                reports how much that covered. The hourly quota uses this so
//                trickle traffic during exhaustion cannot dig a debt hole the
//                rolling refill would then have to climb out of: the moment
//                sending slows below the refill rate, full rate starts coming
//                back.
export class TokenBucket {
  private tokens: number;
  private lastRefillAt: number;

  constructor(
    private readonly ratePerSec: number,
    private readonly capacity: number,
    private readonly now: () => number = Date.now,
  ) {
    this.tokens = capacity;
    this.lastRefillAt = this.now();
  }

  private refill(): void {
    const t = this.now();
    this.tokens = Math.min(this.capacity, this.tokens + ((t - this.lastRefillAt) / 1000) * this.ratePerSec);
    this.lastRefillAt = t;
  }

  // Spend n unconditionally; returns ms until the bucket is non-negative again
  // (0 = it already is, the frame can go now).
  charge(n: number): number {
    this.refill();
    this.tokens -= n;
    return this.tokens >= 0 ? 0 : (-this.tokens / this.ratePerSec) * 1000;
  }

  // Spend up to n without going negative; returns how much was covered.
  coverUpTo(n: number): number {
    this.refill();
    const covered = Math.max(0, Math.min(this.tokens, n));
    this.tokens -= covered;
    return covered;
  }

  // Current fill as a fraction of capacity, clamped to 0..1.
  fraction(): number {
    this.refill();
    return Math.min(1, Math.max(0, this.tokens / this.capacity));
  }
}
