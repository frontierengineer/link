import { randomUUID } from 'node:crypto';
import { TokenBucket } from './bucket';
import type { UsageEntry } from './types';

// All state Link ever holds, in one in-memory registry. Nothing here survives a
// restart, and that is the design: hosts re-register their address, clients
// re-establish their links.
//
// The registry is generic over the socket type so the lifecycle logic can be
// unit-tested with plain objects; the server instantiates it with WebSocket. It
// never touches sockets itself — it only stores them and hands them back, so
// every close/notify decision stays in one place (server.ts).

export type LinkState = 'introduced' | 'pending' | 'relaying' | 'closed';
export type RelayEnd = 'host' | 'client';
export type CloseReason = 'peer_gone' | 'idle' | 'slow_peer';

// What chargeFrame hands back: how long the frame must be held before it may be
// forwarded (0 = now), and — when the hourly quota knob is on and a client-worthy
// change just happened — a usage event for the host's control socket. `used` is a
// fraction of the hourly allowance: fractions are Link's only outward usage
// vocabulary; absolute bytes live on /v1/stats.
export interface FrameCharge {
  waitMs: number;
  usage?: { used: number; throttled: boolean };
}

export interface Link<S> {
  id: string;
  state: LinkState;
  // The introduced client socket (the party that resolved the address).
  client: S;
  // The socket that holds the address registration. Kept only so the host can be
  // notified ('arrived', 'relay', 'usage') — it is never closed on link death.
  hostControl: S;
  // The dedicated socket the host dials back for the relay.
  hostRelay?: S;
  createdAt: number;
  relayStartedAt?: number;
  lastActivity: number;
  bytesFromHost: number;
  bytesFromClient: number;
  bps?: TokenBucket;
  quota?: TokenBucket;
  // Pays for bytes the empty quota bucket cannot, pacing them at the trickle
  // floor so a quota-exhausted link keeps flowing instead of closing.
  trickle?: TokenBucket;
  // True while the link is living off the trickle floor.
  throttled: boolean;
  // Last usage event actually announced, for crossing/flip/rate-limit checks.
  usageTier: number;
  usageThrottled: boolean;
  usageSentAt: number;
}

interface AddressEntry<S> {
  socket: S;
  // Anti-squat pin. `pinPub` is the Ed25519 public key (base64url) presented on
  // this address's FIRST register (trust-on-first-use); `lastTs` is the timestamp
  // of the last accepted register. The pin is memory-only and lives exactly as
  // long as the registration — when the holding socket drops, dropSocket forgets
  // the entry and the next first-register re-pins (a host holds its socket and
  // re-registers with the same key on reconnect). `lastTs` makes every accepted
  // register strictly newer than the last, so a captured frame can't be replayed.
  pinPub: string;
  lastTs: number;
}

// Outcome of an authenticated address registration.
export type RegisterAddressResult<S> =
  | { ok: true; replaced?: S }
  | { ok: false; reason: 'address_pinned' | 'register_stale' };

interface ClosedLink {
  linkId: string;
  relayStartedAt: string;
  closedAt: string;
  reason: CloseReason;
  bytesFromHost: number;
  bytesFromClient: number;
}

export interface RegistryOptions {
  relayIdleSec: number;
  relayMaxBps: number;      // 0 = unshaped
  relayHourlyBytes: number; // 0 = no quota
  relayTrickleBps: number;  // floor rate once the quota bucket is empty
  now?: () => number;
}

const RECENT_MAX = 32;
// Usage events fire when `used` crosses one of these, in either direction.
const USAGE_TIERS = [0.5, 0.8, 0.95, 1];
// And never more often than this per link.
const USAGE_MIN_INTERVAL_MS = 1000;

function round4(x: number): number {
  return Math.round(x * 10_000) / 10_000;
}

export class Registry<S> {
  private readonly addresses = new Map<string, AddressEntry<S>>();
  private readonly links = new Map<string, Link<S>>();
  // Per-link totals of relays that already ended, so a client polling the stats
  // surface just after a close still sees what that relay used. A small ring, in
  // memory like everything else.
  private readonly recentlyClosed: ClosedLink[] = [];
  private linksTotal = 0;
  private relaysTotal = 0;
  private bytesFromHostTotal = 0;
  private bytesFromClientTotal = 0;
  readonly now: () => number;

  constructor(private readonly opts: RegistryOptions) {
    this.now = opts.now ?? Date.now;
  }

  // — host side —

  // Authenticated, anti-squat address registration. `sig` is the ALREADY-VERIFIED
  // identity from registerAuth.verifyRegisterAuth (`pub` = the presenting key,
  // `ts` = the frame's timestamp); the crypto + skew check live there, the PIN
  // state lives here. Trust-on-first-use: the first register for an address pins
  // its key; thereafter every register for the same address MUST be signed by the
  // SAME key and carry a strictly newer timestamp.
  //   • same key + newer ts → accepted; on a DIFFERENT socket the displaced one
  //     is returned as `replaced` (a genuine host reconnect/restart, closed 4005).
  //   • different key → rejected (address_pinned): a party that knows the address
  //     but not the key can no longer steal the rendezvous.
  //   • same key + ts ≤ lastTs → rejected (register_stale): a replayed frame.
  registerAddress(socket: S, address: string, sig: { pub: string; ts: number }): RegisterAddressResult<S> {
    const existing = this.addresses.get(address);
    if (!existing) {
      this.addresses.set(address, { socket, pinPub: sig.pub, lastTs: sig.ts });
      return { ok: true };
    }
    if (existing.pinPub !== sig.pub) return { ok: false, reason: 'address_pinned' };
    if (sig.ts <= existing.lastTs) return { ok: false, reason: 'register_stale' };
    const replaced = existing.socket !== socket ? existing.socket : undefined;
    this.addresses.set(address, { socket, pinPub: sig.pub, lastTs: sig.ts });
    return replaced ? { ok: true, replaced } : { ok: true };
  }

  // — client side —

  lookupAddress(client: S, address: string): { link: Link<S> } | undefined {
    const entry = this.addresses.get(address);
    if (!entry) return undefined;
    return { link: this.createLink(client, entry.socket) };
  }

  private createLink(client: S, hostControl: S): Link<S> {
    const link: Link<S> = {
      id: randomUUID(),
      state: 'introduced',
      client,
      hostControl,
      createdAt: this.now(),
      lastActivity: this.now(),
      bytesFromHost: 0,
      bytesFromClient: 0,
      throttled: false,
      usageTier: 0,
      usageThrottled: false,
      usageSentAt: -Infinity,
    };
    this.links.set(link.id, link);
    this.linksTotal++;
    return link;
  }

  // — relay —

  requestRelay(link: Link<S>): boolean {
    if (link.state !== 'introduced') return false;
    link.state = 'pending';
    link.lastActivity = this.now();
    return true;
  }

  acceptRelay(linkId: string, hostRelay: S): Link<S> | undefined {
    const link = this.links.get(linkId);
    if (!link || link.state !== 'pending') return undefined;
    link.state = 'relaying';
    link.hostRelay = hostRelay;
    link.relayStartedAt = this.now();
    link.lastActivity = this.now();
    if (this.opts.relayMaxBps > 0) {
      link.bps = new TokenBucket(this.opts.relayMaxBps, this.opts.relayMaxBps * 2, this.now);
    }
    if (this.opts.relayHourlyBytes > 0) {
      link.quota = new TokenBucket(this.opts.relayHourlyBytes / 3600, this.opts.relayHourlyBytes, this.now);
      link.trickle = new TokenBucket(this.opts.relayTrickleBps, this.opts.relayTrickleBps * 2, this.now);
    }
    this.relaysTotal++;
    return link;
  }

  // Charge a frame against the caps and account it. Caps shape, they never close:
  // the result is how long the caller must hold the frame before forwarding it.
  // The rate bucket is charged debt-style; the quota bucket covers what it can and
  // the shortfall is paced by the trickle bucket, so a quota-exhausted link
  // degrades to the trickle floor and recovers as the rolling refill catches up.
  // Trickle bytes still count toward the totals.
  chargeFrame(link: Link<S>, from: RelayEnd, bytes: number): FrameCharge {
    let waitMs = 0;
    if (link.bps) waitMs = link.bps.charge(bytes);
    if (link.quota && link.trickle) {
      const shortfall = bytes - link.quota.coverUpTo(bytes);
      link.throttled = shortfall > 0;
      if (shortfall > 0) waitMs = Math.max(waitMs, link.trickle.charge(shortfall));
    }
    if (from === 'host') {
      link.bytesFromHost += bytes;
      this.bytesFromHostTotal += bytes;
    } else {
      link.bytesFromClient += bytes;
      this.bytesFromClientTotal += bytes;
    }
    // A held frame keeps the link alive: idleness counts from the moment the last
    // charged frame is due out, not from when it arrived.
    link.lastActivity = this.now() + waitMs;
    const usage = this.usageEvent(link);
    return usage ? { waitMs, usage } : { waitMs };
  }

  // A single connection's usage in Link's outward vocabulary: a 0..1 fraction of
  // the hourly allowance (+ the throttle flag) when a quota is configured, or an
  // explicit `unlimited` when it is not — never absolute bytes, never the limit
  // itself. Both the push (usageEvent) and the pull (usageForHost) speak this.
  usageSnapshot(link: Link<S>): UsageEntry {
    if (!link.quota) return { linkId: link.id, unlimited: true };
    return { linkId: link.id, used: round4(1 - link.quota.fraction()), throttled: link.throttled };
  }

  // Every live connection owned by one host control socket, each broken out on its
  // own. This is the "give me everything this host owns" pull: a host names no link
  // id, so it can only ever see the usage of connections it actually holds.
  usageForHost(hostControl: S): UsageEntry[] {
    const out: UsageEntry[] = [];
    for (const link of this.links.values()) {
      if (link.state === 'relaying' && link.hostControl === hostControl) out.push(this.usageSnapshot(link));
    }
    return out;
  }

  // A usage event is due when the used fraction crossed a tier or the throttled
  // flag flipped — rate-limited per link, and only when the hourly quota knob is
  // on at all.
  private usageEvent(link: Link<S>): FrameCharge['usage'] {
    if (!link.quota) return undefined;
    const used = round4(1 - link.quota.fraction());
    const tier = USAGE_TIERS.filter((t) => used >= t).length;
    if (tier === link.usageTier && link.throttled === link.usageThrottled) return undefined;
    if (this.now() - link.usageSentAt < USAGE_MIN_INTERVAL_MS) return undefined;
    link.usageTier = tier;
    link.usageThrottled = link.throttled;
    link.usageSentAt = this.now();
    return { used, throttled: link.throttled };
  }

  // — lifecycle —

  // Idempotent: whoever gets to a dying link first records it; later callers find
  // it gone. The state tombstone stops in-flight frames from being spliced after
  // the decision to close (the WS close handshake is not instantaneous).
  closeLink(link: Link<S>, reason: CloseReason): void {
    if (!this.links.delete(link.id)) return;
    link.state = 'closed';
    if (link.relayStartedAt === undefined) return;
    this.recentlyClosed.push({
      linkId: link.id,
      relayStartedAt: new Date(link.relayStartedAt).toISOString(),
      closedAt: new Date(this.now()).toISOString(),
      reason,
      bytesFromHost: link.bytesFromHost,
      bytesFromClient: link.bytesFromClient,
    });
    if (this.recentlyClosed.length > RECENT_MAX) this.recentlyClosed.shift();
  }

  // A socket went away: forget everything it owned. Returns the links that died
  // with it (already removed) so the server can close the other ends. A relaying
  // link only dies with its relay ends — the host control socket dropping must not
  // tear down live relays.
  dropSocket(socket: S): Link<S>[] {
    for (const [address, entry] of this.addresses) {
      if (entry.socket === socket) this.addresses.delete(address);
    }
    const dead: Link<S>[] = [];
    for (const link of this.links.values()) {
      const party = link.state === 'relaying'
        ? link.client === socket || link.hostRelay === socket
        : link.client === socket || link.hostControl === socket;
      if (party) dead.push(link);
    }
    for (const link of dead) this.closeLink(link, 'peer_gone');
    return dead;
  }

  // Collect idle links. Idle links are removed here; the server closes their
  // sockets.
  sweep(): Link<S>[] {
    const now = this.now();
    const idleCutoff = now - this.opts.relayIdleSec * 1000;
    const idle: Link<S>[] = [];
    for (const link of this.links.values()) {
      if (link.lastActivity <= idleCutoff) idle.push(link);
    }
    for (const link of idle) this.closeLink(link, 'idle');
    return idle;
  }

  stats(): Record<string, unknown> {
    let relaying = 0;
    for (const link of this.links.values()) {
      if (link.state === 'relaying') relaying++;
    }
    return {
      addressRegistrations: this.addresses.size,
      links: {
        live: this.links.size,
        relaying,
        total: this.linksTotal,
        totalRelayed: this.relaysTotal,
      },
      bytesRelayed: { fromHost: this.bytesFromHostTotal, fromClient: this.bytesFromClientTotal },
      liveLinks: [...this.links.values()].map((l) => ({
        linkId: l.id,
        state: l.state,
        startedAt: new Date(l.createdAt).toISOString(),
        ...(l.relayStartedAt !== undefined
          ? { relayStartedAt: new Date(l.relayStartedAt).toISOString() }
          : {}),
        bytesFromHost: l.bytesFromHost,
        bytesFromClient: l.bytesFromClient,
        ...(l.quota
          ? { usedFraction: round4(1 - l.quota.fraction()), throttled: l.throttled }
          : {}),
      })),
      recentlyClosed: [...this.recentlyClosed].reverse(),
    };
  }
}
