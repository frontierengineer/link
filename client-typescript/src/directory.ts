// Choosing a relay for a new network. A relay operator may publish a directory:
// regions, each with a URL to time and a relay URL template over its shards. The
// primary times every region once, when it creates the network, takes the
// closest, and hashes the network id onto one of its shards. The URL that comes
// out goes into the roster (section 3) and the network keeps it: the directory
// is consulted at creation only, never on reconnect.

import { utf8 } from './bytes.js';
import { sha256 } from './crypto.js';

export interface RelayDirectory {
  version: 1;
  regions: DirectoryRegion[];
}

export interface DirectoryRegion {
  id: string;
  name?: string;
  /** An https URL to time: a GET answered quickly from the region (a relay's `/health`). */
  probe: string;
  /** The relay URL, with `{shard}` where the shard goes (or none, for a region of one relay). */
  relay: string;
  /**
   * The region's shards; `{shard}` in its template is one of them, in lowercase hex. Default 1.
   * Each region has its own count, so one region can grow without touching the others; a change
   * only affects networks created afterwards, since a network keeps the URL it was given.
   */
  shards?: number;
  /** False: the region takes no new networks; those already on it are unaffected. */
  accepting: boolean;
}

export interface PickRelayOptions {
  /** The new network's id (its primary's node id). */
  network: string;
  /** The directory, or the URL to fetch it from. */
  directory: RelayDirectory | string;
  /** Requests timed per region; the fastest counts. Default 3. */
  probes?: number;
  /** How long a region has for all of its probes, in ms. Default 3000. */
  timeoutMs?: number;
  /** For tests, and for runtimes without a global fetch. */
  fetch?: typeof fetch;
}

export interface PickedRelay {
  /** The relay URL for the network's roster. */
  url: string;
  region: string;
  shard: string;
  /** The region's fastest probe, in ms. */
  rttMs: number;
}

/**
 * The shard a network belongs to among `shards`: the first four bytes of
 * SHA-256 of its id, big-endian, modulo `shards`, in lowercase hex padded to the
 * width of `shards - 1` (two digits for 256).
 */
export function shardOf(network: string, shards: number): string {
  if (!Number.isInteger(shards) || shards < 1 || shards > 0x10000) throw new RangeError('shards must be an integer from 1 to 65536');
  const h = sha256(utf8(network));
  const n = ((h[0]! << 24) | (h[1]! << 16) | (h[2]! << 8) | h[3]!) >>> 0;
  const width = Math.max(1, (shards - 1).toString(16).length);
  return (n % shards).toString(16).padStart(width, '0');
}

/** Checks a directory's shape; throws on anything it cannot use. */
export function parseDirectory(v: unknown): RelayDirectory {
  const fail = (why: string): never => {
    throw new TypeError(`relay directory: ${why}`);
  };
  if (typeof v !== 'object' || v === null) fail('not an object');
  const d = v as Record<string, unknown>;
  if (d.version !== 1) fail('version is not 1');
  if (!Array.isArray(d.regions) || d.regions.length === 0) fail('no regions');
  const regions = (d.regions as unknown[]).map((r, i): DirectoryRegion => {
    if (typeof r !== 'object' || r === null) fail(`region ${i} is not an object`);
    const g = r as Record<string, unknown>;
    if (typeof g.id !== 'string' || g.id === '') fail(`region ${i} has no id`);
    if (typeof g.probe !== 'string' || !/^https?:\/\//.test(g.probe)) fail(`region ${String(g.id)}: probe is not an http(s) URL`);
    if (typeof g.relay !== 'string' || !/^wss?:\/\//.test(g.relay)) fail(`region ${String(g.id)}: relay is not a ws(s) URL`);
    if (typeof g.accepting !== 'boolean') fail(`region ${String(g.id)}: accepting is not a boolean`);
    if (g.shards !== undefined && (!Number.isInteger(g.shards) || (g.shards as number) < 1 || (g.shards as number) > 0x10000)) {
      fail(`region ${String(g.id)}: shards is not an integer from 1 to 65536`);
    }
    return {
      id: g.id as string,
      ...(typeof g.name === 'string' ? { name: g.name } : {}),
      probe: g.probe as string,
      relay: g.relay as string,
      ...(g.shards !== undefined ? { shards: g.shards as number } : {}),
      accepting: g.accepting as boolean,
    };
  });
  return { version: 1, regions };
}

/**
 * Times every accepting region of the directory and returns the relay URL for
 * `network` in the closest. Throws when no region answers in time; the caller
 * then falls back to a relay of its own choosing.
 */
// An abort signal that fires after `ms`. Unlike AbortSignal.timeout, its timer keeps Node's event
// loop alive, so a probe that never answers still ends in the timeout rather than in the process
// exiting with the promise unsettled. Call the returned function once done with it.
function deadline(ms: number): [AbortSignal, () => void] {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(new DOMException('The operation timed out.', 'TimeoutError')), ms);
  return [ac.signal, () => clearTimeout(t)];
}

export async function pickRelay(opts: PickRelayOptions): Promise<PickedRelay> {
  const doFetch = opts.fetch ?? globalThis.fetch;
  const probes = Math.max(1, opts.probes ?? 3);
  const timeoutMs = opts.timeoutMs ?? 3000;
  let dir: RelayDirectory;
  if (typeof opts.directory === 'string') {
    const [signal, done] = deadline(timeoutMs);
    try {
      const resp = await doFetch(opts.directory, { cache: 'no-store', signal });
      if (!resp.ok) throw new Error(`relay directory: ${opts.directory} answered ${resp.status}`);
      dir = parseDirectory(await resp.json());
    } finally {
      done();
    }
  } else {
    dir = parseDirectory(opts.directory);
  }

  const time = async (region: DirectoryRegion): Promise<number> => {
    const [signal, done] = deadline(timeoutMs);
    let best = Infinity;
    try {
      for (let i = 0; i < probes; i++) {
        const t0 = performance.now();
        try {
          const resp = await doFetch(region.probe, { cache: 'no-store', signal });
          await resp.arrayBuffer();
          if (resp.ok) best = Math.min(best, performance.now() - t0);
        } catch {
          break; // timed out or unreachable: what was measured stands
        }
      }
    } finally {
      done();
    }
    return best;
  };
  const accepting = dir.regions.filter((r) => r.accepting);
  const rtts = await Promise.all(accepting.map(time));
  let pick = -1;
  for (let i = 0; i < accepting.length; i++) {
    if (rtts[i]! < Infinity && (pick < 0 || rtts[i]! < rtts[pick]!)) pick = i;
  }
  if (pick < 0) throw new Error('relay directory: no accepting region answered');
  const region = accepting[pick]!;
  const shard = shardOf(opts.network, region.shards ?? 1);
  return { url: region.relay.replaceAll('{shard}', shard), region: region.id, shard, rttMs: rtts[pick]! };
}
