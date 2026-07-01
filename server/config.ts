import { readFileSync } from 'node:fs';

export interface Config {
  port: number;
  // Relay shaping, all per link. These caps SHAPE — they pause the sender and
  // pace frames out — they never close a link:
  //   relayMaxBps      token-bucket rate (bytes/sec), burst capacity 2x. A frame
  //                    that overruns the bucket is held until the bucket refills
  //                    enough to pay for it. 0 disables rate shaping.
  //   relayHourlyBytes rolling per-link quota: a second bucket whose capacity is
  //                    one hour's allowance, refilled continuously. Bounds total
  //                    throughput per link over time. 0 disables.
  //   relayTrickleBps  the floor a quota-exhausted link keeps flowing at, so
  //                    heartbeats and control traffic survive after the hourly
  //                    quota is spent; full rate returns as the rolling refill
  //                    catches up.
  //   relayIdleSec     a link with no traffic for this long is reaped.
  relayMaxBps: number;
  relayHourlyBytes: number;
  relayTrickleBps: number;
  relayIdleSec: number;
  // Per-IP rate limit on register/resolve control messages (per minute, fixed
  // window). Pure control-plane DoS protection — it bounds how fast one source
  // can spam introductions. It is NOT what protects the pairing code (the code
  // never reaches Link). 0 disables.
  ipRatePerMin: number;
  // Link terminates behind a fronting proxy (e.g. Cloudflare), so the socket's
  // peer address is the proxy, not the client. Set LINK_TRUST_PROXY=1 to take the
  // first X-Forwarded-For hop as the client IP for the per-IP limit. Only safe
  // when the origin REFUSES connections that don't arrive through the proxy
  // (otherwise the header is attacker-spoofable) — see the deploy guide.
  trustProxy: boolean;
  // Access control (introduction plane). EMPTY ⇒ OPEN mode: any host that signs a
  // valid register may register (today's default). NON-EMPTY ⇒ CLOSED mode: only
  // hosts whose register public key (base64url) is in this set may register; every
  // other signed register is refused with Close.registerUnauthorized. This is pure
  // supplied config — no dynamic pairing state, no per-host state in Link. Populate
  // it from LINK_ALLOWED_REGISTER_KEYS (comma-separated) and/or a file named by
  // LINK_ALLOWED_REGISTER_KEYS_FILE (one key per line, `#` comments allowed).
  allowedRegisterKeys: Set<string>;
  // Bind the routing address to the host's register key: require every register's
  // address to equal base64url(SHA-256(register pub)). On ⇒ an address is a
  // commitment to a key nobody else holds, so it cannot be squatted or raced at
  // all (the register-key pin becomes a derivation). Default ON; set
  // LINK_BIND_ADDRESS_TO_KEY=0 for the legacy opaque-address model where the
  // address is any operator-chosen high-entropy handle.
  bindAddressToKey: boolean;
  // The canonical WebSocket authority (host[:port]) clients dial this instance at,
  // e.g. `link.example.com`. Folded into every register signature so a frame signed
  // for one Link cannot be replayed to another. Empty ⇒ derive it per-connection
  // from the request's Host header (correct unless a proxy rewrites Host, in which
  // case set LINK_ORIGIN to the public authority).
  origin: string;
}

// Comma/newline-separated list from an env var, trimmed, blanks and `#` comments
// dropped. Mirrors intEnv: a helper beside it for the allowlist config.
function csvEnv(name: string): string[] {
  return splitList(process.env[name] ?? '');
}

function splitList(raw: string): string[] {
  return raw
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0 && !s.startsWith('#'));
}

function boolEnv(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  if (raw === '1' || raw === 'true') return true;
  if (raw === '0' || raw === 'false') return false;
  throw new Error(`${name} must be 0/1 (or true/false), got ${JSON.stringify(raw)}`);
}

// The allowlist of authorized register keys: LINK_ALLOWED_REGISTER_KEYS (inline)
// unioned with the lines of LINK_ALLOWED_REGISTER_KEYS_FILE (if set). Non-empty ⇒
// the relay runs in closed mode.
function loadAllowedRegisterKeys(): Set<string> {
  const keys = new Set<string>(csvEnv('LINK_ALLOWED_REGISTER_KEYS'));
  const file = process.env.LINK_ALLOWED_REGISTER_KEYS_FILE;
  if (file !== undefined && file !== '') {
    let contents: string;
    try {
      contents = readFileSync(file, 'utf8');
    } catch (e) {
      throw new Error(`LINK_ALLOWED_REGISTER_KEYS_FILE could not be read (${file}): ${e instanceof Error ? e.message : String(e)}`);
    }
    for (const k of splitList(contents)) keys.add(k);
  }
  return keys;
}

function intEnv(name: string, fallback: number, min = 1): number {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n < min) {
    throw new Error(`${name} must be an integer >= ${min}, got ${JSON.stringify(raw)}`);
  }
  return n;
}

export function loadConfig(): Config {
  return {
    port: intEnv('LINK_PORT', 80),
    relayMaxBps: intEnv('LINK_RELAY_MAX_BPS', 1024 * 1024, 0),
    relayHourlyBytes: intEnv('LINK_RELAY_HOURLY_BYTES', 0, 0),
    relayTrickleBps: intEnv('LINK_RELAY_TRICKLE_BPS', 16_384),
    relayIdleSec: intEnv('LINK_RELAY_IDLE_SEC', 300),
    ipRatePerMin: intEnv('LINK_IP_RATE_PER_MIN', 60, 0),
    trustProxy: process.env.LINK_TRUST_PROXY === '1',
    allowedRegisterKeys: loadAllowedRegisterKeys(),
    bindAddressToKey: boolEnv('LINK_BIND_ADDRESS_TO_KEY', true),
    origin: (process.env.LINK_ORIGIN ?? '').trim().toLowerCase(),
  };
}
