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
  };
}
