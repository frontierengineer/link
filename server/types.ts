// The wire vocabulary for the /v1/link WebSocket. Control traffic is JSON text
// frames; everything in here is ROUTING, never content. An `address` is an
// opaque, high-entropy string to Link — it stores and matches it, it never
// interprets it.
//
// There is deliberately NO field anywhere in this protocol for a pairing secret.
// The short pairing code lives only inside the two endpoints' SPAKE2 handshake
// (which rides the relay as opaque frames); it never reaches Link in any form,
// raw or hashed. Link's entire job is: pin an address to a key, introduce a
// client to the host at that address, and splice ciphertext between them.

export interface RegisterMessage {
  type: 'register';
  // The host's routing address: high-entropy, public, stable. Knowing it lets a
  // client ASK to be introduced — nothing more; entry is gated by the end-to-end
  // handshake that Link cannot see.
  address: string;
  // REQUIRED. Proves the registrant holds the key pinned to this address
  // (anti-squat). An absent/invalid/stale auth is refused outright
  // (Close.registerAuth). See registerAuth.ts for the signed-message construction.
  auth: RegisterAuth;
}

// The signature envelope on a register. Link verifies `sig` (Ed25519) over a
// canonical message binding address + ts + nonce, checks `ts` against its skew
// window, and pins `pub` on first use (TOFU). See registerAuth.ts.
export interface RegisterAuth {
  alg: 'ed25519';
  pub: string; // base64url, 32-byte Ed25519 public key
  ts: number; // ms since epoch
  nonce: string; // base64url random
  sig: string; // base64url, 64-byte Ed25519 signature
}

export interface ResolveMessage {
  type: 'resolve';
  // The address of the host this client wants to be introduced to.
  address: string;
}

// Host → Link, on the authenticated control socket: "report the usage of every
// connection I own." There is deliberately NO link selector — a host pulls the
// AGGREGATE for all of its live connections at once, so it can never probe a link
// it does not own. The reply is a `usage` message (the SAME shape Link pushes
// unprompted on tier crossings), so push and pull are interchangeable.
export interface GetUsageMessage {
  type: 'getUsage';
}

export interface RelayMessage {
  type: 'relay';
  linkId: string;
}

export interface AcceptMessage {
  type: 'accept';
  linkId: string;
}

export type ClientMessage = RegisterMessage | ResolveMessage | RelayMessage | AcceptMessage | GetUsageMessage;

// One connection's usage, spoken in RELATIVE terms only. Link never puts absolute
// bytes or its own limit configuration on the wire, so a host cannot reverse-
// engineer the operator's byte budget from what it sees:
//   • quota configured  → `used` is the fraction of the hourly allowance consumed
//     (0..1) and `throttled` says whether the connection is pinned to the trickle
//     floor. `used` is a proportion, never a byte count.
//   • no quota (self-hosted / unlimited) → `unlimited: true`. This is reported
//     EXPLICITLY rather than as `used: 0`, so "no limit" is never confused with
//     "limit that happens to be untouched".
export type UsageEntry =
  | { linkId: string; used: number; throttled: boolean }
  | { linkId: string; unlimited: true };

export type ServerMessage =
  | { type: 'registered'; address: string }
  | { type: 'found'; linkId: string }
  | { type: 'arrived'; linkId: string; address: string }
  | { type: 'relay'; linkId: string }
  | { type: 'relaying'; linkId: string }
  // Relay usage for every live connection the receiving control socket owns, each
  // broken out per connection. Sent two ways with the SAME shape: PUSHED unprompted
  // when a connection crosses a usage tier or flips its throttle flag (rate-limited
  // per connection), and PULLED on demand in reply to `getUsage`. See UsageEntry
  // for why it is fractions/`unlimited`, never bytes or limits.
  | { type: 'usage'; connections: UsageEntry[] }
  | { type: 'error'; error: string };

// Application close codes (4000-4999). The close code is the protocol's way of
// telling a client *why* its socket died, so it can pick the right reaction.
export const Close = {
  // Malformed JSON, unknown type, or a message illegal for the socket's current
  // role/state.
  badRequest: 4000,
  // Per-IP rate limit on register/resolve tripped.
  rateLimited: 4002,
  // The other end of the link went away (covers a host that never dialed back).
  peerGone: 4003,
  // The link sat with no traffic for relayIdleSec.
  idleTimeout: 4004,
  // A newer socket validly re-registered the same address; this older one is
  // retired.
  replaced: 4005,
  // The peer stopped draining and too much piled up in its send buffer.
  slowPeer: 4006,
  // A register was missing a valid signed `auth`, or its signature/timestamp did
  // not check out: the registrant cannot prove it holds the address's key, so it
  // is refused outright (distinct from 4005, which retires a SUPERSEDED but
  // validly-signed socket). Also covers a register whose address is not the
  // commitment to its own key when address-key binding is enforced.
  registerAuth: 4007,
  // The register's signature was valid, but the relay is in CLOSED mode and this
  // host's register key is not on the operator's allowlist. Distinct from 4007:
  // the key is genuine, it is simply not authorized on this instance.
  registerUnauthorized: 4010,
  // Reserved, never sent: 4001 (unused), 4008/4009 (former rate/quota closes —
  // those caps now SHAPE flow instead of closing). Kept reserved so they are
  // never reused to mean something new to an older client.
} as const;
