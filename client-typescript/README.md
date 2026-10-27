# @frontierengineer/link-client

The TypeScript client for Link, protocol version 1 ([`spec/protocol.md`](../spec/protocol.md)). It
does everything a member needs: keys, signed rosters, pairing with a short code (SPAKE2), and
end-to-end encrypted sessions (Noise IK) over one outbound WebSocket to a relay that only routes.

ESM, Node 22 or later, and browsers. The core imports nothing from Node. A WebSocket constructor
can be passed in; the default is `globalThis.WebSocket`. Its only dependencies are
`@noble/curves`, `@noble/hashes` and `@noble/ciphers`.

## Use

```ts
import { createIdentity, identityFromSeed, createNetwork, Primary, Member, pair } from '@frontierengineer/link-client';

// The primary: create the network once, then persist both seeds and the roster.
const me = createIdentity();                                   // me.seed: 32 secret bytes
const { roster, networkSeed } = createNetwork({ identity: me, relay: 'wss://frontierengineer.link/v1' });
const primary = await Primary.connect({ identity: me, roster, networkSeed });
primary.on('roster', (r) => save(r));                         // every accepted roster: persist it

// Invite a node. Show the code or the link; it admits one node for 15 minutes.
const { code, codeId, link, expiresAt } = primary.openPairingCode();
primary.on('paired', ({ member, codeId }) => label(member.id, codeId)); // your own categories, by code

// The newcomer: pair once, then connect as a member from then on.
const id = identityFromSeed(savedSeed);
const { roster: r } = await pair({ link, identity: id });     // or { network, code, codeId, relay }
const member = await Member.connect({ identity: id, roster: r });

await member.send(peerId, bytes);                              // Uint8Array, up to 64 MiB
member.onMessage(({ from, bytes }) => { /* ... */ });          // or: for await (const m of member.messages)
member.close();
```

## API

**Identity.** `createIdentity()`, `identityFromSeed(seed)` give `{ seed, id, ed25519, x25519, sign }`.
Persist `seed`; everything else derives from it (section 2).

**Network seed.** A network has a 32-byte seed of its own, minted by `createNetwork` apart from
every node's seed (`createNetworkSeed()`). `networkKeyFromSeed(seed)` gives `{ seed, id, ed25519,
sign }`: the network key signs every roster, and the network id derives from it, whichever node is
primary (section 2). Its custody is the application's: the client never stores, sends or deletes
it. A node started with `networkSeed` is the primary; when its roster names another member
primary, it claims the primary once registered, publishing the next roster with itself as
`primary`, nothing else changed (section 3.1). The former primary takes that roster and stops being the
primary in place: its codes close and its pairing channels end, and its connection and sessions
stay.

**Rosters.** `createNetwork({ identity, relay?, members?, now?, networkSeed? })` returns
`{ roster, networkSeed }`: version 1 with `identity` as the primary and `members` (roster entries,
none by default) listed beside it, issued at `now` (Unix milliseconds), signed by the network key.
It throws `InvalidError` for an entry that is not one or is listed twice, and `RosterFullError`
over 65000 bytes. A roster is `{ network, version,
issuedAt, relay, networkKey, primary, members, signature }`: `primary` is a member's node id, and
each member is `{ id, ed25519, x25519 }`; `primaryOf(r)` is that member's entry. Members carry no
categories: an application that has some keeps them in its own data, by node id.
`rosterProblem(r)` returns why a roster is invalid, or `null`; `acceptanceProblem(r, pinned, held)`
applies the acceptance rule; `canonicalize(value)` is RFC 8785 JCS. A roster's JCS encoding,
signature included, is at most `MAX_ROSTER_BYTES` (65000 bytes, about 440 members; `rosterSize(r)`
measures it), so it always fits one session message; a larger one is invalid.

**A network with no relay yet** (section 3.2). Without `relay` (or with `''`), `createNetwork` makes
a network that is not placed: valid, but no member dials it, so it can be made offline, and placed the
first time the primary can reach the directory. `isPlaced(roster)` says whether a roster names a relay. A `Member` or
`Primary` on an unplaced roster without a `relayUrl` throws `InvalidError` ("the network has no
relay yet") at once; with one, it dials that, and its pairing links name it.
`placeNetwork({ roster, networkSeed, relay, now? })` returns the next version with `relay` set and
nothing else changed, signed by the network key; start the primary on it and it publishes it at
registration. It throws `InvalidError` when the roster is placed already, when `relay` is not a
`ws://` or `wss://` URL (`isRelayUrl`), or when the seed does not derive the roster's network
key. A placed network is not placed again.

**Offline.** A member never stops or crashes for want of a network (section 11): with its relay
unreachable (refused, a name that does not resolve, no route) or gone mid-session, it says so
through its states (`disconnected`, then `connecting` again), retries with backoff, and a call
that needs the relay fails with its own error; a lookup after 4009 that answers something that is
not a URL is ignored.

```ts
const { roster, networkSeed } = createNetwork({ identity: me, members: [memberFromIdentity(laptop)] }); // no relay
// ...later, the first time the directory answers:
const { url } = await pickRelay({ network: roster.network, directory });
const placed = placeNetwork({ roster, networkSeed, relay: url });   // version 2: persist it
const primary = await Primary.connect({ identity: me, roster: placed, networkSeed });
```

**`Member`** (`Member.connect(options)` resolves once registered; `new Member(options)` starts
connecting and returns at once):

| Option | |
|---|---|
| `identity`, `roster` | required; the newest roster held |
| `relayUrl` | defaults to `roster.relay`; required on a roster not placed yet |
| `pinnedNetworkKey` | defaults to `roster.networkKey` |
| `networkSeed` | the network seed, for the node to be the primary; it must derive `roster.networkKey` |
| `WebSocket` | a WHATWG WebSocket constructor, used as given |
| `WebSocketStream` | a WHATWG WebSocketStream constructor (real back-pressure). Without either option a member uses `globalThis.WebSocketStream` where it exists, else `globalThis.WebSocket` |
| `creditWindow` | the receive window granted per session: 1 MiB (every session's initial credit) or more, granted as extra credit |
| `resolveRelay(network)` | called on close code 4009; may return a new relay URL |
| `timing` | overrides for the protocol timers (rekey, idle, handshake timeout, backoff), for tests |

- `send(peerId, bytes)` resolves once every fragment is handed to the relay connection. It
  rejects with a `LinkError` whose `code` is `unreachable` (the peer is not connected; nothing is
  queued), `refused` (the peer's roster does not list this node), `revoked`, `replaced`,
  `timeout`, `closed`, or `invalid` (unknown peer, over 64 MiB). Delivery is at most once:
  resolving means handed to the relay.
- `onMessage(handler)` or the async iterator `messages` deliver `{ from, bytes }` whole and in
  order per sender. A message is credited back to its sender when the application takes it, so a
  slow reader slows its senders.
- Events (`on(name, listener)` returns an unsubscribe function): `state`
  (`connecting`, `connected`, `disconnected`, `revoked`, `replaced`, `closed`), `roster`, `disconnect`
  (`{ code, reason }`), `moved` (4009), `relayError`, `shaping` (below).
- `shaping` is how the relay shapes the network now, `{ rateBps, slowed }` (type `Shaping`):
  `rateBps` the rate in force in bytes a second (the network's rate, or its trickle rate once its
  quota is spent; 0 for none), `slowed` whether the quota is spent and the trickle holds. Every
  member has it, the primary or not, from the relay's `shaping` notices (spec section 9): the
  relay sends one at registration and whenever it changes, and the `shaping` event fires on each
  change, so an application never polls `usage()` to learn it is slowed. It is
  `{ rateBps: 0, slowed: false }` before any notice and with a relay that does not send them.
- `syncRoster()` asks the primary for its newest roster. `resign()` leaves the network.
  Rosters also spread member to member: when a handshake shows a peer holds a newer roster,
  the member asks that peer for it, and hands its own to a peer that is behind. A roster is
  taken only if the pinned network key signed it, so a revocation reaches every member that meets
  one that has it, with the primary offline and whatever the relay remembers.
  `roster`, `state`, `id`, `network`, `waitConnected(timeoutMs?)`, `close()`.
- `traffic()` counts what this member sent and received, always on: `{ since, total, relay, peers }`,
  where `total` and each `peers[id]` are `{ sent, received }` of `{ messages, bytes, frames, frameBytes }`.
  `messages`/`bytes` are whole application messages and their payload; `frames`/`frameBytes` are
  routed frames of every type (handshakes and credit included) at their full size, header
  included, which is what the relay charges; `relay` is the UTF-8 bytes of control messages.
  Pairing frames are not counted. `resetTraffic()` starts over. The relay keeps no per-member
  figures: each member counts its own.
- `diagnostics()` and `resetDiagnostics()`: see Diagnostics below; `undefined` while they are off.

A member reconnects after 500 ms, doubling to 10 s, forever, except after close code 4008 (it is
`revoked`) or 4005 (`replaced`: another copy of the identity connected); both are terminal. A member that registers with an older roster than the relay holds
receives the newer one in `registered` and accepts it (a `roster` event) before it is `connected`.

**The primary.** `isPrimary` says whether a member is the primary now: it holds the network seed
and its roster names it. Only then do these work (each throws `InvalidError` otherwise):
`openPairingCode({ lifetimeMs?, code? })`
returning `{ code, codeId, link, expiresAt }` (`code` chooses the code instead of a random one;
it must still be 8 Crockford characters, and a word is easier to guess than a random code), `cancelPairingCode(codeId)`,
`revoke(nodeId)` returning the new roster, `usage()`; events `paired` (`{ member, codeId, roster }`:
the new member and the code that admitted it) and `pairingFailed`. `Primary`
extends `Member` and requires `networkSeed`: `Primary.connect(options)`.
`usage()` asks the relay (request-only: the relay never pushes these figures) and resolves
`{ network: { bytesHour, connections, limits: { rateBps, quotaBytesHour, trickleBps }, quotaUsed, slowed } }`,
within a second however busy the network. The relay allows one ask per `USAGE_INTERVAL_MS`
(10 s) per network, with no burst (`USAGE_BURST` is 1); an ask sooner is refused at once and
`usage()` rejects with `RateLimitedError` (code `rate-limited`). When no further member fits under the roster limit, `openPairingCode` throws
`RosterFullError` (code `roster-full`), and a code opened earlier fails its pairing with
`pairingFailed`.

**Pairing.** `pair({ link, identity, WebSocket?, timeoutMs? })` returns
`{ roster, pinnedNetworkKey }`, or rejects with `PairingError`, `UnreachableError` (the primary is
not connected) or `TimeoutError`. Codes: `generateCode`, `normalizeCode`, `formatCode`;
pairing parameters (section 5.1): `buildPairingParams(parts)` writes
`v=1&n=…&c=…&i=…&r=…` alone, and `parsePairingParams(string)` reads it back, throwing
`InvalidError` on a missing parameter, an unknown version or a bad value. Link defines the
parameters, not a scheme: carry them as you like, in an https URL's fragment say
(`https://example.com/#${buildPairingParams(parts)}`). `buildPairingLink` and `parsePairingLink`
are one wrapping of them, `frontier://pair?<parameters>`.

## Choosing a relay

A relay operator can publish a **directory**: regions, each with a URL to time and a relay URL
template over its own number of shards (default 1), so one region can grow without the others.

```json
{ "version": 1, "regions": [
  { "id": "eu1", "name": "Europe", "probe": "https://eu1.relay.example.com/health",
    "relay": "wss://{shard}.eu1.relay.example.com/v1", "shards": 256, "accepting": true } ] }
```

When a primary creates its network, `pickRelay({ network, directory })` times every accepting
region (the fastest of three requests each, within `timeoutMs`, default 3 s), takes the closest,
and puts the network's shard into that region's template. The shard is `shardOf(network,
shards)` with that region's `shards`: the first four bytes of SHA-256 of the network id, big-endian, modulo `shards`, in
lowercase hex padded to the width of `shards - 1` (`00` to `ff` for 256). Pass the URL it returns
to `createNetwork({ relay })`, or to `placeNetwork` for a network made before it had one; the roster carries it from then on, so the directory is consulted
once, at creation, and never on reconnect. It throws when no region answers; fall back to a relay
of your own.

## Sessions in brief

- Every session starts with 1 MiB of credit each way; a larger `creditWindow` is granted as extra
  credit when the session comes up. Fragments of a message in progress are credited while the
  application has nothing waiting; complete messages when the application takes them. Credit goes
  back in batches: at once from 64 KiB owed, otherwise 250 ms after it began to be owed, so a
  stream of small messages costs about one credit frame per 64 KiB instead of one per message.
- **The socket is kept short.** Control (handshakes, `reset`, `refused`, credit and roster
  messages, relay control) is handed to the socket at once. Message fragments wait in the
  client's own queue and are encrypted only when handed over, which happens while at most 64 KiB
  waits in the socket (`bufferedAmount`, or a WebSocketStream's writes still in progress) and
  while the session's un-credited bytes are under its window: the larger of 64 KiB and one and a
  half times what the receiver credited back over the last second. A fragment is cut to the room
  left under the window (16 KiB at least), so on a slow link fragments shrink. One slow receiver
  never holds up sends to another. Wire order is still nonce order, since each fragment is
  encrypted at the moment it is sent.
- **Paced to the rate in force.** While the relay shapes the network at `rateBps` R (`shaping`
  above), fragments go at most at 7/8 of R over the whole connection, counted at their size on
  the wire, each at most a quarter of a second of that pace (3584 bytes at a 16 KB/s trickle), and
  a session keeps at most about a second of what its receiver takes un-credited, never more than
  half a second of R (spec section 11). The relay then reads a member's data as it arrives, so
  nothing lies in front of its control: a usage ask or a roster sync is answered in milliseconds
  with one member sending, and within about a second with several sending at once. Throughput
  while shaped is 7/8 of the rate; the rest is room for control.
- To a relay whose `hello` lists `control`, session messages other than application messages go
  as frame type `0x08`, which the relay keeps ahead of its shaping (spec section 9).
- A message is never split across sessions: a rekey switches at a message boundary.
- A handshake-init carries a stamp (wall-clock milliseconds, always above the last sent), and
  a member refuses an init from a peer stamped no later than the last it accepted from it, so a
  recorded init replayed by the relay or an observer changes nothing (spec section 7.1). The
  cost is in clock steps: a member whose clock steps back below a stamp a peer stored is refused
  by that peer until its clock passes it again (at most 10 minutes for an honest member: the
  relay keeps every member within 5 minutes of its own clock), and one whose clock runs more
  than 10 minutes ahead is refused until it is fixed. A restart, which in a browser is every page
  load, costs nothing by itself: stamps come from the wall clock again.
- Fragments carry at most 65517 bytes, so each transport message fits Noise's 65535 bytes.
- A data frame for a session the receiver does not hold is answered `reset`; the sender drops the
  session and its next send handshakes again. The message in that frame is lost.
- Losing the relay connection ends every session. Sends wait up to the handshake timeout for the
  connection to come back. `syncRoster()` and `resign()` repeat their request until answered.
- **A peer is held to the protocol** (spec sections 7.2 to 7.4, 11). A session ends when its peer
  sends message bytes beyond the credit granted, an empty fragment that says more follow, or a Noise
  message over 65535 bytes. Per peer, a member keeps at most 2 × 64 MiB + 4 × `creditWindow` bytes
  in reassembly or waiting for the application, 65536 waiting messages and 8 sessions. A peer gets a
  roster (asked for, or pushed after a handshake) at most once per 250 ms, and never a second while
  one is still unsent. Resets and handshake-inits come out of each id's own budget, kept across
  reconnects and measured on a monotonic clock; a member id whose inits keep failing is silenced
  alone; pairing channel setups per open code are budgeted; `relayError` and `pairingFailed` events
  are rate-limited. More than 64 MiB unsent in the socket drops the connection, which reconnects.
  Every JSON document read from the relay or a peer is parsed strictly: a repeated name, a lone
  surrogate, more than 32 levels of nesting, or a `version`, `issuedAt` or `ts` not written as
  digits only (`12`, never `12.0` or `-0`) makes it invalid.

## Rules for apps on Link

The relay's bandwidth is the scarce resource, and every byte is relayed (and charged) in both
directions. These rules keep an application lean; the diagnostics below check them while it runs.

1. **Send raw bytes.** Never base64, hex or bytes inside JSON: they add 33% and 100% to every
   relayed byte.
2. **No JSON headers on hot paths.** Anything sent more than 10 times a second to a peer gets a
   small fixed binary header (cursor 9 bytes instead of 33, audio 15 instead of 70).
3. **Batch tiny messages.** Merge what one tick sends to one peer into one message: each message
   costs 40 bytes of Link framing, a WebSocket frame and a relayed frame.
4. **Compress only large, text-like content you wrote yourself**, one message at a time (1 KiB or
   more; never media, audio or anything already compressed, which deflate makes bigger), and
   never put a secret in the same message as data a peer controls: the relay sees every
   ciphertext length, and compression turns content into length (CRIME, BREACH). Use
   `deflate`/`inflate` from `@frontierengineer/link-client/compression`.
5. **Respect back-pressure.** Await `send`; when it lags, shed load (skip to the next keyframe)
   rather than queue.
6. **Ask for usage rarely, and send less when slowed.** Keep the last answer. Watch the `shaping`
   event (or read `shaping`) rather than asking: when it says `slowed`, drop video and keep audio,
   and tell your peers over your own messages.
7. **Don't hammer unreachable peers.** A send to an absent peer fails at once and nothing is
   queued; wait for it to come back instead of retrying in a loop.
8. **One live member per identity.** A second copy replaces the first (4005), and recreating
   members or sessions costs a registration or a handshake each time.

## Compression

`@frontierengineer/link-client/compression` exports `deflate(bytes)` and `inflate(bytes, maxBytes?)`:
deflate-raw through the platform's `CompressionStream`, a fresh context per call. `deflate`
rejects inputs under `MIN_COMPRESS_BYTES` (1 KiB). `inflate` stops and rejects once its output
passes `maxBytes` (default 64 MiB), so a small message cannot expand without bound. Mark
compressed messages yourself (a bit in your own header); the library does not.

## Diagnostics

`@frontierengineer/link-client/diagnostics` checks the rules at run time. A bundle that never
imports it carries none of its code, and with it off the core does one branch per send and
receive.

```ts
import { enableDiagnostics } from '@frontierengineer/link-client/diagnostics';

const off = enableDiagnostics(member, {
  mode: 'throw',                        // 'count' (default) | 'warn' | 'throw'
  sample: 1 / 16,                       // share of large messages screened for compressibility
  accept: { compressibleUncompressed: 'mixes peer data with a secret' }, // or false to mute
  onFinding: (f) => log(f),             // once per kind, then each time its count doubles
});
const report = member.diagnostics();    // counts per kind, sizes, high-water marks; never payloads
expect(Object.values(report.counts).every((n) => n === 0)).toBe(true);
member.resetDiagnostics();
off();
```

`warn` logs once per kind with the call site. In `throw` mode the offending `send` rejects with
`DiagnosticFindingError` before anything is sent; a finding made off the send path (a refused
usage ask, churn, a compression that gained nothing) fails the next `send`.

| Kind | Rule | Found when |
|---|---|---|
| `textEncodedBinary` | 1 | a message of 64 bytes or more is base64, base64url or hex text |
| `base64InJson` | 1 | a JSON message carries a base64 or hex string of 64 characters or more |
| `hotJsonHeaders` | 2 | over 10 messages a second to a peer, each more than a quarter JSON header |
| `tinyBatchable` | 3 | messages under 128 bytes to one peer less than 40 ms apart, over 5 a second for 3 s |
| `compressibleUncompressed` | 4 | sampled messages over 1 KiB under 7 bits per byte (confirmed with a real deflate at most once a second) add up to over 5% of bytes sent |
| `compressedNoGain` | 4 | `deflate` saved under 10% |
| `backlog` | 5 | a message of 64 KiB or less waited over 2 s to be handed over |
| `usageAsks` | 6 | an ask came within 12.5 s of the last (the relay allows one per 10 s), or was refused |
| `sentWhileSlowed` | 6 | more bytes sent since the network was slowed (a `shaping` notice, or a `slowed` usage answer) than its whole trickle rate allows |
| `unreachableRetries` | 7 | over 6 sends a minute to one unreachable peer |
| `sessionChurn` | 8 | over 3 handshakes with one peer within one rekey interval, over 3 reconnects a minute, or any 4005 |

The report also carries `findings.credits.sentPerMessageReceived`, the library's own check that
credit is batched (well under 0.1 on bulk traffic), and the high-water marks of un-credited bytes,
socket backlog and bytes queued ahead of a control message. It stays in the process: nothing is
sent anywhere.

## Develop

```sh
npm install
npm run typecheck
npm test          # unit, vector and integration tests (an in-process test relay in test/support/)
npm run build     # dist/ with .d.ts
npm run vectors   # rewrite ../spec/vectors/client.json; the tests fail if it is stale
(cd scripts/check-vectors-go && go run .)   # independent check of the vectors in Go
```
