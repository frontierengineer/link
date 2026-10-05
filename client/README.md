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

// The primary: create the network once, then persist the seed and the roster.
const me = createIdentity();                                   // me.seed: 32 secret bytes
const roster = createNetwork({ identity: me, relay: 'wss://eu.frontierengineer.link/v1' });
const primary = await Primary.connect({ identity: me, roster });
primary.on('roster', (r) => save(r));                         // every accepted roster: persist it

// Invite a node. Show the code or the link; it admits one node for 15 minutes.
const { code, codeId, link, expiresAt } = primary.openPairingCode('worker'); // or 'surface', 'mcp'

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

**Rosters.** `createNetwork({ identity, relay })` makes version 1 with the primary alone.
`rosterProblem(r)` returns why a roster is invalid, or `null`; `acceptanceProblem(r, pinned, held)`
applies the acceptance rule; `canonicalize(value)` is RFC 8785 JCS. A roster's JCS encoding,
signature included, is at most `MAX_ROSTER_BYTES` (65000 bytes, about 400 members; `rosterSize(r)`
measures it), so it always fits one session message; a larger one is invalid.

**`Member`** (`Member.connect(options)` resolves once registered; `new Member(options)` starts
connecting and returns at once):

| Option | |
|---|---|
| `identity`, `roster` | required; the newest roster held |
| `relayUrl` | defaults to `roster.relay` |
| `pinnedPrimary` | defaults to `roster.primary.ed25519` |
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
  (`{ code, reason }`), `moved` (4009), `relayError`.
- `syncRoster()` asks the primary for its newest roster. `resign()` leaves the network.
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

**`Primary`** extends `Member`: `Primary.connect(options)`, `openPairingCode(kind, { lifetimeMs?, code? })`
returning `{ code, codeId, kind, link, expiresAt }` (`code` chooses the code instead of a random one;
it must still be 8 Crockford characters, and a word is easier to guess than a random code), `cancelPairingCode(codeId)`,
`revoke(nodeId)` returning the new roster, `usage()`. Extra events: `paired`, `pairingFailed`.
`usage()` asks the relay (request-only: the relay never pushes) and resolves
`{ network: { bytesHour, connections, limits: { rateBps, quotaBytesHour, trickleBps }, quotaUsed, slowed } }`.
The relay allows `USAGE_BURST` (3) asks at once, then one per `USAGE_INTERVAL_MS` (10 s), per
network; beyond that it refuses and `usage()` rejects with `RateLimitedError` (code `rate-limited`). When no further member fits under the roster limit, `openPairingCode` throws
`RosterFullError` (code `roster-full`), and a code opened earlier fails its pairing with
`pairingFailed`.

**Pairing.** `pair({ link, identity, WebSocket?, timeoutMs? })` returns
`{ roster, pinnedPrimary }`, or rejects with `PairingError`, `UnreachableError` (the primary is
not connected) or `TimeoutError`. Codes: `generateCode`, `normalizeCode`, `formatCode`;
links: `buildPairingLink`, `parsePairingLink`.

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
  while the session's un-credited bytes are under its pace: the larger of 64 KiB and one and a
  half times what the receiver credited back over the last second. A fragment is cut to the room
  left under the pace (16 KiB at least), so on a slow link fragments shrink. So control is never stuck behind megabytes of
  data, even when the relay is shaping, and one slow receiver never holds up sends to another.
  Wire order is still nonce order, since each fragment is encrypted at the moment it is sent.
- To a relay whose `hello` lists `control`, session messages other than application messages go
  as frame type `0x08`, which the relay keeps ahead of its shaping (spec section 9).
- A message is never split across sessions: a rekey switches at a message boundary.
- Fragments carry at most 65517 bytes, so each transport message fits Noise's 65535 bytes.
- A data frame for a session the receiver does not hold is answered `reset`; the sender drops the
  session and its next send handshakes again. The message in that frame is lost.
- Losing the relay connection ends every session. Sends wait up to the handshake timeout for the
  connection to come back. `syncRoster()` and `resign()` repeat their request until answered.

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
6. **Ask for usage rarely, and send less when slowed.** Keep the last answer. When it says
   `slowed`, drop video and keep audio, and tell your peers over your own messages.
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
| `usageAsks` | 6 | an ask used 80% of the relay's budget, or was refused |
| `sentWhileSlowed` | 6 | more bytes sent since a `slowed` answer than the network's whole trickle rate allows |
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
