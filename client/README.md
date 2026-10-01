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
| `WebSocket` | a WHATWG WebSocket constructor; defaults to `globalThis.WebSocket` |
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

A member reconnects after 500 ms, doubling to 10 s, forever, except after close code 4008 (it is
`revoked`) or 4005 (`replaced`: another copy of the identity connected); both are terminal. A member that registers with an older roster than the relay holds
receives the newer one in `registered` and accepts it (a `roster` event) before it is `connected`.

**`Primary`** extends `Member`: `Primary.connect(options)`, `openPairingCode(kind, { lifetimeMs? })`
returning `{ code, codeId, kind, link, expiresAt }`, `cancelPairingCode(codeId)`,
`revoke(nodeId)` returning the new roster, `usage()`. Extra events: `usageAlert`, `paired`,
`pairingFailed`. When no further member fits under the roster limit, `openPairingCode` throws
`RosterFullError` (code `roster-full`), and a code opened earlier fails its pairing with
`pairingFailed`.

**Pairing.** `pair({ link, identity, WebSocket?, timeoutMs? })` returns
`{ roster, pinnedPrimary }`, or rejects with `PairingError`, `UnreachableError` (the primary is
not connected) or `TimeoutError`. Codes: `generateCode`, `normalizeCode`, `formatCode`;
links: `buildPairingLink`, `parsePairingLink`.

## Sessions in brief

- Every session starts with 1 MiB of credit each way; a larger `creditWindow` is granted as extra
  credit when the session comes up. Fragments of a message in progress are credited at once while
  the application has nothing waiting; complete messages when the application takes them.
- A message is never split across sessions: a rekey switches at a message boundary.
- Fragments carry at most 65517 bytes, so each transport message fits Noise's 65535 bytes.
- A data frame for a session the receiver does not hold is answered `reset`; the sender drops the
  session and its next send handshakes again. The message in that frame is lost.
- Losing the relay connection ends every session. Sends wait up to the handshake timeout for the
  connection to come back. `syncRoster()` and `resign()` repeat their request until answered.

## Develop

```sh
npm install
npm run typecheck
npm test          # unit, vector and integration tests (an in-process test relay in test/support/)
npm run build     # dist/ with .d.ts
npm run vectors   # rewrite ../spec/vectors/client.json; the tests fail if it is stale
(cd scripts/check-vectors-go && go run .)   # independent check of the vectors in Go
```
