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
applies the acceptance rule; `canonicalize(value)` is RFC 8785 JCS.

**`Member`** (`Member.connect(options)` resolves once registered; `new Member(options)` starts
connecting and returns at once):

| Option | |
|---|---|
| `identity`, `roster` | required; the newest roster held |
| `relayUrl` | defaults to `roster.relay` |
| `pinnedPrimary` | defaults to `roster.primary.ed25519` |
| `WebSocket` | a WHATWG WebSocket constructor; defaults to `globalThis.WebSocket` |
| `creditWindow` | bytes in flight per session and direction, default 1 MiB |
| `resolveRelay(network)` | called on close code 4009; may return a new relay URL |
| `timing` | overrides for the protocol timers (rekey, idle, handshake timeout, backoff), for tests |

- `send(peerId, bytes)` resolves once every fragment is handed to the relay connection. It
  rejects with a `LinkError` whose `code` is `unreachable` (the peer is not connected; nothing is
  queued), `refused` (the peer's roster does not list this node), `revoked`, `timeout`,
  `closed`, or `invalid` (unknown peer, over 64 MiB).
- `onMessage(handler)` or the async iterator `messages` deliver `{ from, bytes }` whole and in
  order per sender. A message is credited back to its sender when the application takes it, so a
  slow reader slows its senders.
- Events (`on(name, listener)` returns an unsubscribe function): `state`
  (`connecting`, `connected`, `disconnected`, `revoked`, `closed`), `roster`, `disconnect`
  (`{ code, reason }`), `moved` (4009), `relayError`.
- `syncRoster()` asks the primary for its newest roster. `resign()` leaves the network.
  `roster`, `state`, `id`, `network`, `waitConnected(timeoutMs?)`, `close()`.

A member reconnects after 500 ms, doubling to 10 s, forever, except after close code 4008: then it
is `revoked`, a terminal state. A member that registers with an older roster than the relay holds
receives the newer one in `registered` and accepts it (a `roster` event) before it is `connected`.

**`Primary`** extends `Member`: `Primary.connect(options)`, `openPairingCode(kind, { lifetimeMs? })`
returning `{ code, codeId, kind, link, expiresAt }`, `cancelPairingCode(codeId)`,
`revoke(nodeId)` returning the new roster, `usage()`. Extra events: `usageAlert`, `paired`,
`pairingFailed`.

**Pairing.** `pair({ link, identity, WebSocket?, timeoutMs? })` returns
`{ roster, pinnedPrimary }`, or rejects with `PairingError`, `UnreachableError` (the primary is
not connected) or `TimeoutError`. Codes: `generateCode`, `normalizeCode`, `formatCode`;
links: `buildPairingLink`, `parsePairingLink`.

## Behaviour the spec leaves open

- **Credit.** Credit and reassembly belong to one Noise session. A sender starts with its own
  `creditWindow` as the credit it holds, so the members of a network should use the same value. A
  receiver credits fragments of a message in progress at once while its application has nothing
  waiting (so messages larger than the window can complete) and credits complete messages when
  the application takes them.
- **Rekeying** switches to the new session at a message boundary. A message under way finishes on
  the session it started on, which stays alive past the 30 s grace for as long as it is in use.
- **Fragment size.** At most 65517 message bytes per fragment, so every transport message fits
  Noise's 65535-byte limit. Larger ciphertexts from other implementations are accepted.
- **Lost session state.** A data frame for an unknown receiver index makes the receiver open a
  new session to the sender, which adopts it for its next message. The frame itself is lost:
  delivery is at most once.
- **The relay connection** dropping ends every session. Sends wait up to the handshake timeout
  for the connection to come back.

## Develop

```sh
npm install
npm run typecheck
npm test          # unit, vector and integration tests (an in-process test relay in test/support/)
npm run build     # dist/ with .d.ts
npm run vectors   # rewrite ../spec/vectors/client.json; the tests fail if it is stale
```
