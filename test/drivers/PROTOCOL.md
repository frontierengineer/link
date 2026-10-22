# The driver protocol

Every client implementation ships a **driver**: a small program that runs one node of a Link
network and is steered over stdin and stdout. The cross-implementation suite in `test/` starts
drivers of any implementation side by side on a real relay, so the same scenarios prove that
the TypeScript, Go and Rust clients pair, talk and fail with one another identically.

A driver is test equipment only. It is never part of a published package's public API. This
document is the whole contract: a driver is written from it and `spec/protocol.md` (the wire
protocol, cited below as "spec section N"), with no need to read another implementation.

## Framing

- One JSON object per line, UTF-8, `\n`-terminated, on stdin (commands) and stdout (replies and
  events). Nothing else is written to stdout; logs go to stderr.
- Payload bytes inside the driver protocol (`seed`, `networkSeed`, `bytes`) are standard base64
  (with padding). This is the test harness, not the wire: Link itself never carries base64.
- Keys (`ed25519`, `pinnedNetworkKey`) are written exactly as a roster writes them: unpadded
  base64url, so they compare equal to the roster's own fields. Node ids are the roster's form too.
- The driver handles commands concurrently: a slow command (`connect`, `pair`, `send`, `take`)
  never blocks a later one. Replies may therefore arrive out of order; `id` matches them up.
- Replies and events are written in the order the node produced them: an event raised before a
  command completed is written before that command's reply.
- A line that is not a JSON object with an integer `id` and a string `cmd` gets no reply; the
  driver logs it to stderr and goes on.
- The driver exits 0 when stdin closes, after closing its node, and after `exit` (below).
  Commands still running then get no reply.

## Lifecycle

A driver holds at most one identity and at most one node at a time.

1. `identity` sets the identity that `createNetwork`, `pair`, `connect` and `start` use. It may be
   called again at any time; a running node keeps the identity it started with.
2. `createNetwork` (a primary) or `pair` (a newcomer) yields a roster, and `createNetwork` a
   network seed too. Neither starts a node.
3. `connect` or `start` creates the node and connects it to the relay. While a node exists that
   is not `closed`, another `connect` or `start` fails `invalid`. After `close` (which closes a
   `revoked` or `replaced` node too) they create a new node: no sessions, traffic counted afresh.
4. Every other command acts on the node, and fails `invalid` when there is none.

## Commands and replies

A command is `{"id": <integer>, "cmd": "<name>", ...arguments}`. No result or argument field is
ever named `id`: that name is the command's alone, and a reply's `id` is always the command's.
Its reply is `{"id": <same>, "ok": true, ...result}` or
`{"id": <same>, "ok": false, "error": {"code": "<code>", "message": "<text>"}}`. An error with code
`refused` also carries `"reason": <integer>`, the refusal's reason byte (spec section 6; `1`: the
peer's roster does not list this node).

| Command | Arguments | Result |
|---|---|---|
| `identity` | `seed?` (base64, 32 bytes; random when absent) | `seed`, `node` (the node id), `ed25519` |
| `createNetwork` | `relay` (URL) | `roster`: version 1, this identity alone as primary, signed with a network key minted for it; `networkSeed` (base64, 32 bytes) |
| `pair` | `link`, or `network`+`code`+`codeId`+`relay`; `timeoutMs?` (default 60000, the whole exchange) | `roster`, `pinnedNetworkKey` (`roster.networkKey`) |
| `connect` | `role` (`member` or `primary`), `roster`, `networkSeed?` (base64), `pinnedNetworkKey?`, `relayUrl?`, `creditWindow?`, `timing?`, `autoTake?` (default `true`), `timeoutMs?` | `{}` once registered |
| `start` | as `connect`, without `timeoutMs` | `{}` at once; the node connects in the background |
| `waitConnected` | `timeoutMs?` | `{}` once registered |
| `state` | | `state`, `roster` (the newest held), `primary` (whether this node acts as the primary now), `shaping` (below) |
| `sessions` | `peer?` | `sessions`: the sessions held, below |
| `send` | `peer`, and `bytes` (base64) or `size`+`fill` (see below) | `{}` once every fragment is handed to the relay connection |
| `take` | `count` (default 1), `timeoutMs?` | `messages`: the taken messages, as `message` event bodies |
| `syncRoster` | | `roster`, once the primary answered (newer or not) |
| `resign` | | `{}` once the relay closed this node (`revoked`) |
| `traffic` | | the traffic report, below |
| `resetTraffic` | | `{}` |
| `openPairingCode` | `lifetimeMs?` (default 900000), `code?` | `code`, `codeId`, `link`, `expiresAt` |
| `cancelPairingCode` | `codeId` | `{}` |
| `revoke` | `node` | `roster`: the new roster, already published |
| `usage` | | the usage report, below |
| `close` | | `{}`; the node stops and does not reconnect |
| `exit` | | `{}`, then the driver closes its node and exits 0 |

**Primary only:** `openPairingCode`, `cancelPairingCode`, `revoke` and `usage` fail `invalid` on a
node that is not the primary now: one that does not hold the network seed, or whose roster names
another member primary. `resign` fails `invalid` on the primary and on a node started with
`networkSeed`; `syncRoster` on the primary answers its own roster at once.

**A node started with `networkSeed`** whose roster names another member primary claims the
primary once registered (spec section 3.1): it publishes the next roster, naming itself
`primary`, nothing else changed, and raises a `roster` event for it. A node whose roster stops
naming it primary stops acting as the primary in place, and stays connected.

**`connect` and `waitConnected`** resolve once the node is registered. They reject with
`revoked`, `replaced` or `closed` as soon as the node reaches that terminal state, and with
`timeout` once `timeoutMs` passes (none by default). After a timeout the node keeps trying;
`close` stops it.

**`connect`/`start` arguments.** `roster` must be valid and list this identity, and
`pinnedNetworkKey` (default `roster.networkKey`) must equal `roster.networkKey`; otherwise
`invalid`. `networkSeed`, when given, must derive `roster.networkKey` (`invalid` otherwise).
`relayUrl` defaults to `roster.relay`. `role: "primary"` requires `networkSeed` (`invalid`
otherwise); the node is then the primary, claiming it when the roster names another (above).
`creditWindow` is the receive window granted per session, an integer from 1048576 (the initial credit, the default) to 2^32 − 1; more than the
initial credit is granted as extra credit when a session comes up (spec section 7.3).

**`timing`**, every field in milliseconds except `rekeyMessages`; an omitted field keeps its
default:

| Field | Meaning | Default |
|---|---|---|
| `handshakeTimeoutMs` | how long a handshake message is awaited | 10000 |
| `rekeyIntervalMs` | an initiator rekeys a session this old | 600000 |
| `rekeyMessages` | ...or one that carried this many transport messages in either direction | 4294967296 |
| `retireGraceMs` | a replaced session's keys are kept this long; a responder expires a session older than `rekeyIntervalMs + retireGraceMs` | 30000 |
| `idleMs` | a session with no frame either way this long is forgotten | 600000 |
| `backoffInitialMs` | the first reconnect delay, doubling... | 500 |
| `backoffMaxMs` | ...up to this | 10000 |
| `requestTimeoutMs` | how long `syncRoster`, `resign` and `usage` wait for an answer | 10000 |

**`send`.** `peer` is a node id. The payload is 0 to 67108864 bytes (64 MiB); an empty message is
allowed and arrives as one. `size`+`fill` sends `size` bytes where byte `i` is
`(fill + i * 31) mod 256` (`fill` a non-negative integer), so a several-MiB message needs no
several-MiB command line. Failures: `unreachable` (the relay says the peer is not connected;
nothing is queued), `refused` (with `reason`), `invalid` (the peer is not on this node's roster,
is this node, or the payload is over 64 MiB), `revoked`, `replaced`, `closed`, `timeout`.

**`take`** is allowed only with `autoTake: false` (`invalid` otherwise). It waits until `count`
messages are waiting, then takes them, oldest first, and so credits them back to their senders.
With `timeoutMs`, it fails `timeout` once that passes and takes nothing. If the node reaches a
terminal state first, it fails with that state (`revoked`, `replaced` or `closed`).

**`sessions`** lists the established sessions this node holds, with every peer or with `peer`
alone: `[{"peer": "<node id>", "localIndex": <u32>, "remoteIndex": <u32>, "initiator": <bool>,
"current": <bool>}]`, in no particular order. `localIndex` is the index this node chose (data
frames to it name it), `remoteIndex` the peer's. `initiator` is true when this node sent the
handshake-init. `current` marks the one session per peer that new messages use; the others are
replaced sessions kept for their grace (spec section 7.2). A handshake still in progress is not
listed. So for a session both sides hold, one side's `localIndex` is the other's `remoteIndex`.

**`openPairingCode`.** A code admits one node. `code` chooses the code instead of a random one:
8 Crockford base32 characters in any spelling spec section 5.1 accepts (`invalid` otherwise). The result's `code` is the display form `XXXX-XXXX`, `codeId` the code id (b64u),
`link` the pairing link (spec section 5.1), `expiresAt` Unix milliseconds. When no further
member fits under the roster limit it fails `roster-full`.

**`revoke`** fails `invalid` for the primary itself or a node not on the roster.

**`usage`** asks the relay (spec section 4.3) and answers its report:
`{"network": {"bytesHour", "connections", "limits": {"rateBps", "quotaBytesHour", "trickleBps"},
"quotaUsed", "slowed"}}`, exactly those fields, as the relay sent them. Refused over the relay's
budget (one ask per 10 seconds per network, no burst): `rate-limited`, at once. No answer within
`requestTimeoutMs`: `timeout`.

**`shaping`** in the `state` result is the node's shaping property (spec section 11):
`{"rateBps": <integer>, "slowed": <bool>}`, from the relay's last `shaping` notice; `{"rateBps": 0,
"slowed": false}` before any, and after registering with a relay whose `hello` does not list
`shaping`. The node paces its sends to `rateBps` (spec section 11) whatever the driver does.

### Error codes

| Code | When |
|---|---|
| `unreachable` | the peer (or, for `pair`, the network's primary) is not connected |
| `refused` | the peer refused this node; `reason` gives why |
| `revoked` | this node is no longer a member (close code 4008, or a roster without it) |
| `replaced` | a newer connection of this identity took over (close code 4005) |
| `timeout` | a wait ran out: `timeoutMs`, a handshake, or a relay request |
| `closed` | the node was closed, or a session ended under the operation |
| `pairing` | pairing failed: wrong, burned, expired, cancelled or used code, the primary ended it, or the relay closed the channel |
| `invalid` | a bad argument, a missing prerequisite (no identity, no node, a node already running), a primary-only command on a member, `take` with `autoTake`, an unknown peer |
| `roster-full` | `openPairingCode` with no room left on the roster |
| `rate-limited` | `usage` over the relay's budget |
| `internal` | an unknown command, or anything else the driver itself could not do |

## Events

An event is `{"event": "<name>", ...body}`, written whenever the node raises it:

| Event | Body |
|---|---|
| `state` | `state`: `connecting`, `connected`, `disconnected`, `revoked`, `replaced`, `closed` |
| `roster` | `roster` (each accepted roster) |
| `disconnect` | `code`, `reason`: the relay connection closed, with its close code and reason (`""` when none) |
| `moved` | `network`: the relay closed the connection 4009; the node reconnects to the same relay URL |
| `message` | `from`, `size`, `sha256` (hex of the payload), and `bytes` (base64) when `size` is 65536 or less |
| `paired` | `node`, `codeId` (the code that admitted it), `version` (the new roster's) (primary only) |
| `pairingFailed` | `codeId`, `reason`: a code from the table below (primary only) |
| `relayError` | `code`, `message` (`""` when the relay sent none): a non-fatal `error` control message the node did not consume itself |
| `shaping` | `rateBps`, `slowed`: the node's shaping property changed (a `shaping` notice from the relay that differs from the last, or the reset at registration with a relay without the feature); raised only on a change |

**`state`.** A node raises `connecting` as it dials, `connected` once registered, `disconnected`
when the connection drops and it will retry, and the terminal `revoked`, `replaced` and
`closed`. A state is raised only when it changes. After close code 4008 or 4005 the only `state`
event is the terminal one, `revoked` or `replaced`: no `disconnected` before it and nothing after
it (a later `close` command raises `closed`). The `disconnect` event for the close comes before
its `state` event. A roster accepted without this node also ends in `revoked`.

**`message`.** Messages from one sender are raised in the order sent. With `autoTake` the message
is taken as it arrives, which is what credits it back to its sender; without it the event is
still raised on arrival, and the message stays untaken until a `take`.

**`pairingFailed` reasons:**

| `reason` | The pairing attempt ended because |
|---|---|
| `wrong-code` | the newcomer's confirmation did not verify (a failed attempt; five burn the code) |
| `malformed` | a pairing message was malformed (counts as a failed attempt, spec section 5.1) |
| `unknown-code` | no open code has that id: never opened, expired, cancelled, used, or burned |
| `used` | another newcomer has already confirmed this code |
| `no-attempts` | the code is open, but its five attempts are all failed or in flight |
| `newcomer-left` | the relay ended the channel (`pairEnd`): the newcomer left or the relay timed out |
| `timeout` | the primary's own 60-second limit on the channel ran out |
| `relay-lost` | the primary's relay connection dropped mid-pairing |
| `demoted` | the primary stopped being the primary mid-pairing: a newer roster names another (spec section 3.1) |
| `already-member` | the newcomer's key is already on the roster |
| `roster-full` | the roster has no room for the newcomer |

## The traffic report

`traffic` counts what this node sent and received since the node was created or since the last
`resetTraffic`, always on:

```json
{"since": 1790000000000,
 "total": {"sent": T, "received": T},
 "relay": {"sent": 0, "received": 0},
 "peers": {"<node id>": {"sent": T, "received": T}}}
```

where each `T` is `{"messages", "bytes", "frames", "frameBytes"}`, and `total` is the sum over
`peers`.

- `since`: Unix milliseconds the counts start from.
- `messages` and `bytes`: whole application messages and their payload bytes. A sent message
  counts once `send` succeeds; a received one on arrival, taken or not. A message counts once,
  however many fragments it took.
- `frames` and `frameBytes`: routed frames (spec section 6) of every type, at their full size,
  the 18-byte header included: what the relay charges. A sent frame counts when handed to the
  relay connection, under the peer it names; a received frame counts under the peer the relay
  named in it, including `unreachable` (`0x04`) frames from the relay itself. `pair` frames are
  never counted.
- `relay`: UTF-8 bytes of the text control messages this node exchanged with the relay over its
  member connections (`hello`, `register` and `registered` included). Pairing connections are not
  counted.
- `resetTraffic` zeroes every count, sets `since` to now, and empties `peers`.

Frame sizes, header included (`n` the payload of one fragment, at most 65517 bytes):

| Frame | Bytes |
|---|---|
| data or control (`0x03`, `0x08`) carrying a `message` fragment | 40 + n |
| data or control carrying `credit` | 43 |
| handshake-init (`0x01`) | 134 |
| handshake-resp (`0x02`) | 82 |
| reset (`0x07`) | 22 |
| refused (`0x05`) | 19 |
| unreachable (`0x04`) | 18 |

(A data body is a 4-byte index and the ciphertext: the plaintext's type byte, its contents, and
a 16-byte tag. The handshake-init payload is the 8-byte roster version and the 8-byte stamp; the
handshake-resp payload is the 8-byte roster version.)

## Running a driver

The suite finds each driver through an environment variable holding a command line. It splits
the line on whitespace; single or double quotes group text that contains whitespace (without
escapes, and with no shell expansion). Every driver runs with `test/` as its working directory.

- `LINK_DRIVER_TS`: default `node --import tsx drivers/typescript.ts`.
- `LINK_DRIVER_GO`: default: `go build -o <temporary directory>/link-driver ./cmd/link-driver`
  in `client-go/`, then run that.
- `LINK_DRIVER_RUST`: default: `cargo build --release --bin link-driver --message-format=json`
  in `client-rust/`, then run the `executable` of the `compiler-artifact` message whose target
  is named `link-driver` (so `CARGO_TARGET_DIR` and workspaces need nothing more).

A driver whose directory does not exist or whose build fails is skipped with the reason, unless
`LINK_REQUIRE_DRIVERS` (a comma list such as `go,rust`) names it. `LINK_DRIVERS` limits which
implementations run (default all three).
