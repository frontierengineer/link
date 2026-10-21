# link-client (Rust)

The Rust client for Link, protocol version 1 ([`spec/protocol.md`](../spec/protocol.md)). It does
everything a member needs: keys, signed rosters, pairing with a short code (SPAKE2), and
end-to-end encrypted sessions (Noise IK) over one outbound WebSocket to a relay that only routes.
It behaves as the TypeScript client ([`client-typescript/`](../client-typescript/README.md)) does, and passes the same
vectors.

Edition 2024, async on tokio. `ws://` and `wss://` (rustls with ring, Mozilla's roots from
`webpki-roots`). No `unsafe`. Ed25519 is verified strictly, by the rule every implementation
shares: `A` and `R` canonical encodings (`y < p`, no `x = 0` with the sign bit set), neither one
of the 8 small-order points, `S < L`, and the cofactorless equation `[S]B = R + [k]A`.

## Use

```rust
use link_client::*;

// The primary: create the network once, then persist both seeds and the roster.
let me = Identity::generate();                                  // me.seed(): 32 secret bytes
let (roster, network_key) = create_network(&me, "wss://frontierengineer.link/v1", unix_ms())?;
let mut opts = MemberOptions::new(me, roster);
opts.network_seed = Some(*network_key.seed());                  // the network's own 32 secret bytes
let primary = Primary::connect(opts).await?;
let mut events = primary.events();                              // Event::Roster(r): persist r

// Invite a node. Show the code or the link; it admits one node for 15 minutes.
let code = primary.open_pairing_code(CodeOptions::default())?;

// The newcomer: pair once, then connect as a member from then on.
let id = Identity::from_seed(&saved_seed);
let paired = pair(PairOptions { target: PairTarget::Link(code.link), identity: id.clone(), timeout: None }).await?;
let member = Member::connect(MemberOptions::new(id, paired.roster)).await?;

member.send(&peer_id, bytes).await?;                           // up to 64 MiB
while let Some(InboundMessage { from, bytes }) = member.recv().await { /* ... */ }
member.close();
```

## API

**Identity.** `Identity::generate()`, `Identity::from_seed(&seed)`: `seed()`, `id()`,
`ed25519_public()`, `x25519_public()`, `sign(msg)`. Persist the seed; everything else derives
from it (section 2). Secrets are zeroised on drop and never printed by `Debug`.

**Network key.** A network has a seed of its own, minted once when it is created, apart from
every node's (section 2): `NetworkKey::generate()`, `NetworkKey::from_seed(&seed)`: `seed()`,
`id()` (the network id, derived from the network key, whichever node is primary),
`ed25519_public()`, `sign(msg)`. It signs every roster; only the primary holds it. Its seed is
zeroised on drop and never printed by `Debug`.

**Rosters.** `create_network(&identity, relay, now_ms)` mints a network key and returns it with
version 1, `identity` alone as the primary; `create_network_with(&identity, &network_key, relay,
now_ms)` takes a key already minted. `roster.network_key()` / `network_key_b64u()` is
`networkKey`, what a member pins; `roster.primary_id()` is `primary`, the node id of the
member holding the network seed, and `roster.primary()` that member. Members carry `id`,
`ed25519` and `x25519` (`RosterMember::new(ed25519, x25519)`, `RosterMember::from_identity(&id)`);
a field the protocol does not define is signed over and otherwise ignored.
A `Roster` is always valid: `Roster::parse(text)` and `Roster::from_json(json)` check every rule of
section 3, signature included, and keep the JSON as signed (members a later version adds
included). `roster_problem(&json)` says why a value is not a valid roster;
`acceptance_problem(&json, pinned, held)` applies the acceptance rule; `Json::canonicalize()` is
RFC 8785 JCS. A roster's JCS encoding is at most `MAX_ROSTER_BYTES` (65000). Every JSON document is
parsed as I-JSON (spec section 1): duplicate names, lone surrogates and nesting deeper than 32
levels are refused, and `version`, `issuedAt` and `ts` must be integer literals (`12`, not
`12.0` or `1.2e1`).

**`Member`** (`Member::connect(opts)` resolves once registered; `Member::new(opts)` starts
connecting and returns at once; both need a tokio runtime). A `Member` is a cheap handle: clone
it freely; the member closes when the last clone is dropped.

| `MemberOptions` | |
|---|---|
| `identity`, `roster` | required; the newest roster held (`MemberOptions::new(identity, roster)`) |
| `relay_url` | defaults to the roster's `relay` |
| `pinned_network_key` | defaults to the roster's `networkKey` |
| `network_seed` | the network seed, for a node that is to be the primary; it must derive the roster's `networkKey`. Its custody is the caller's: the client never stores, sends or deletes it |
| `credit_window` | the receive window granted per session: 1 MiB (every session's initial credit) up to 2^32 - 1, granted as extra credit |
| `timing` | the protocol timers (rekey, idle, handshake timeout, backoff, request timeout), for tests |
| `resolve_relay` | called on close code 4009 with the network id; may return a new relay URL |
| `observer` | an `Observer` (`Arc<dyn Fn(&Observed)>`) called with every event and every arriving message, in order, as they happen, from creation; it must be quick and must not call back into the member |

- `send(peer, bytes)` resolves once every fragment is handed to the relay connection. It fails
  with a `LinkError` whose `code()` is `Unreachable` (the peer is not connected; nothing is
  queued), `Refused` (the peer's roster does not list this node), `Revoked`, `Replaced`,
  `Timeout`, `Closed`, or `Invalid` (unknown peer, over 64 MiB). Delivery is at most once.
  `ErrorCode::as_str()` spells the codes as the TypeScript client does (`rate-limited`, ...).
- `recv()` takes the next message, whole and in order per sender; `try_recv()` does not wait;
  `recv_many(n)` waits until `n` are waiting and takes them together. A message is credited back
  to its sender when taken, so a slow reader slows its senders.
- `events()` streams `Event`s: `State` (`Connecting`, `Connected`, `Disconnected`, `Revoked`,
  `Replaced`, `Closed`), `Roster` (persist it), `Disconnect { code, reason }`, `Moved` (4009),
  `RelayError`, and for the primary `Paired { member, code_id, roster }` (the new member, the
  code it paired with, the roster that lists it) and `PairingFailed` (with a `PairingFailure`
  reason: `wrong-code`, `malformed`, `unknown-code`, `used`, `no-attempts`, `newcomer-left`,
  `timeout`, `relay-lost`, `already-member`, `roster-full`, and `demoted`, when a newer roster
  names another member primary). The first call sees every event since creation; later calls see events from then on. `observe()` streams events and
  arriving messages together, in order, without taking the messages; it holds at most 1024 items,
  dropping its oldest past that and saying how many with `Observed::Lagged(n)`.
- `sync_roster()` asks the primary for its newest roster. `resign()` leaves the network. Rosters
  also spread member to member: when a handshake shows a peer holds a newer roster, the member
  asks that peer for it, and hands its own to a peer that is behind. A roster is taken only if
  the pinned network key signed it, so a revocation reaches every member that meets one that has it.
  After a pairing, the new roster is pushed to every member but the newcomer, which already
  holds it from P6. A primary's push of a new roster that fails (the member away, a handshake
  that times out) is made again after 1 s, the wait doubling up to 10 minutes, until it goes, the
  member leaves the roster, or a newer roster replaces it: a member that sends nothing still
  learns of a revocation.
- `roster()`, `state()`, `id()`, `identity()`, `network()`, `relay_url()`,
  `wait_connected(timeout)`, `close()`.
- `traffic()` counts what this member sent and received, always on: `since`, `total`, `relay`
  (UTF-8 bytes of control messages) and `peers`, each direction `{ messages, bytes, frames,
  frame_bytes }` as the TypeScript client counts them; `total` is the sum over `peers`.
  `reset_traffic()` starts over.
- `session_info(peer)` and `sessions()` show the live sessions with a peer, or with every peer
  (indices, counters, credit).

A member reconnects after 500 ms, doubling to 10 s, forever, except after close code 4008 (it is
revoked) or 4005 (replaced: another copy of the identity connected); both are terminal. A member
that registers with an older roster than the relay holds receives the newer one in `registered`
and accepts it (an `Event::Roster`) before it is connected.

**The primary.** Being primary is a trait of a member (section 3.1): `is_primary()` is true while
it holds the network seed and its roster names it primary, and `holds_network_seed()` says
whether it holds the seed. The primary's calls are `Member`'s, and fail with `Invalid` on a
member that is not the primary now: `open_pairing_code(CodeOptions { lifetime, code })`
returning `{ code, code_id, link, expires_at }` (`code` chooses the code instead of a random
one), `cancel_pairing_code(code_id)`, `revoke(node_id)` returning the new roster, `usage()`. The
relay allows `USAGE_BURST` (3) asks at once, then one per `USAGE_INTERVAL` (10 s); beyond that
`usage()` fails with `RateLimited`. When no further member fits under the roster limit,
`open_pairing_code` fails with `RosterFull`. `Primary::connect(opts)` / `Primary::new(opts)` start
a member that must be the primary (`network_seed` given); `Primary` derefs to `Member`.

**Becoming the primary.** A node started with the network seed whose roster names another
member primary claims the network at its first registration (section 3.1): it signs the next
roster naming itself `primary`, the members unchanged,
adopts it and publishes it like any change, and from then on is the primary. It claims only at
start, never on a later roster. A node whose roster comes to name another member primary stops
being the primary in place: its codes close, its pairing channels end (`pairEnd`, and a
`PairingFailed` of reason `demoted`), its pushes are cancelled and its usage asks fail; its
connection and sessions are untouched, and the seed its caller gave it stays. The relay, too,
keeps that node's connection: nobody is disconnected. Neither the primary nor a node given the
seed can `resign()`.

**Pairing.** `pair(PairOptions { target, identity, timeout })` returns `{ roster, pinned_network_key }`,
or fails with `Pairing`, `Unreachable` (the primary is not connected) or `Timeout`. Codes:
`generate_code`, `normalize_code`, `format_code`; links: `build_pairing_link`, `parse_pairing_link`.

`link_client::wire` exposes the building blocks (encodings, frames, the Noise engine, SPAKE2,
the pairing state machines) for the vector tests and for tools; applications need none of it.

## Choosing a relay

A relay operator can publish a **directory**: regions, each with a URL to time and a relay URL
template over its own number of shards (default 1), so one region can grow without the others.

```json
{ "version": 1, "regions": [
  { "id": "eu1", "name": "Europe", "probe": "https://eu1.relay.example.com/health",
    "relay": "wss://{shard}.eu1.relay.example.com/v1", "shards": 256, "accepting": true } ] }
```

When a primary creates its network, it mints the network key first (`NetworkKey::generate()`:
the network id is its `id()`), then `pick_relay(PickRelayOptions::new(network, directory))`
(`directory` a URL, or a `RelayDirectory` already in hand) times every accepting region (the
fastest of `probes` requests each, default 3, within `timeout`, default 3 s), takes the closest,
and puts the network's shard into that region's template. The shard is `shard_of(network,
shards)` with that region's `shards`: the first four bytes of SHA-256 of the network id,
big-endian, modulo `shards`, in lowercase hex padded to the width of `shards - 1` (`00` to `ff`
for 256). Pass the `url` of the `PickedRelay` it returns to `create_network_with(&identity,
&network_key, relay, now_ms)`; the roster carries it from then on, so the directory is consulted once, at creation,
and never on reconnect. It fails with `Unreachable` when no region answers (or the directory
cannot be fetched) and `Invalid` on a directory it cannot use (`parse_directory` checks one);
fall back to a relay of your own. The requests are the client's own HTTP/1.1 GETs (http:// and
https://, on the rustls and webpki roots the WebSocket already uses); `fetch` replaces them with
any `Fetch` (`Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<FetchResponse, String>>
+ Send>>>`), for tests or another HTTP stack.

## Sessions in brief

- Every session starts with 1 MiB of credit each way; a larger `credit_window` is granted as
  extra credit when the session comes up. Fragments of a message in progress are credited while
  the application has nothing waiting; complete messages when it takes them. Credit goes back in
  batches: at once from 64 KiB owed, otherwise 250 ms after it began to be owed.
- **The socket is kept short.** Control (handshakes, `reset`, `refused`, credit and roster
  messages, relay control) is handed to the socket at once. Message fragments wait in the
  client's own queue and are encrypted only when handed over, which happens while at most 64 KiB
  waits in the socket and while the session's un-credited bytes are under its pace (the larger
  of 64 KiB and one and a half times what the receiver credited back over the last second).
  Wire order is nonce order, since each fragment is encrypted at the moment it is handed over.
- To a relay whose `hello` lists `control`, session messages other than application messages go
  as frame type `0x08`.
- Handshake message 1 carries 16 bytes: the roster version and a stamp, the initiator's Unix
  milliseconds (wall clock, so it keeps increasing across restarts), one more than the last when
  the clock has not moved on. A responder keeps, per roster member, the greatest stamp it has
  accepted, and takes an init only if it is stamped later than that and no more than W = 10
  minutes ahead of its own wall clock, and later than a floor W before this node started or the
  member joined its roster, whichever is later (kept on the monotonic clock and read in wall
  time, so a wall clock set right after the start moves it too): inits recorded before a restart
  or a re-add cannot be replayed. The stamps of ids that leave the roster are kept (1,024 at
  most) and restored if they are re-added, so an init accepted before an id left stays refused
  however soon it returns. An init outside those bounds is dropped
  unanswered and charged to that member's failure budget, its version ignored, no session made
  or ended, nothing kept. An 8-byte payload (a bare roster version) is a malformed init.
- A message is never split across sessions: a rekey switches at a message boundary.
- A data frame for a session the receiver does not hold is answered `reset`; the sender drops the
  session and its next send handshakes again. The message in that frame is lost.
- Losing the relay connection ends every session. Sends wait up to the handshake timeout for the
  connection to come back. `sync_roster()` and `resign()` repeat their request until answered.

**Bounds.** Every byte from the relay or a peer is treated as hostile. Beyond what the protocol
requires, a member ends a session whose peer sends message bytes beyond the credit it was given,
keeps at most 8 sessions per peer, and holds per peer at most `2 × 64 MiB + 4 × credit_window`
bytes and 65536 messages waiting for the application or in reassembly; past those, the session
that would exceed them ends (delivery is at most once). Control messages over 128 KiB and frames
over 1 MiB are refused.

What others can make a member send is bounded too. A connection holds at most 64 MiB queued and
unwritten (a primary publishing a full roster to about 440 members needs some 29 MB); past
that, the member drops the connection and redials rather than grow or wait. A peer's
rosters (answers to `roster-request`, and rosters handed to a peer seen to be behind) go at most
once per 250 ms, repeats coalesced into one, and no roster is queued to a peer while one as new is
still unsent to it. `reset` goes once per peer and index per second, and to each peer at most 32
a second (64 at once): one peer's flood spends only its own budget; resets to ids off the roster
also share a ceiling of 128 a second (256 at once). Handshake-inits are processed
at most 16 a second (32 at once) per member, 4 a second (8 at once) per id off the roster (a
table of 256), and 128 a second (256 at once) from all ids off the roster together, before any
key agreement is spent on them. Inits named as from a member that fail (a static key that is not
the member's, a message that does not read, or one on the member's key without the 8-byte roster
version; the member itself or a relay naming it can send them) spend that member id's own
failure budget of 2 a second (4 at once), apart from its init budget, and while it is spent that
id's inits are dropped before any key agreement: they starve only that id, never another member.
The version a failed init claims is ignored: no roster is pushed to the member it names, none
asked of it or of the primary. An init from an id off the roster that a budget drops, or that is
read and refused while claiming a newer roster, is a hint that a roster the member has not seen
lists that id: the primary is asked for its roster, at most once a second, and after each hint
that brought no newer roster the wait before the next doubles, up to 5 minutes (a newer roster
puts it back to 1 s). Hints during the wait are not lost: one ask goes when it ends. A newer
`rosterVersion` in `registered` asks the primary at once, whatever the wait. Budgets carry across reconnects, refilling only with time.
What a relay sends that would raise an event is bounded as well: a `pairing` for a code id the
primary never opened raises no event, one for a code it closed (expired, cancelled, burned,
used) at most one a second, the `pairEnd` answer to a refused pairing for an issued code goes on
the first refusal on each channel and at most once a second per code and channel after, and,
for ids never issued, at most 32 a second (64 at once) in all. Each open code sets up at most 4
pairing channels a second (8 at once), each a SPAKE2 setup, since a channel that ends without a
failed attempt refunds its slot; past that a `pairing` is refused as for a code out of attempts.
A channel that ends without a failed attempt (the newcomer left, a timeout, the connection
dropped, an existing member) raises `PairingFailed` at most once a second per code and reason.
Relay `error`s become events at most 16 a second (64 at once), each field cut to 1 KiB.

Every rate, interval and timeout runs on a monotonic clock (`Instant`, tokio time): a wall
clock stepped back neither strands a budget nor holds back a roster offer, nor keeps a pairing
code open past its lifetime. The wall clock is read only for what is signed or shown (`ts`,
`issuedAt`, a code's `expires_at`, `traffic().since`).

## Develop

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test                                  # unit, vector and integration tests
cargo test --lib                            # the state machines on a fake relay and clock
cargo test --test vectors                   # spec/vectors and client-typescript/test/vectors
cargo build --release --bin link-driver     # the driver for test/drivers/PROTOCOL.md
```

The integration tests build the relay from `../relay` with `go build` into a temporary
directory (or use `LINK_RELAY_BIN`) and start it on a loopback port per test, configured
through `LINK_*` variables. They need Go 1.27 or later.

The driver (`src/bin/link-driver.rs`) is test equipment, not part of the library's API. The
cross-implementation suite runs it from `test/`:

```sh
(cd test && LINK_DRIVERS=ts,rust node --import tsx --test interop.test.ts)
```
