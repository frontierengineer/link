# github.com/frontierengineer/link/client-go

The Go client for Link, protocol version 1 ([`spec/protocol.md`](../spec/protocol.md)), the
equal of the TypeScript client in [`client-typescript/`](../client-typescript/README.md). It does everything a member
needs: keys, signed rosters, pairing with a short code (SPAKE2), and end-to-end encrypted
sessions (Noise IK) over one outbound WebSocket to a relay that only routes.

Package `link`, Go 1.27 or later. Its dependencies are `golang.org/x/crypto` (ChaCha20-Poly1305),
`github.com/flynn/noise` (Noise IK), `filippo.io/nistec` (P-256 for SPAKE2) and
`github.com/gorilla/websocket`.

## Use

```go
import link "github.com/frontierengineer/link/client-go"

// The primary: create the network once, then persist both seeds and the roster.
me, _ := link.NewIdentity()                                    // me.Seed(): 32 secret bytes
roster, networkSeed, _ := link.CreateNetwork(me, "wss://frontierengineer.link/v1", time.Now(), nil)
primary, _ := link.ConnectPrimary(ctx, link.MemberOptions{Identity: me, Roster: roster,
	NetworkSeed: networkSeed, // the network's own seed: as secret as me.Seed(), and yours to keep
	OnEvent: func(e link.Event) {
		if r, ok := e.(link.RosterEvent); ok {
			save(r.Roster) // every accepted roster: persist it
		}
	}})

// Invite a node. Show the code or the link; it admits one node for 15 minutes. It is the
// network's default code: opening another closes it, unless that one is Separate.
code, _ := primary.OpenPairingCode(link.PairingCodeOptions{})

// The newcomer: pair once, then connect as a member from then on.
id, _ := link.IdentityFromSeed(savedSeed)
res, _ := link.Pair(ctx, link.PairOptions{Link: code.Link, Identity: id}) // or Target: &link.PairingLink{...}
member, _ := link.ConnectMember(ctx, link.MemberOptions{Identity: id, Roster: res.Roster})

err := member.Send(ctx, peerID, bytes)                      // up to 64 MiB
msg, err := member.Receive(ctx)                             // or member.OnMessage(func(m link.InboundMessage) { ... })
member.Close()
```

## API

**Identity.** `NewIdentity()`, `IdentityFromSeed(seed)` give an `*Identity` with `Seed()`, `ID()`,
`Ed25519Public()`, `X25519Public()` and `Sign(msg)`. Persist the seed; everything else derives
from it (section 2). `NodeIDFromEd25519`, `IsNodeID`. A network has a seed of its own, apart
from every node's: `NewNetworkSeed()` mints one, and `NetworkKeyFromSeed(seed)` gives its
`*NetworkKey`, with `Seed()`, `ID()` (the network id), `Ed25519Public()` (the roster's
`networkKey`) and `Sign(msg)`. Every signature (rosters, resignations) is
verified strictly, the same in every implementation: A and R canonical encodings and neither
of small order, S < L, and the cofactorless equation. `crypto/ed25519` gives the last two (and
refuses a non-canonical R); the checks on A and R it would not make are made first.

**Rosters.** `CreateNetwork(identity, relay, now, networkSeed)` mints a network seed (or takes
the one given), and returns version 1, with the identity alone as primary, signed by the network
key, and the network seed. The network id derives from the network key, never from a node's.
The roster's `Primary` (also `(*Roster).PrimaryID()`) is the node id of the primary, and must
be a member's id. A member is `{ID, Ed25519, X25519}`; any field this version does not define is
signed and otherwise ignored. `MemberFromIdentity(identity)` is an identity's entry.
`CreateNetworkWith(NetworkOptions{Primary, Relay, Members, NowMs, NetworkSeed})` does the same with
the relay optional, `Members` listed in version 1 beside the primary, and the time in Unix
milliseconds (0: now); it fails `invalid` for an entry that is not one or is listed twice, and
`roster-full` over 65000 bytes.
`*Roster` marshals and unmarshals as JSON (strictly: no duplicate keys, no lone surrogates),
keeping any members this protocol version does not define, since the signature covers them.
`DecodeRoster(json)` checks the shape, `ValidateRoster(json)` and `(*Roster).Problem()` every
rule of section 3; `AcceptanceProblem(r, pinnedNetworkKey, heldVersion)` applies the acceptance rule;
`SignRoster`, `MemberFromIdentity`, `(*Roster).FindMember`, `JCS`, `Size`, `SigningBytes`,
`Clone`; `Canonicalize(json)` is RFC 8785 JCS. A roster's JCS encoding, signature included, is
at most `MaxRosterBytes` (65000 bytes, about 440 members), so it always fits one session message.

**A network with no relay yet** (section 3.2). With `Relay` empty, `CreateNetworkWith` makes a
network that is not placed: valid, but no member dials it, so it can be made offline, and placed the
first time the primary can reach the directory. `(*Roster).IsPlaced()` says whether a roster names a relay. A member or
primary on an unplaced roster without `RelayURL` fails `invalid` ("the network has no relay yet")
at once; with one, it dials that, and its pairing links name it.
`PlaceNetwork(roster, networkSeed, relay, nowMs)` returns the next version with `relay` set and
nothing else changed (`nowMs` 0: now), signed by the network key; start the primary on it and it
publishes it at registration. It fails `invalid` (`errors.Is(err, link.ErrInvalid)`) when the
roster is placed already, when `relay` is not a `ws://` or `wss://` URL (`IsRelayURL`), or when
the seed does not derive the roster's network key. A placed network is not placed again.

**Offline.** A member never stops or crashes for want of a network (section 11): with its relay
unreachable (refused, a name that does not resolve, no route) or gone mid-session, it says so
through its states (`disconnected`, then `connecting` again), retries with backoff, and a call
that needs the relay fails with its own error; a lookup after 4009 that answers something that is
not a URL is ignored.

```go
roster, seed, _ := link.CreateNetworkWith(link.NetworkOptions{Primary: me, Members: []link.RosterMember{link.MemberFromIdentity(laptop)}})
// ...later, the first time the directory answers:
picked, _ := link.PickRelay(ctx, link.PickRelayOptions{Network: roster.Network, DirectoryURL: dir})
placed, _ := link.PlaceNetwork(roster, seed, picked.URL, 0) // version 2: persist it
primary, _ := link.ConnectPrimary(ctx, link.MemberOptions{Identity: me, Roster: placed, NetworkSeed: seed})
```

**`Member`** (`ConnectMember(ctx, options)` returns once registered; `NewMember(options)` starts
connecting and returns at once):

| `MemberOptions` | |
|---|---|
| `Identity`, `Roster` | required; the newest roster held |
| `RelayURL` | defaults to the roster's relay; required on a roster not placed yet |
| `PinnedNetworkKey` | defaults to the roster's `networkKey` |
| `NetworkSeed` | for the node meant to be the primary; must derive the roster's `networkKey`. The seed is the caller's: this package never stores, sends or deletes it |
| `CreditWindow` | the receive window granted per session: 1 MiB (every session's initial credit) to 2^32 - 1, the excess granted as extra credit |
| `Timing` | overrides for the protocol timers (rekey, idle, handshake timeout, backoff, request timeout); a zero field keeps the default |
| `ResolveRelay(ctx, network)` | called on close code 4009; may return a new relay URL |
| `OnEvent` | a listener installed before the member starts, so it sees every event |

- `Send(ctx, peerID, bytes)` returns once every fragment is handed to the relay connection, or
  an `*Error` whose `Code` is `unreachable` (the peer is not connected; nothing is queued),
  `refused` (the peer's roster does not list this node), `revoked`, `replaced`, `timeout`,
  `closed`, or `invalid` (unknown peer, over 64 MiB). Delivery is at most once. `ctx` withdraws
  a message only before its first fragment goes out; after that it is sent whole or fails with
  its session. `SendAsync(peerID, bytes)` returns a channel for the result instead; messages to
  one peer go in call order either way. `errors.Is(err, link.ErrUnreachable)` and
  `link.CodeOf(err)` branch on the code.
- `Receive(ctx)` takes the next message, `{From, Bytes}`, whole and in order per sender;
  `OnMessage(handler)` takes each as it arrives instead. A message is credited back to its
  sender when the application takes it (with `OnMessage`, once the handler returns), so a slow
  reader slows its senders. `OnArrival(listener)` sees messages on arrival without taking
  them; `Pending()` counts those waiting.
- Events (`On(listener)` returns a remove function; listeners run one at a time, in order, on
  a goroutine of the member's; `Settle()` waits until those raised so far are delivered):
  `StateEvent` (`connecting`, `connected`, `disconnected`, `revoked`, `replaced`, `closed`),
  `RosterEvent`, `DisconnectEvent` (`Code`, `Reason`), `MovedEvent` (4009), `RelayErrorEvent`,
  `ShapingEvent` (`Shaping`, below). Every close is reported before the state it leads to, the
  member's own (`Close`, a roster without it) included.
- `Shaping()` is how the relay shapes the network now, from its last `shaping` notice (section
  9): `{RateBps, Slowed}` (JSON `rateBps`, `slowed`), the rate in force (0: none; the trickle
  rate once the quota is spent) and whether the network is slowed. It is `{0, false}` before any
  notice and on a relay whose `hello` does not list `shaping`. A `ShapingEvent` is raised when it
  changes (the quota spent, the trickle lifted, the limits reloaded), so an application never
  polls `Usage` to know it is slowed.
- `SyncRoster(ctx)` asks the primary for its newest roster. `Resign(ctx)` leaves the network;
  it fails `invalid` on the primary and on any node holding the network seed.
  Rosters also spread member to member: when a handshake shows a peer holds a newer roster,
  the member asks that peer for it, and hands its own to a peer that is behind. A roster is
  taken only if the pinned network key signed it, so a revocation reaches every member that meets
  one that has it, with the primary offline and whatever the relay remembers.
- `ID()`, `Network()`, `Roster()`, `State()`, `RelayURL()`, `WaitConnected(ctx)`, `Close()`,
  `Sessions(peer)` (the live sessions with a peer, for tests and diagnostics).
- `Traffic()` counts what this member sent and received, always on: `{Since, Total, Relay, Peers}`,
  where `Total` and each `Peers[id]` are `{Sent, Received}` of `{Messages, Bytes, Frames, FrameBytes}`,
  as in the TypeScript client (JSON field names included). `ResetTraffic()` starts over.

A member reconnects after 500 ms, doubling to 10 s, forever, except after close code 4008
(`revoked`) or 4005 (`replaced`: another copy of the identity connected); both are terminal. A
member that registers with an older roster than the relay holds receives the newer one in
`registered` and accepts it (a `RosterEvent`) before it is `connected`.

**The primary** is the member that holds the network seed and that its roster names primary
(section 3.1): a trait of a member and its connection, not a separate object. `IsPrimary()` and
`HoldsNetworkSeed()` say where a member stands. `ConnectPrimary` and `NewPrimary` start a member
meant to be the primary (they need `NetworkSeed`) and return a `*Primary`, which embeds
`*Member`. The primary capabilities are the `Member`'s, and
fail `invalid` on a member that is not the primary now:
`OpenPairingCode(PairingCodeOptions{Lifetime, Code, Separate})` returning
`{Code, CodeID, Link, ExpiresAt}` (`Code` chooses the code instead of a random one; codes
below), `CancelPairingCode(codeID)` (`""` cancels the default code; a newcomer midway through a
cancelled code is turned away), `Revoke(nodeID)` returning the new roster, and `Usage(ctx)`, which
asks the relay (request-only) for `{Network: {BytesHour, Connections, Limits, QuotaUsed, Slowed}}`;
the relay allows one ask per `UsageInterval` (10 s) per network, with no burst (`UsageBurst`
is 1), and refuses one sooner at once: it fails `rate-limited`. Whether the network is slowed is
`Shaping()`, which needs no ask. When no further member fits under the roster limit, `OpenPairingCode` fails
`roster-full`, and a code opened earlier fails its pairing with a `PairingFailedEvent`. Extra
events: `PairedEvent` (`Member`, `CodeID`: the code it paired with, `Roster`), `PairingFailedEvent` (its `Code` one of the `Fail*` constants:
`wrong-code`, `malformed`, `unknown-code`, `used`, `no-attempts`, `newcomer-left`, `timeout`,
`relay-lost`, `already-member`, `roster-full`, and the one below).

**Default and separate codes** (section 5.1). A primary holds at most one default code, whose
id is 8 zero bytes, `DefaultCodeID` (`AAAAAAAAAAA`). Since 0.6.0, `OpenPairingCode` opens the
default code unless `Separate` is set, so **opening a second code closes the first unless it is
`Separate`**: the default code open before it admits nobody from then on, and a newcomer midway
through it is turned away. A `Separate` code gets a random id of its own (never all zeros), and
any number of them stay open beside the default code. The default code's pairing link and
parameters carry no `i`, so the code alone pairs: a newcomer given no code id pairs with the
default code. `PairedEvent` and `PairingFailedEvent` name the default code by `DefaultCodeID`.
Once a default code has been opened, a pairing for its id while none is open is refused as for
a closed code (`FailUnknownCode`), however many codes close after it.

**Becoming the primary.** A node started with `NetworkSeed` whose roster names another member
primary claims the primary once registered (section 3.1): it signs the next roster naming
itself primary, the members unchanged, publishes it as any change, and is the primary from then
on. It claims only at its first registration. A node whose roster later
names another member stops being the primary in place: its codes close, its pairing channels
end (`PairingFailedEvent` code `FailDemoted`), its pushes stop and its usage asks fail, and
its connection is untouched; it keeps the seed its caller gave it and signs nothing more. The
relay likewise treats the former primary's connection as an ordinary member's without closing
it, so nobody disconnects.

**Pairing.** `Pair(ctx, PairOptions{Link | Target, Identity, Timeout})` returns
`{Roster, PinnedNetworkKey}`, or fails with `pairing`, `unreachable` (the primary is not
connected) or `timeout`. A `Target` with no `CodeID` pairs with the default code. Codes: `GenerateCode`, `NormalizeCode`, `FormatCode`; links:
`BuildPairingLink`, `ParsePairingLink`. Pairing parameters (section 5.1):
`BuildPairingParams(PairingLink)` writes `v=1&n=…&c=…&i=…&r=…` alone, leaving `i` out when
`CodeID` is `DefaultCodeID` or `""`, and `ParsePairingParams(string)` reads it back, taking a
missing `i` as `DefaultCodeID` and failing `invalid` on a missing `v`, `n`, `c` or `r`, an empty
`i`, an unknown version or a bad value. Link defines the parameters, not a scheme: carry them as you like, in an
https URL's fragment say. A `frontier://pair?` link is one wrapping of them.

## Choosing a relay

A relay operator can publish a **directory**: regions, each with a URL to time and a relay URL
template over its own number of shards (default 1), so one region can grow without the others.

```json
{ "version": 1, "regions": [
  { "id": "eu1", "name": "Europe", "probe": "https://eu1.relay.example.com/health",
    "relay": "wss://{shard}.eu1.relay.example.com/v1", "shards": 256, "accepting": true } ] }
```

When a primary creates its network, `PickRelay(ctx, PickRelayOptions{Network, DirectoryURL})`
(or `Directory` for one already in hand) times every accepting region (the fastest of `Probes`
requests each, default 3, within `Timeout`, default 3 s), takes the closest, and puts the
network's shard into that region's template; `Client` replaces `http.DefaultClient`. The shard is
`ShardOf(network, shards)` with that region's `Shards`: the first four bytes of SHA-256 of the
network id, big-endian, modulo `shards`, in lowercase hex padded to the width of `shards - 1`
(`00` to `ff` for 256). The network id derives from the network seed, so mint the seed first
(`NewNetworkSeed`, then `NetworkKeyFromSeed(seed).ID()` is the network), and pass the `URL` of
the `PickedRelay` it returns and that seed to `CreateNetwork(identity, relay, now, seed)`, or to
`PlaceNetwork` for a network made before it had one; the roster carries it from then on, so the directory is
consulted once, at creation, and never on reconnect. It fails `unreachable` when no region
answers (or the directory cannot be fetched) and `invalid` on a directory it cannot use
(`ParseDirectory` checks one); fall back to a relay of your own.

## Sessions in brief

- Every session starts with 1 MiB of credit each way; a larger `CreditWindow` is granted as
  extra credit when the session comes up. Fragments of a message in progress are credited while
  the application has nothing waiting; complete messages when the application takes them.
  Credit goes back in batches: at once from 64 KiB owed, otherwise 250 ms after it began to be
  owed.
- **The socket is kept short.** Control (handshakes, `reset`, `refused`, credit and roster
  messages, relay control) is handed to the socket at once. Message fragments wait in the
  client's own queue and are encrypted only when handed over, which happens while at most
  64 KiB waits in the socket's queue and while the session's un-credited bytes are under its
  window (the larger of 64 KiB and one and a half times what the receiver credited back over the
  last second). Wire order is still nonce order.
- **Pacing (section 11).** While the relay's `shaping` gives a rate R, fragments go at most at
  7/8 of R over the whole connection (each counted at its frame's size), carry at most a quarter
  of a second of that (at least 1 KiB), and a session keeps at most the larger of one fragment
  and the lesser of what was credited back over the last second and R/2 un-credited. Little then
  lies in the socket in front of control, so usage asks, roster sync and other control arrive in
  well under a second even while the network is trickled and the member sends in bulk.
- To a relay whose `hello` lists `control`, session messages other than application messages go
  as frame type `0x08`.
- A message is never split across sessions: a rekey switches at a message boundary, and a
  retired session lives past its 30 s grace while a message still crosses it.
- **Replay protection (section 7.1).** A handshake-init's payload is the roster version and a
  `stamp`: wall-clock Unix milliseconds, and always greater than the last this node sent. A
  responder keeps, per member, the greatest stamp it accepted; when a member leaves the roster
  its stamp is retained (the last 1024 such ids) and restored if it is re-admitted, so the
  inits recorded before it left stay refused; for a member with none stored or retained it takes the later of its own start and the member's
  addition to its roster (kept on the monotonic clock, read in wall time), less W = 10 minutes.
  An init with a stamp no greater is a replay, and one stamped more than W ahead of the
  responder's wall clock is refused too: both are dropped unanswered, counted as a failed init,
  and store nothing.
- A data frame for a session the receiver does not hold is answered `reset`; the sender drops
  the session and its next send handshakes again. The message in that frame is lost. A frame
  that does not decrypt (lost, replayed, reordered) ends the session.
- Every byte from the relay or a peer is treated as hostile, and every JSON document is I-JSON
  with integer literals of digits only (section 1): repeated names, lone surrogates, more than 32
  arrays and objects open at once, `12.0`, `1.2e1` and `-0` make it invalid, and names match
  case included. A member enforces the credit it granted (a peer that sends message bytes beyond it
  loses the session), ends a session on an empty fragment that says more follow, and keeps per
  peer at most 8 sessions (a ninth ends the oldest that is not current), `2 × 64 MiB + 4 ×
  window` bytes buffered and 65536 untaken messages (section 7.3).
- **Rates (section 7.4).** Every budget belongs to one id, and budgets carry across relay
  connections (a relay that forces reconnects gets nothing fresh for it). A roster goes to a
  peer at most once each 250 ms, coalesced, and never while one as new is still unsent. A
  member's handshake-inits are read 16 a second (bursts of 32), and those labelled with a
  member's id that fail to read or fail the key check spend that id's own failure budget of 2
  a second (bursts of 4), while it is empty that id's inits are not read, and their roster
  version is ignored (a well-keyed init whose payload is malformed counts as one); an id off the roster
  gets 4 a second (bursts of 8), kept for the 256 most recently seen, and all such ids together
  128 a second (bursts of 256); a dropped one, or a refused one claiming a newer roster, asks the
  primary for its roster, at most once a second, and after an ask that brings no newer roster
  twice the wait before the next, up to 5 minutes (a newer roster starts it over); an ask held
  back by the wait is deferred to its end, not dropped. `reset` goes to one id at most 32 a second (bursts of 64) and once a second per
  index, and to all ids off the roster together 128 a second (bursts of 256). A primary
  answers the first refusal on each pairing channel for a code it issued (open, or among the
  last 1024 closed), repeats there once a second, and tells its application once a second per
  code and reason (an open code's pairing channels are set up at most 4 a second,
  bursts of 8, and the events of channels ended with their slot refunded go once a second per
  code and reason); a code id it never issued gets `pairEnd` within a budget of 32 a second
  (bursts of 64) and no event. Relay errors reach the application 16 a second (bursts of 64),
  each field cut to 1 KiB. A connection whose send buffer would pass 64 MiB, counting 64 bytes
  a frame besides its bytes, is dropped and redialled (section 11). A relay that does not
  complete registration within 10 s, or from which nothing at all arrives for 75 s, is left,
  and the member reconnects.
- Every rate, interval and timeout runs on the monotonic clock; the wall clock only stamps
  what the protocol writes down (a registration's or resignation's `ts`, a roster's
  `issuedAt`), so stepping it strands no budget and ends no session or connection.
- Reassembly keeps one contiguous buffer per message, grown by doubling, so fragments of any
  size cost their bytes; JSON numbers must be finite (`1e309` is refused).
- **Roster pushes.** The primary pushes each new roster to every member (after pairing, every
  member but the newcomer, which has it from P6 and is not connected yet); a push it fails to
  hand over is tried again 1 s later, doubling to 10 min, until it goes, the member leaves the
  roster, or a newer roster supersedes it.
- Losing the relay connection ends every session. Sends wait up to the handshake timeout for
  the connection to come back. `SyncRoster` and `Resign` repeat their request until answered.

## The driver

[`cmd/link-driver`](cmd/link-driver/main.go) implements [`test/drivers/PROTOCOL.md`](../test/drivers/PROTOCOL.md)
for the cross-implementation suite: one node, steered by JSON lines on stdin and stdout. It is
test equipment, not part of the package's API.

## Develop

```sh
go vet ./...
go test -race -count=1 ./...          # vectors, unit, state-machine, the real relay, the driver
go test -short -count=1 ./...         # without building and running the relay
LINK_RELAY_BIN=/path/to/link-relay go test ./...   # with a relay built elsewhere
```

The tests read the vectors from `../spec/vectors/` and `../client-typescript/test/vectors/`, and build
`../relay/cmd/link-relay` (and the driver) into temporary directories with `go build`.
