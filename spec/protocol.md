# Link protocol, version 1

Link is a private network for one install. Every member holds one outbound WebSocket to a relay
and exchanges end-to-end encrypted messages with other members of its network. The relay routes
by member id and never sees content.

This document is the wire specification. Every implementation (the Go relay, the TypeScript
client, and any later client) must follow it exactly and pass the vectors in `spec/vectors/`.

Notation: `||` is concatenation. `u32be(x)`, `u64be(x)` are big-endian unsigned integers.
`lenStr(s)` is `u32be(byte length of the UTF-8 encoding) || UTF-8 bytes`. `b64u` is base64url
without padding. `b32` is RFC 4648 base32, lowercase, without padding.

## 1. Primitives

| Use | Primitive |
|---|---|
| Identity and signatures | Ed25519 (RFC 8032), verified as below |
| Session key agreement | X25519 |
| Sessions | `Noise_IK_25519_ChaChaPoly_SHA256`, Noise revision 34 |
| Pairing | SPAKE2, RFC 9382, ciphersuite P256-SHA256-HKDF-HMAC |
| Key derivation | HKDF-SHA256 (RFC 5869) |
| Hash | SHA-256 |
| Pairing transport | ChaCha20-Poly1305 (RFC 8439) |
| Canonical JSON for signing | JSON Canonicalization Scheme, RFC 8785 (JCS) |

**Ed25519 verification.** A signature `R || S` by public key `A` over message `M` is valid
exactly when all of these hold, and every implementation checks exactly these:

- `A` and `R` are canonical encodings: the encoded `y` is below `p = 2^255 - 19`, and the sign
  bit is not set when `x = 0` (the points with `y = 1` and `y = p - 1`);
- neither `A` nor `R` is one of the eight points of small order;
- `S < L`, the order of the prime subgroup;
- the equation is cofactorless: `[S]B = R + [k]A`, with `k = SHA-512(R || A || M) mod L`.

No other check is made: in particular no subgroup check, so a key or `R` of mixed order (a
point of the prime subgroup plus one of small order) is valid whenever the cofactorless
equation holds, as one vector shows.

Implementations disagree out of the box (on non-canonical and small-order keys, and on the
cofactored against the cofactorless equation), and every implementation must accept exactly
the same signatures, or members holding the same roster can disagree about whether it is valid.
Lax keys are worse: under a small-order key, anyone can forge a signature on any message (`R` the
identity, `S = 0`). `spec/vectors/relay.json` holds a vector for each of these rules
(section 12).

**JSON.** Every JSON document of the protocol (control messages, rosters, the `roster` and
`resign` session messages, sealed pairing messages) is I-JSON, RFC 7493: UTF-8, one value with
nothing after it but whitespace, no member name twice in one object, no lone surrogate in a
string or a name, escaped (`"\ud800"`) or not, and every number finite as an IEEE 754 double
(`1e309` overflows to infinity and is refused). At most 32 arrays and objects are open at once
(a roster needs three). Member names match exactly, case included: `"Type"` is not `type`. A
receiver refuses a document that breaks any of this, whatever a lenient parser would make of it
(keeping the last of two names, turning a lone surrogate into U+FFFD, matching names without
regard to case, reading `1e309` as infinity): the relay closes the connection `4000`, a member
ignores the document. A field this document gives as an integer (`version`, `issuedAt`, `ts`) is
written as a non-negative integer literal: digits only, with no sign, fraction or exponent. `12`
and `0` are integers; `12.0`, `1.2e1` and `-0` are not, and make the document invalid as a wrong
type would. `spec/vectors/relay.json` holds such documents as text (section 12).

## 2. Keys and ids

- Each node has a 32-byte **seed** from a secure random source. It never leaves the node.
- `ed25519Seed = HKDF-SHA256(ikm = seed, salt = empty, info = "frontier-link/1/ed25519", L = 32)`;
  the Ed25519 keypair is derived from it as RFC 8032 specifies.
- `x25519Private = HKDF-SHA256(ikm = seed, salt = empty, info = "frontier-link/1/x25519", L = 32)`,
  clamped as X25519 requires.
- **Node id** = `b32(SHA-256(ed25519Public)[0..16])`: 26 characters.
- Each network has its own 32-byte **network seed**, from a secure random source, minted once
  when the network is created, apart from every node's seed. Its custody is the application's
  (section 3.1): Link never stores, sends or deletes it.
- `networkEd25519Seed = HKDF-SHA256(ikm = network seed, salt = empty, info = "frontier-link/1/network", L = 32)`;
  the **network key**, an Ed25519 keypair, is derived from it as RFC 8032 specifies.
- **Network id** = `b32(SHA-256(networkKeyPublic)[0..16])`, derived from the network key as a
  node id is from a node's key. It never changes, whichever node is primary.
- Public keys in JSON are `b64u` of the raw 32 bytes.

## 3. The roster

```json
{
  "network": "<network id>",
  "version": 12,
  "issuedAt": 1790000000000,
  "relay": "wss://frontierengineer.link/v1",
  "networkKey": "<b64u>",
  "primary": "<node id>",
  "members": [
    { "id": "<node id>", "ed25519": "<b64u>", "x25519": "<b64u>" }
  ],
  "signature": "<b64u>"
}
```

- `version` is a positive integer that increases with every change. `issuedAt` is Unix
  milliseconds. Both are non-negative integer literals (section 1) of at most 2^53 − 1.
- A roster's JCS encoding (with its signature) is at most **65000 bytes**, about 440 members,
  so that it always fits in one session message. A primary refuses to add a member beyond that,
  and a roster over the limit is invalid everywhere.
- `networkKey` is the network key's public half (section 2).
- `relay` is the URL of the relay the network's members dial (section 3.2 says which URLs), or
  `""`: the network is not placed yet (section 3.2). Validity asks only that it is a string.
- `members` is sorted by `id`, each id once.
- `primary` is the node id of the **primary**, the member that holds the network seed; it must
  be the `id` of one of `members`. It has nothing to do with `network`.
- A roster or a member entry may carry other fields: they are signed like the rest and
  otherwise ignored. An application that sorts its members into categories keeps them in its
  own data, by node id.
- **Signature** = Ed25519 by the network key over
  `UTF-8("frontier-link/1/roster") || JCS(roster with the "signature" member removed)`.
- **Valid** when: the signature verifies against `networkKey`; `network` equals the id derived
  from `networkKey`; every member's `id` is derived from its `ed25519`; `primary` is a member's
  `id`; the rules above hold.
- A member **accepts** a roster only if it is valid, `networkKey` equals the key the member
  pinned at pairing, and `version` is greater than the version it holds.

### 3.1 The network seed and the primary

Being primary is a trait of one member, the one the roster names primary, and of its relay
connection: nothing more. A node keeps its own seed, its node id and its connection when it
becomes primary or stops being one, and nobody is disconnected when the primary changes.

- **Creating a network.** A node mints a network seed, derives the network key and id, and signs
  version 1 listing itself as `primary`, alongside any other members its application names (by
  default none). Its `relay` is the relay's URL, or `""` for a network not placed yet (section
  3.2).
- **Custody.** The application that runs a node keeps the network seed and gives it to the node
  it wants to be the primary. Link never stores, sends or deletes it: no message of this
  protocol carries it. Whoever holds the seed can make its node the primary, so keeping it to one
  node is the application's.
- **Signing.** Only a node holding the network seed signs a roster, and only while the roster it
  holds names it primary.
- **Becoming the primary.** A node started with the network seed whose roster names another
  member primary claims it once registered: it signs the next roster with itself as `primary`,
  nothing else changed (the former primary is an ordinary member of it), and publishes it
  as any change (sections 4.2 and 8). It is the primary from then on. It claims only when it
  starts: a node whose roster later names another member primary stops being the primary in
  place (it closes its codes and ends its pairing channels, section 5.3) and signs nothing more,
  whatever seed it holds.
- **The relay** follows the roster: the primary is whichever member its roster names primary,
  and when a newer roster names another, the relay demotes the former primary's connection in
  place (section 4.2).

### 3.2 Placing a network

A network can be made before it has a relay: on a machine that is offline, or that cannot reach
the relay directory yet. It is placed on a relay the first time its primary can reach the
directory, and its members connect from then on. There is no mode: the same node, on the same
code path, makes the network, places it and connects.

- **Unplaced.** A roster whose `relay` is `""` is valid, and its network is **not placed**. No
  member dials it: a node is started on an unplaced roster only when it is given a relay URL apart
  from the roster, and otherwise refuses to start, at once, as a caller error (`invalid`), never
  as a connection that fails or retries. A pairing link from a primary so started names the relay
  it dials.
- **Placing.** A network is placed by the next roster version that changes `relay` alone, from
  `""` to a relay URL: `version` one more, `issuedAt` the later of now and the previous one,
  every other field (`members`, `primary`, fields this document does not define) as it was, and
  signed by the network key. Placing needs the roster and the network seed, nothing else: no
  identity and no connection. A client refuses (`invalid`) to place a roster that is placed
  already, at a URL that is not a relay URL, or with a seed that does not derive `networkKey`.
- **A relay URL**, for placing, begins `ws://` or `wss://` in lower case, followed at once by a
  host (the text before the next `/`, `?` or `#` is not empty), and parses as a URL (the WHATWG
  URL Standard): `wss://eu.frontierengineer.link/v1` and `ws://127.0.0.1:8080/v1` are;
  `https://eu.frontierengineer.link/v1`, `wss:///v1`, `ws:/eu.frontierengineer.link` and
  `WSS://eu.frontierengineer.link/v1` are not.
- **Once placed**, a network is not placed again, and no roster sets its `relay` back to `""`.
  Moving a network to another relay is as before: close code `4009` and the client looking the
  network up again (section 11).
- **At the relay** a placed roster is an ordinary newer version: presented at registration or
  pushed, it replaces the version the relay holds (section 4.2). The relay reads `relay` as a
  string and nothing more, so it neither knows nor minds whether a network is placed.
- Choosing the relay (a directory timed from the client, and the network's shard, which derives
  from the network id) is the client's, before it places: an unplaced roster already has its
  network id.

## 4. Connecting to the relay

WebSocket over TLS, path `/v1`. Text frames carry control messages, one JSON object each with a
`type`, at most 131072 bytes (128 KiB; a roster, at most 65000 bytes, travels inside some of
them). Larger ones close the connection `4000`, as does one that is not I-JSON (section 1); a
node ignores such a message from the relay. Binary frames carry routed frames (section 6).

### 4.1 Registration

1. Relay → node: `{"type":"hello","version":1,"challenge":"<b64u 32 bytes>","features":["control","shaping"]}`

   `features` lists optional behaviours the relay supports; a node ignores names it does not
   know, and treats a missing `features` as empty. `control`: the relay accepts routed frames of
   type `0x08` (section 6). `shaping`: the relay tells its members the rate their network is
   shaped at with `shaping` messages (section 9).
2. Node → relay:
   ```json
   {"type":"register","network":"<id>","node":"<id>","ed25519":"<b64u>",
    "ts":1790000000000,"sig":"<b64u>","roster":{ ... }}
   ```
   `sig` = Ed25519 by the node over
   `lenStr("frontier-link/1/register") || lenStr(network) || lenStr(node) || challenge (32 raw bytes) || u64be(ts) || lenStr(origin)`,
   where `origin` is the lowercased `host[:port]` of the URL the node dialled, with the port
   omitted when it is `80` or `443`, whatever the scheme. The relay builds its side the same way
   from `LINK_ORIGIN` or the request's `Host`. (A relay behind a TLS terminator cannot tell the
   scheme, so both ports are dropped on both sides.)
3. The relay checks, in this order, and closes with the given code on the first failure:
   1. the message's shape (`4000`);
   2. `node` equals the id derived from `ed25519` (`4007`);
   3. the signature, rebuilt with the relay's own origin and the challenge it sent (`4007`);
   4. `|now - ts| <= 300000` (`4007`);
   5. the roster is valid and its `network` equals `network` (`4008`);
   6. the **effective roster** is the newer of the presented roster and the newest the relay
      holds for the network. A presented roster newer than the relay's replaces it (it is signed
      with the network key, so any member may deliver it);
   7. `node` is a member of the effective roster (`4008`).
4. Relay → node: `{"type":"registered","node":"<id>","rosterVersion":12}`, followed at once by
   `shaping` (section 9) from a relay that lists that feature. When the relay held a
   newer roster than the node presented, it adds `"roster":{ ... }` with that newer roster, and
   the node applies the acceptance rules of section 3, before it counts itself registered. A
   member that was offline while the roster changed is therefore brought up to date at
   registration, and is closed `4008` only if the newest roster no longer lists it. A node that
   accepts a `roster` here that does not list it enters the terminal `revoked` state at once
   (section 8): it never counts itself registered, and does not reconnect. A relay that keeps
   only a compact record of its newest roster (section 9) sends a higher `rosterVersion`
   without `roster`; the node then learns the roster from the primary or from its peers
   (section 7.1).

A node must send nothing but `register` (or `pair`) before `registered`, and must send it within
30 seconds of `hello`; otherwise the relay closes `4000`. A connection that has not registered
(a pairing newcomer's included) may send at most 16 WebSocket frames, control frames included;
the 17th closes it `4000`. Malformed ids, or keys and signatures of
the wrong length, are shape errors (`4000`). Per-IP limits are checked before signatures; over
the limit, the relay answers `rate_limited` and closes `4002`. Membership is checked before a
network the relay does not know is created, so a non-member never uses up an IP address's
allowance of new networks. A second registration for the same node replaces the first
connection, which is closed `4005`.

When a presented roster has the same version as the relay's but different contents, the relay's
copy wins and nothing is sent back.

### 4.2 Rosters at the relay

- The relay keeps, in memory, the newest valid roster per network. The network's **primary**,
  for the relay, is the member that roster names primary; its connection is the **primary
  connection**, and every other is a member connection.
- The primary pushes every new roster: `{"type":"roster","roster":{ ... }}`. The relay accepts it
  from any member of the network, if valid and newer: it is signed with the network key, so
  whoever delivers it, a holder of the network seed signed it (a node claiming the primary is
  not yet the relay's primary when it pushes, section 3.1). It then closes `4008` every
  connection of that network whose node is no longer a member. There is no acknowledgement. An
  invalid or older roster is answered with error `bad_request`, and an equal version is ignored.
- **A new primary.** When the roster the relay adopts, at a push or at a registration, names another
  member primary, the relay demotes the former primary's connection in place: it MUST NOT close
  or disconnect it, and no close code is used. That connection stays registered as an ordinary
  member connection, and the node goes on sending and receiving as before. The relay ends every
  pairing channel of the demoted connection as when a primary leaves (section 5.2: `pairEnd` to
  both sides, the newcomer closed `1000`), answers that node's `usage` asks `forbidden` from
  then on, and treats the new primary's connection, if it is connected, as the primary
  connection at once.
- After registration, an unknown control message type is answered `bad_request` and the
  connection stays open. A node sending a frame of type `0x04` or an unknown type is closed
  `4000`.
- The relay's roster is a cache: it forgets a network's roster once it has had no connected
  member for `LINK_NETWORK_TTL` (default 7 days), or sooner to stay within
  `LINK_IDLE_ROSTERS_BYTES`, first cutting it to a compact record (section 9). Members do not
  depend on it for revocation (section 8).

### 4.3 Usage

Usage is request-only: the relay never pushes these figures. What a member needs to know at
once, whether its network is slowed and the rate it is shaped at, the relay pushes as `shaping`
(section 9), so no one polls usage for it.

- The primary may send `{"type":"usage","id":"<request id>"}`. The relay answers:
  ```json
  {"type":"usage","id":"<request id>",
   "network":{"bytesHour":0,"connections":3,
              "limits":{"rateBps":1048576,"quotaBytesHour":0,"trickleBps":16384},
              "quotaUsed":0.0,"slowed":false}}
  ```
  `bytesHour` is what the network was charged (section 9) over the last hour, in five-minute
  steps. `connections` counts its connected members. A `quotaBytesHour` of `0` means no quota,
  and `quotaUsed` is then `0`. Each member counts its own traffic; the relay keeps no
  per-member figures.
- Asks are limited per network: one every 10 seconds, with no burst. An ask within 10 seconds
  of the last one the relay took is refused at once, not queued:
  `{"type":"error","code":"rate_limited","id":"<request id>"}`. The limit is what keeps anyone
  from hammering the relay; an ask within it is answered at once (section 9), however busy the
  network.
- A `usage` request from a node that is not the primary (section 4.2) is answered
  `{"type":"error","code":"forbidden","id":"<request id>"}`.
- Asks, answers and refusals are charged to the network like any other traffic (section 9).

### 4.4 Errors

Non-fatal problems are answered `{"type":"error","code":"<code>","message":"<text>"}`, with `id`
when answering a request. Codes: `forbidden`, `bad_request`, `unreachable`, `rate_limited`.

## 5. Pairing

### 5.1 Codes

- A pairing code is 8 characters from Crockford's base32 alphabet
  (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`), displayed as `XXXX-XXXX`. The hyphen is not part of the
  code; input is upper-cased, and `I`/`L` read as `1`, `O` as `0`.
- Each code has a **code id**: 8 random bytes, `b64u` in links and JSON.
- A code lives 15 minutes and admits one node.
- Five failed confirmations burn the code. A slot is reserved when an attempt starts; a failed
  confirmation keeps it; a timeout or a dropped connection refunds it.
- **Pairing parameters.** What a newcomer needs is the string
  `v=1&n=<network id>&c=<code>&i=<code id b64u>&r=<relay URL>`: parameters separated by `&`, each
  `name=value`, every value percent-encoded as ECMAScript's `encodeURIComponent` does (its UTF-8
  bytes, all but `A-Z a-z 0-9 - _ . ! ~ * ' ( )` as `%XX` in upper-case hex). `c` carries the
  code without the hyphen. A writer writes the five in this order, and refuses a relay that is not
  a relay URL (section 3.2). A reader takes them in any order, skips empty parts, ignores names it
  does not know, accepts the code in its displayed form or any spelling the first item allows,
  and refuses (`invalid`): a part without `=`; a name given twice; a value whose percent-encoding
  is malformed or does not decode to UTF-8 (`+` stays `+`, not a space); a missing or empty `v`,
  `n`, `c`, `i` or `r`; a `v` other than `1`; an `n` that is not a network id, a `c` that is not
  a code, an `i` that is not 8 bytes; an `r` that is not a relay URL.
- **Wrappings.** Link defines the pairing parameters, not a scheme. An application carries them
  as it likes, and each form it uses is one wrapping of them, read by taking the parameters back
  out. The clients write and read one, the **pairing link**
  `frontier://pair?<pairing parameters>`. Another is an https URL's fragment,
  `https://<host>/#<pairing parameters>`, which a browser never sends to the host.
- A malformed pairing message (an invalid point, a wrong length, a P5 that will not open) counts
  as a failed confirmation.

### 5.2 Finding the primary

1. The newcomer connects to the relay, receives `hello`, and sends
   `{"type":"pair","network":"<id>","code":"<code id b64u>"}` instead of `register`.
2. If the network's primary (section 4.2) is not connected, the relay answers
   `{"type":"error","code":"unreachable"}` and closes `1000`.
3. Otherwise the relay picks a random 16-byte **channel id**, sends
   `{"type":"pairing","channel":"<b64u>"}` to the newcomer, and
   `{"type":"pairing","channel":"<b64u>","code":"<code id b64u>"}` to the primary.
4. From then on, binary frames of type `pair` (section 6) between them carry the channel id in
   the peer field, and the relay forwards them. The relay ends the channel (and closes the
   newcomer's connection `1000`) when either side sends `{"type":"pairEnd","channel":"<b64u>"}`,
   when the newcomer disconnects, or after 60 seconds. In every case the relay sends `pairEnd`
   to whichever side is still connected, so the primary learns that a newcomer left mid-pairing
   and can refund its guess slot.
5. Pairing attempts are limited per IP address (section 9). Anyone holding a code id (the
   relay, an observer of a `ws://` connection, or whoever has the link) can deny pairing on
   that code without burning it, by opening channels on it and holding all five attempts in
   flight until each times out. This is accepted: the code id travels with the code, so it
   cannot be kept from those who see the code travel, and the relay can stop any pairing
   anyway by not forwarding it. The primary opens a new code.
6. The primary refuses a `pairing` it cannot serve with `pairEnd`, and a relay can stream
   such `pairing`s, so neither answers nor events are one per message:
   - for a code it issued (now closed, expired, used or out of attempts, remembered for the
     last 1024 codes closed), a `pairEnd` for the first refusal on each pairing channel, and
     for repeats on that channel at most once a second per code and channel; an event for its
     application at most once a second per code and reason. These are kept apart from the
     budget below, and the repeats are counted per channel, not per code, so that neither
     made-up ids nor anyone else holding the code id can use up the answer an honest newcomer
     with a mistyped or expired code is owed (it would otherwise wait out the relay's 60
     seconds);
   - for a code id it never issued, which only a relay can make up, a `pairEnd` within one
     budget of 32 a second with a burst of 64, and never an event.
7. Setting up a pairing channel costs the primary a SPAKE2 setup, and a `pairEnd` refunds the
   attempt it reserved (section 5.1), so the five attempts do not bound how often a relay (or a
   holder of the link) can set channels up and end them. Each open code therefore has a budget
   of channel setups, 4 a second with a burst of 8; a `pairing` beyond it is refused as for a
   code out of attempts (item 6), with the same reason code, but any text that goes with it says
   to try again: the code is not spent, and an honest newcomer caught by it can retry. A channel
   that ends without a failed attempt (the newcomer left, the relay or the primary timed it out,
   the primary's connection dropped, the newcomer is already a member) tells the application at
   most once a second per code and reason, as a refusal does. Failed attempts are bounded by the
   five already, and each is told.

### 5.3 The exchange

SPAKE2 exactly as RFC 9382 with ciphersuite P256-SHA256-HKDF-HMAC, with these parameters:

```
w     = HKDF-SHA256(ikm = UTF-8(code without hyphen, upper-case), salt = empty,
                    info = "frontier-link/1/spake2/w", L = 40), read big-endian, mod n.  w = 0 is refused.
A     = newcomer (uses M);  B = primary (uses N)
idA   = "frontier-link/1/newcomer"     idB = "frontier-link/1/primary"
pA, pB: uncompressed SEC1 points (65 bytes). x, y from 48 random bytes, mod n.
TT    = as RFC 9382: L(idA) idA L(idB) idB L(pA) pA L(pB) pB L(K) K L(w) w   (L = u64 little-endian length; w as 32 bytes big-endian)
hash  = SHA-256(TT);  Ke = hash[0..16];  Ka = hash[16..32]
KcA || KcB = HKDF-SHA256(ikm = Ka, salt = empty, info = "ConfirmationKeys" || codeId (8 raw bytes), L = 32)
cA    = HMAC-SHA256(KcA, TT);   cB = HMAC-SHA256(KcB, TT)
```

Messages, each the body of one `pair` frame:

| # | Direction | Body |
|---|---|---|
| P1 | newcomer → primary | `pA` (65 bytes) |
| P2 | primary → newcomer | `pB` (65 bytes) |
| P3 | newcomer → primary | `cA` (32 bytes) |
| P4 | primary → newcomer | `cB` (32 bytes), sent only after `cA` verifies (constant-time compare) |
| P5 | newcomer → primary | sealed `{"ed25519":"<b64u>","x25519":"<b64u>"}` |
| P6 | primary → newcomer | sealed `{"roster":{ ... }}`: the new roster, already including the newcomer |

Sealing for P5 and P6:

```
okm = HKDF-SHA256(ikm = Ke, salt = hash, info = "frontier-link/1/pair-transport", L = 64)
newcomer → primary key = okm[0..32];  primary → newcomer key = okm[32..64]
ChaCha20-Poly1305, nonce = 4 zero bytes || u64le(counter), counter starting at 0 per direction,
empty associated data. Plaintext is UTF-8 JSON.
```

After P6 the primary burns the code, pushes the new roster to the relay and its members (all but
the newcomer, which holds it already from P6 and is not yet connected as a member, so a push to
it would only fail and be tried again, section 8), and sends `pairEnd`. It tells its
application the new member's node id and the code id that admitted it: an application that
labels its members does so by the code it opened for each. The newcomer pins
`networkKey` from the roster, checks it lists itself, and reconnects to register as a member.

A primary that stops being one (section 3.1) closes every code it opened and ends every pairing
channel it holds; the relay ends them too.

## 6. Routed frames

Every binary WebSocket frame:

```
offset 0   1 byte    version = 1
offset 1   1 byte    type
offset 2   16 bytes  peer
offset 18  ...       body
```

`peer` is a raw 16-byte node id (the bytes before `b32`). On a frame a node sends, it names the
recipient; the relay replaces it with the sender's id before delivery. For `pair` frames it is
the channel id, unchanged.

| Type | Name | Body |
|---|---|---|
| `0x01` | handshake-init | `u32be(sender index) || Noise message 1` |
| `0x02` | handshake-resp | `u32be(sender index) || u32be(receiver index) || Noise message 2` |
| `0x03` | data | `u32be(receiver index) || ciphertext` |
| `0x04` | unreachable | empty; relay → sender: the named peer is not connected |
| `0x05` | refused | `u8(reason)`; a member will not talk to the sender. Reason `1`: not on my roster |
| `0x06` | pair | a pairing message (section 5.3) |
| `0x07` | reset | `u32be(index)`; member → member: I hold no session with this receiver index |
| `0x08` | control | as `0x03`; a session message other than `message` (section 7.3) |

- The maximum binary frame is 1 MiB (1048576 bytes) including the header. Larger frames close
  the connection `4000`.
- The relay forwards `0x01`–`0x03`, `0x05`, `0x07` and `0x08` only between registered members of
  the same network, and answers `0x04` when the peer is not connected. It never parses bodies.
- **Control.** A node may send a session message other than `message` (credit,
  roster-request, roster, resign) as `0x08` instead of `0x03`, only to a relay whose `hello`
  lists `control`. The body is exactly that of `0x03`: the same session, the same nonce
  sequence. The relay delivers it as `0x03`, so a receiver never sees `0x08` and needs no new
  behaviour; the type only lets the relay keep such frames ahead of shaping (section 9). A
  relay without `control` closes `4000` on `0x08`.
- A pairing newcomer's `pair` frames are at most 1024 bytes each; a larger one closes it `4000`.

## 7. Sessions

### 7.1 Handshake

`Noise_IK_25519_ChaChaPoly_SHA256`. The initiator takes the responder's static key from the
roster.

- Prologue: `UTF-8("frontier-link/1/session") || UTF-8(network id)`.
- Message 1 payload: `u64be(roster version the sender holds) || u64be(stamp)`, 16 bytes.
  Message 2 payload: `u64be(roster version the sender holds)`, 8 bytes.
- **Stamps.** `stamp` is milliseconds since the Unix epoch, greater than every stamp this node
  has sent before, to any peer, since it started: `stamp = max(wall clock now, last stamp + 1)`.
  The last stamp is kept in memory only; after a restart a node's stamps come from its wall
  clock alone. The stamp is the one use of the wall clock in a handshake, so that it outlasts a
  restart.
  Let `W` be 10 minutes. The relay refuses a registration whose `ts` is more than 5 minutes from
  its own clock (section 4.1), so any two registered members' clocks are within 10 minutes of
  each other: `W` covers every honest difference, slow or fast.
  The responder keeps, per member id, the stamp of the last init it accepted from it. When an id
  leaves the roster its stamp is kept, among the last 1024 ids to leave, and restored if the id
  is admitted again, so inits from before a revocation stay refused exactly, whatever the clocks
  say. An init must be stamped after the greater of that stamp (if any) and `F = S - W`, where
  `S` is the later of the responder's start and the moment the id joined its roster, taken on
  the monotonic clock and read as wall time when used (`wall now - (monotonic now - instant)`),
  so a correction of the wall clock after it does not move `F`. `F` is what refuses old
  recordings after a responder restarts, when no stamp is stored; with a stamp kept across a
  removal, it still refuses an init recorded but never delivered before the removal once the
  re-admission is more than `W` after it. A registered member is never refused by `F`: its clock
  is at most `W` behind. The responder also refuses an init stamped more than `W` ahead of its
  own wall clock, and stores nothing for it. A refused init is dropped unanswered, counts as a
  failed init (section 7.4), and changes nothing (no session, no stamp, and its version is
  ignored). An init that passes the key check and is accepted stores its stamp as it is; nothing
  else changes the stored stamp. The table outlives every session with a member: it changes only
  as above, never when sessions end or go idle, or a replay of a member's last init would be
  accepted again. A message 1 whose payload is not 16 bytes is malformed, a failed init too.
  This closes IK's replay gap: message 1 has no replay protection of its own, so before stamps a
  relay or a `ws://` observer that recorded one genuine init could send it again at will, to
  evict a live session, cost the responder a full handshake, or draw a roster push. What
  remains, and is accepted:
  - after a responder restarts, an init recorded in the `W` (10 minutes) before the restart can
    be replayed, each at most once and in ascending order: the table is not persisted, and `F`
    bounds how far back it reaches;
  - an initiator whose clock runs more than `W` ahead of a responder's is refused, visibly, for
    as long as it does (the relay refuses its registration then anyway), and accepted again as
    soon as its clock is right: nothing it sent while ahead was stored;
  - an initiator whose clock steps back below a stamp a responder stored for it (corrected, or a
    different device restored from the same seed) is refused by that responder until its clock
    passes that stamp again, for at most `W` when the stamp was within `W` of the responder's
    clock. A browser member restarts on every page load, which by itself costs nothing: its
    stamps come from its wall clock again, still ahead of every stamp it sent before.
- **Indices.** Each side picks a random non-zero 32-bit index for the session and sends it as
  `sender index`. A data frame names the **receiver's** index, so a receiver can tell sessions
  apart during rekeying.
- The responder looks up the initiator's static key (learned from message 1) on its current
  roster, and requires that entry to be the member the relay named as the frame's sender. Either
  check failing: it answers `refused` with reason `1` and drops the handshake. The initiator
  likewise checks the responder's key when it reads message 2.
- **Rosters spread member to member.** If a payload shows the peer holds a newer roster, the
  side that is behind asks that peer for it (`roster-request`, section 7.3; the primary when it
  cannot open a session to the peer). If it shows the peer is behind, and the peer is on this
  side's roster, this side sends the peer its roster. A roster is accepted only under section
  3's rules, signed by the pinned network key, so it may come from any member.
- Handshake timeout: 10 seconds per message.

### 7.2 Transport

- After the handshake, each direction uses its Noise CipherState: ChaCha20-Poly1305 with the
  64-bit counter nonce, never transmitted. Frames for one pair arrive in order, so a frame that
  fails to decrypt ends the session; the next send starts a new one.
- A Noise message is at most 65535 bytes, so one transport plaintext is at most 65519 bytes.
  A receiver checks this before decrypting: a data frame whose ciphertext is longer ends the
  session, as a frame that fails to decrypt does.
- **Unknown sessions.** A data frame naming a receiver index the receiver does not hold is
  answered with `reset` (within the rates of section 7.4). The sender drops that session, and
  its next send starts a new handshake.
  The message in that frame is lost.
- **What the relay can do to sessions.** The relay cannot read, forge or alter a session
  message, but it routes every frame, so it can drop, delay or replay frames and forge `reset`,
  `refused` and `unreachable` naming any peer. Each of these ends sessions or the handshakes
  behind them, and the next send starts again. This is inherent in routing through it and
  accepted: it denies service, as a relay that stops forwarding does anyway, and never yields
  content, keys or membership. The rates of section 7.4 keep it from turning such frames into
  unbounded work.
- **Delivery is at most once.** `send` completing means the message was handed to the relay.
  Applications that need confirmation build it on top. A client ends all its sessions when its
  own relay connection drops.
- **Rekeying:** the initiator starts a new handshake after 10 minutes or 2^32 messages in either
  direction, whichever comes first. A responder treats a session older than 10 minutes and 30
  seconds as expired, and answers `reset`, except while a message is still crossing it, which
  always completes first. Both sides keep the previous session's keys for 30
  seconds, for frames already in flight, and longer while a message is still crossing it: a
  message is never split across two sessions.
- **Idle:** a session with no frame in either direction for 10 minutes is forgotten.

### 7.3 Session messages

Each decrypted plaintext starts with a type byte:

| Type | Name | Rest |
|---|---|---|
| `0x01` | message | `u8(flags) || bytes`. Flag bit 0 set: more fragments follow. |
| `0x02` | credit | `u32be(bytes)`: the receiver allows this many more message bytes |
| `0x03` | roster-request | empty |
| `0x04` | roster | UTF-8 JSON roster |
| `0x05` | resign | UTF-8 JSON `{"node":"<id>","ts":1790000000000,"sig":"<b64u>"}`, sent to the primary |

- **Messages** larger than one fragment (65517 bytes of `bytes`) are split, joined by the
  receiver, and delivered to the application whole and in order. Maximum message size: 64 MiB.
  A fragment with flag bit 0 set carries at least one byte. A session message that breaks the
  table (an empty fragment saying more follow, a `credit` not of 4 bytes, an unknown type) ends
  the session; so does a message over 64 MiB.
- **Credit (flow control).**
  - Every session starts with **1 MiB** of credit in each direction. A sender may only send
    message bytes (the `bytes` of `message` plaintexts) up to the credit it holds, and waits
    otherwise.
  - The receiver enforces it. Per session it counts the credit it has granted (the initial
    1 MiB and every `credit` it sent) less the message bytes received; a peer that sends message
    bytes beyond that ends the session. Credit still on its way only leaves the sender holding
    less than the receiver counts, never more.
  - The receiver returns credit with `credit` messages: for complete messages as its application
    takes them, and for fragments of a message still arriving while the application has
    nothing waiting, so a message larger than the window cannot deadlock.
  - Credit is returned in batches: at once when 65536 bytes or more are owed, and otherwise
    no later than 250 ms after credit began to be owed. One `credit` message per received
    message would make credits a large share of all frames.
  - A receiver that wants a larger window (a client setting) simply grants extra credit at any
    time. Nothing is negotiated.
  - Credit and reassembly belong to one session.
- **Per-peer bounds.** Whatever a peer does, a receiver keeps for it, over all its sessions with
  that peer: at most `2 × 64 MiB + 4 × window` message bytes in reassembly or waiting for the
  application (`window`: the credit this receiver grants each session, 1 MiB by default); at
  most 65536 whole messages waiting for the application; at most 8 sessions. A fragment that
  would take the peer past either message bound ends its session, and the message is lost
  (delivery is at most once); a ninth session ends the oldest that is not current. An honest
  sender stays within them: credit is returned for fragments only while nothing waits on that
  session, so at most one whole message waits on a session while the next arrives on the
  session a rekey made, and a reassembly buffer never holds more than its message's bytes.
- **Reassembly memory.** These bounds count payload bytes, so an implementation must also keep
  the memory reassembly takes in proportion to them, however the message was cut. A peer may
  send one-byte fragments, and storing each as its own buffer or list entry multiplies the
  bounds by that per-fragment overhead, many times over; joining fragments into one buffer as
  they arrive keeps it within twice the payload.
- **Rosters.** Any member answers `roster-request` with the newest roster it holds, within the
  rates of section 7.4. A member that receives a `roster` applies the acceptance rules of
  section 3.
- **Resigning.** `sig` = Ed25519 by the member over
  `lenStr("frontier-link/1/resign") || lenStr(network) || lenStr(node) || u64be(ts)`. The primary
  accepts it only from that member's own session and with `ts` within 5 minutes of its clock,
  then publishes a roster without the member. Neither the primary nor a node started with the
  network seed resigns.

### 7.4 Rates

What a peer (or a relay forging frames, which it can) gets a member to do in return is bounded,
so that small frames cannot buy large or costly answers. Every budget belongs to one id: a peer
that floods spends only its own, and can never use up what another peer is owed. A budget
shared between peers would let one starve the others (a single bucket for all resets let one
member's flood cost another peer the resets it was owed; one bucket for all ids off the roster
let forged ids drop a newly added member's handshakes). A limit over many ids together exists
only as a backstop on memory or work that a relay forging ids could otherwise reach; members
never share a rate budget.

- **Rosters to a peer.** A member sends one peer its roster, whether answering a
  `roster-request` or pushing it because a handshake showed the peer behind (section 7.1), at
  most once per 250 ms; offers within that interval are coalesced into one at its end. A roster
  can be 65000 bytes; the routed frame asking for it is 39. A push needs no request at all: a
  peer that sends handshakes showing an old roster version draws one each time, so pushes are
  coalesced like answers. (A replayed init no longer can: its stamp refuses it, section 7.1.)
- **One roster in flight.** A member does not queue a roster to a peer while one at least as
  new is still waiting, unsent, in its connection's send buffer: that one already says as much.
  This holds for every roster sent, answered, pushed or published.
- **Resets.** A `reset` for one peer and receiver index goes out at most once per second, and to
  one peer at most 32 a second with a burst of 64. Resets to ids off the roster also draw on a
  ceiling for all of them together, 128 a second with a burst of 256, which only forged ids
  reach. A frame beyond that is dropped unanswered.
- **Handshakes.** A responder does the Diffie-Hellman work of a `handshake-init` from one roster
  member at most 16 times a second with a burst of 32. An id off its roster gets its own budget
  of 4 a second with a burst of 8, and its own reset budget; budgets are kept for the 256 most
  recently seen such ids, the least recently seen forgotten first. Beyond those, inits from all
  ids off the roster together are processed at most 128 a second with a burst of 256: a
  ceiling on work, which only a relay forging ids can reach, since a member always arrives
  under its own id. An init beyond a budget is dropped unanswered; its sender times out and
  retries (section 7.1).
- **Failed inits.** A relay can label inits built on its own key with a roster member's id, and
  a member can send inits under its own id with a bogus static key, so per-member init budgets
  alone leave the Diffie-Hellman work of failures to anyone who wants it. Each member id
  therefore also has a failure budget, 2 a second with a burst of 4, apart from its init budget.
  An init labelled with that id fails when it does not read, when its static key is not that
  member's, when it is on the member's key but its payload is not the 16 bytes of section 7.1
  (malformed), or when its stamp is not later than the last accepted (a replay); each failure
  spends the budget, and while it is spent that id's inits are dropped before any Diffie-Hellman
  work. An init on another key is answered `refused`; the other failures are dropped unanswered.
  The version a failed init claims is ignored: it says nothing about the member named, so it
  triggers neither a roster push nor a `roster-request` to that member (a forged one could
  otherwise steer full rosters at any member). The budget is per id, never shared: a shared one
  (tried, and proven exploitable) let a few members sending bad inits under their own ids block
  every honest member's handshakes. Per id, a member sending bad inits starves only itself, a
  relay forging an id silences only that id (which it can do anyway by not forwarding its
  frames), and the work all failures cause stays within the roster's size times 2 a second.
- **Ids off the roster.** An id off the roster may be one a roster the member has not seen lists
  (a newcomer, say). Two things hint at that: any init from an id off the roster that a budget
  drops, whatever it carries (its version is never read), and an init from such an id that is
  read and refused, if the version it carries is newer than the member's. On a hint the member
  asks the primary for its roster, then waits before the next: 1 second at first, doubled after
  each hint that brought no newer roster, up to 5 minutes, and back to 1 second once a newer
  roster arrives. A relay can provoke hints on every node at once, and each answer is a full
  roster from the primary, so a fixed once a second would cost the primary as many rosters a
  second as there are members. A hint that comes within the wait is deferred, not dropped: one
  request goes when the wait ends, however many hints came, so a node at the longest wait still
  learns of a newer roster (one that revokes someone, say) within it. No other init prompts that
  request, and a failed init labelled with a member's id never does.
- **Reconnecting.** Budgets carry across relay connections and refill only with time, from
  their last use: a relay that forces reconnects gains no budget by it. An offer coalesced for
  the end of an interval is dropped with the old connection, but when the last roster went to
  each peer is kept.

Every rate, interval and timeout of this section and of sections 5.2, 7.2 and 11 is measured on
a monotonic clock, one that never goes back. The wall clock serves only for times that are
signed or shown (`ts`, `issuedAt`, a code's expiry as displayed): a wall clock stepped back (by
NTP, or a restored virtual machine) would otherwise strand a budget, or hold back a roster
offer, for as long as the step, and budgets now carry across reconnects, so nothing else would
reset them.

The rates are token buckets: a burst's worth to begin with, refilled at the rate. They are
maxima: an implementation may answer, push or process less (a separate budget for `refused`
answers, say), never more. A peer must not rely on any answer a rate may drop; each has a
timeout or a retry behind it. The same holds for the limits of sections 5.2 and 11.

## 8. Revocation

- The primary publishes a roster without the member, pushes it to the relay (section 4.2) and to
  every member. A push to a member that fails (the member unreachable, the primary's own
  connection down) is tried again after 1 second, doubling to at most 10 minutes, until it goes,
  the member leaves the roster, or a newer roster replaces it (which is then pushed in its
  stead). Without that, a member with no traffic of its own would keep the old roster, still
  trusting the revoked member, until its next handshake.
- Members drop sessions with peers no longer on the roster, and refuse their handshakes. A
  member that was offline learns the new roster from the relay at registration, or from the
  first up-to-date member it meets (section 7.1), so revocation reaches it with the primary
  offline and whatever the relay remembers: members enforce it themselves, and the relay is not
  trusted to.
- A network whose seed is lost cannot change its roster again: there is no second key that
  could sign one, by design, since any such key could also admit or revoke. The way back is a
  new network, with every node paired again. A new primary (section 3.1) uses the one seed; it
  never makes a second.
- A client whose registration is closed `4008`, or that accepts a roster no longer listing it
  (in `registered`, from the primary or from a peer), enters a terminal `revoked` state and
  stops retrying. It is never `registered` (connected) after that, not even for the
  `registered` message that carried the roster.

## 9. Relay limits and flow control

All limits apply per network unless stated, slow traffic rather than closing, and are settings.
A self-hosted relay defaults every limit to off; the values below are the public relay's.

| Setting | Meaning | Public default |
|---|---|---|
| `LINK_RATE_BPS` | bytes per second charged to a network | 1048576 |
| `LINK_QUOTA_BYTES_HOUR` | quota over the last hour (0 = none) | set per deployment |
| `LINK_TRICKLE_BPS` | rate once the quota is spent | 16384 |
| `LINK_QUEUE_BYTES` | bytes held in the relay for one recipient before its senders pause | 0 |
| `LINK_SLOW_PEER_SEC` | a recipient that drains nothing this long with a full queue is closed `4006` | 30 |
| `LINK_IP_REGISTER_PER_MIN` | registrations per IP address | 60 |
| `LINK_IP_PAIR_PER_MIN` | pairing attempts per IP address | 60 |
| `LINK_IP_NETWORKS_PER_HOUR` | new networks first seen from one IP address | 10 |
| `LINK_IP_PENDING` | connections from one IP address not registered yet (pairing newcomers included) | 16 |
| `LINK_IP_CONNECTIONS` | connections from one IP address in all | 1024 |
| `LINK_NETWORK_TTL` | forget an idle network's roster after | 168h |
| `LINK_IDLE_ROSTERS_BYTES` | memory for the rosters of networks nobody is connected to; beyond it, room is made at the address holding the most | 1073741824 |
| `LINK_ORIGIN` | the origin used to check signatures (else the request's Host) | — |
| `LINK_TRUST_PROXY` | the number of proxies in front of the relay (`true` = 1, `false` = 0) | 0 |
| `LINK_ADDR` | listen address | `:8080` |

- **Charging.** Every frame a registered member sends the relay (routed frames, the primary's
  `pair` frames included, control messages, WebSocket pings and pongs) and every answer the
  relay sends it in return (`error`, `usage`, `unreachable`) is charged to the member's network,
  by its size on the wire (the WebSocket frame, header included), whether or not it reaches a
  recipient. The rate and the quota both count charged bytes. A pairing newcomer, which has no
  network yet, is not charged; its frames are limited instead (sections 4.1 and 6).
- **Shaping.** When a network is over its rate, the relay holds back the connection that
  sends next: it reads the header of its next data frame and does not read that frame's body,
  or anything behind it, until the network's bucket allows (one second of burst). A network
  over its quota is shaped at `LINK_TRICKLE_BPS`. Frames are never dropped. The **rate in
  force** is `LINK_RATE_BPS` (`0`: none), or `LINK_TRICKLE_BPS` once the quota is spent.
- **The shaping notice.** `{"type":"shaping","rateBps":16384,"slowed":true}`: `rateBps` is the
  rate in force, `0` for none; `slowed` is whether the trickle rate is in force (as `usage`
  says). The relay sends it to a member right after `registered`, and to every connected member
  of the network as soon as either value changes: the charge that spends the quota, the
  trickle lifting (the last hour's charges below the quota again, which the relay looks for
  at least once a second while a network is slowed, with or without traffic), and a reload of
  the limits (`LINK_LIMITS_FILE`) that changes them. Notices go out in the order the changes
  happened. A notice is not charged. A member keeps to it (section 11), and a node ignores
  fields it does not know.
- **Grace.** When the quota is spent, the trickle is announced at once, but the relay goes on
  shaping the network at `LINK_RATE_BPS` (or not at all, without one) for one second more:
  what members had handed their connections before the notice reached them is read then,
  rather than at the trickle rate in front of their control. A grace begins only when the
  network becomes slowed, which its hour's window allows at most once per five-minute step,
  and at a reload; every byte is charged as ever.
- **Control ahead of shaping.** Text control messages, WebSocket pings and pongs, and routed
  frames of types `0x01`, `0x02`, `0x05`, `0x06`, `0x07` and `0x08`, each sent as one
  unfragmented WebSocket frame, are read at once while the sending member's own control budget
  allows: 4096 bytes per second, with 131072 bytes of burst. Beyond the budget, and for any
  fragmented message, control waits like data. It is charged like data either way. The budget is
  each member's, never the network's: one budget for the network let one member spend it and
  hold back every other member's handshakes and control. It belongs to the member, kept by node
  id across its connections, so reconnecting buys no fresh burst. A ceiling for the whole
  network bounds them all together, and is tied to the rate in force: 64 members' budgets
  (262144 bytes per second), but never more than half the network's rate, and half the trickle
  rate once its quota is spent; its burst is four members' bursts, or a second of the ceiling if
  more, up to 64 members'. Control read ahead is charged but not held back, so a ceiling above
  the rate in force would let members, each within its own budget, carry ordinary traffic past
  the network's rate or quota in `0x08` frames. At half of it, control read ahead moves no more
  than half the rate in force over time, beyond its burst (512 KiB, or a second of the ceiling
  if more): a one-off allowance that then refills at half the rate. No one member's burst
  empties the ceiling. This lets control past held data only when it is the next frame on its
  connection: one stream is read in order, so data a member has already sent, in its socket
  and the relay's, is read at the rate in force before anything behind it. A member therefore
  keeps its data in its own queue and paces it to the rate in force (section 11).
- **The relay's own messages first.** What the relay writes to a member goes in two lanes. The
  relay's own messages (`hello`, `registered`, `shaping`, `error`, `usage` and, on a pairing
  channel, `pairing`, `pairEnd` and the `pair` frames it forwards) are written ahead of the
  routed frames queued for that member, and WebSocket pings and pongs ahead of both. Each lane
  keeps its order, so routed frames stay in order and a channel's `pairing`, `pair` frames and
  `pairEnd` stay in theirs; `unreachable` goes with routed frames; a frame begun is finished
  first. The relay also keeps what its kernel holds unsent for a connection small (64 KiB,
  through `TCP_NOTSENT_LOWAT` where the system has it), so an answer waits behind at most
  that, the frame being written and what is in flight, never behind the routed frames queued
  for a member, whatever `LINK_QUEUE_BYTES` lets the relay hold.
- **Back-pressure.** A sender that hands a frame to a recipient whose queue in the relay (both
  lanes) then holds more than `LINK_QUEUE_BYTES` (0: anything at all) stops being read until
  that queue drains. With the default, each sender has at most one frame waiting for a
  recipient, the relay holds no other buffer, and everything else is TCP's own flow control:
  the relay stops reading, and the sender's kernel stops sending. A connection's own answers
  (`error`, `usage`, `unreachable`) pause its reading beyond 65536 bytes queued.
- **Liveness.** The relay sends a WebSocket ping every 30 seconds and drops a connection that
  has not answered by the next one. A connection the relay is currently pausing is exempt, since
  its answer may be stuck behind frames held back. A node's own pings are answered with one pong
  for the latest ping.
- **Slowed** means the trickle rate is in effect. A quota without a trickle rate is reported but
  never slows.
- **Connections per address.** An upgrade that would take an address over `LINK_IP_PENDING` or
  `LINK_IP_CONNECTIONS` is answered HTTP 429 before any WebSocket exists. The client backs off
  and retries as after any failed connection.
- **Idle networks.** The relay's roster is a cache of what the primary signed: forgetting it is
  what a restart does, and the next member to register brings it back. It is kept while anyone
  of the network is connected, and after that for `LINK_NETWORK_TTL`, within
  `LINK_IDLE_ROSTERS_BYTES`. While kept, it closes revoked members at registration and brings
  members that were offline up to date, even with the primary offline. An idle network counts
  against the address of the last member connected to it. Over the budget, room is made at the
  address holding the most: its longest idle roster is cut to a compact record (version and
  member ids, enough to go on refusing members it does not list, but not to hand the roster
  out), and a record is forgotten only once all that address's full rosters are cut. A node
  that creates networks to fill memory therefore evicts its own first. A member presenting the
  version a record was cut from restores the full roster.
- **Addresses.** Per-IP limits count IPv6 addresses by their /64 prefix. With
  `LINK_TRUST_PROXY` set to n, the client address is the n-th `X-Forwarded-For` entry counted
  from the right (the one the outermost trusted proxy added), never one the client wrote.
- With `LINK_QUEUE_BYTES` at 0, a recipient's queue counts as full for the slow-peer rule as
  soon as anything is waiting for it.

## 10. Close codes

| Code | Meaning |
|---|---|
| `1000` | normal (pairing finished, or nothing to pair with) |
| `1001` | relay shutting down |
| `4000` | bad request: malformed, oversized or out of order |
| `4002` | rate limited |
| `4005` | replaced by a newer connection for the same node |
| `4006` | slow peer |
| `4007` | registration failed: bad signature, stale time or wrong key |
| `4008` | not a member: not on the roster, revoked or resigned |
| `4009` | moved: the network now lives on another relay node; look it up again |

## 11. Client behaviour

- Reconnect after 500 ms, doubling to at most 10 seconds, forever; reset after `registered`.
  Never after `4008` (revoked) or `4005` (replaced): a replaced connection belongs to a copy of
  the identity that is no longer the current one, and it stops rather than fight the new one.
- A send to a peer that answers `unreachable` fails at once with a typed error. Nothing is queued
  for absent peers.
- On `4009`, look the network up again and reconnect. An answer that is not a URL is ignored,
  as no answer is: the node keeps the relay URL it had.
- **Offline.** A node never stops or crashes for want of a network. An unreachable relay
  (connection refused, a name that does not resolve, no route), a relay that goes away, a lookup
  that fails, or a WebSocket that cannot be made is a connection that failed: the node says so
  through its states (`disconnected`, then `connecting` again) and retries as above, and a call
  that needs the relay (a send, a usage ask, a roster sync) fails with its own error. Nothing is
  thrown out of a socket's callbacks or a timer, and no promise is left to reject unhandled. Only
  what its caller gives wrongly at the start (a roster not placed and no relay URL, section 3.2;
  a relay URL that is not a URL) is refused at once, as a caller error.
- **A new primary closes nothing.** A node whose roster stops naming it primary, or starts to,
  keeps its connection and its sessions: it neither closes nor reconnects (section 3.1), and the
  relay closes neither (section 4.2).
- **Relay errors.** `error` messages from the relay reach the application at most 16 a second
  with a burst of 64; the rest are dropped. A relay's messages never raise an event each without
  a bound.
- **Shaping.** A client holds the last `shaping` its relay sent (section 9), as a property an
  application can read at any time, and raises an event when it changes, so an application
  never polls usage to learn its network is slowed. Before any notice, and on a connection to
  a relay whose `hello` does not list `shaping`, it is `rateBps` 0 and not slowed. A notice
  whose `rateBps` is not a non-negative integer, or whose `slowed` is not a boolean, is ignored.
- **Pacing.** A client keeps message fragments in its own queue (section 7.3), and hands each
  to its connection only when that keeps little in its socket in front of whatever follows, so
  that control, which it hands over at once, ahead of queued fragments, arrives within about a
  second however busy the network. With `R` the `rateBps` in force:
  - `R` = 0: fragments go when the socket holds at most 64 KiB, each of at most 65517 bytes but
    never more than the room under the session's window, at least 16384 bytes, and a session
    has at most the larger of 65536 bytes and one and a half times `C` un-credited, `C` the
    credit returned on it over the last second (the larger of the last whole second and the
    one under way).
  - `R` > 0: the socket rule as above, and the connection's fragments, together, go at most at
    `7R/8` bytes a second, each counted at its frame's size (40 bytes more than its message
    bytes), with no burst: a fragment goes no sooner than the last one's size after the last
    one at that pace. A fragment carries at most `F` = max(1024, min(65517, ⌊7R/32⌋)) message
    bytes, a quarter of a second of the pace, and at least min(16384, `F`), and a session has
    at most max(`F`, min(`C`, ⌊R/2⌋)) message bytes un-credited. The eighth of `R` left over is
    for the frames that are not fragments (credit, handshakes, the peer's own) and WebSocket
    headers.
  A member sending alone is then read as fast as it sends, and its control waits behind about
  one fragment. Members sending at once share the rate: each is read at about its share `S`
  and keeps about a second of `S` un-credited, of which a quarter of a second is the credit
  on its way back, so control waits about 0.75 s behind its own data with two to four members
  sending at once; with more, at least one fragment of each is ahead, about `7N/32 − 1/4` s for
  `N` members. A notice that lowers `R` applies at once to what has not yet been handed over;
  what was handed over before it is what the relay's grace reads.
- **Send buffer.** A client holds at most 64 MiB (67108864 bytes) handed to its connection and
  not yet sent. Message fragments wait in the client's own queue (pacing, above), but control
  (handshakes, `credit`, `reset`, rosters, control messages) is handed over at once; a send that
  would pass the bound drops the connection, which reconnects as after any close, rather than
  growing behind a relay that has stopped reading. The bound is set by the largest honest
  burst: a primary publishing a full roster to about 440 members queues some 29 MB at once, and
  must never be cut off for it, with room left for the handshakes and messages around it and a
  slow link. A bound much nearer 29 MB would drop a primary for doing its job.

## 12. Vectors

`spec/vectors/` holds JSON vectors for: key and id derivation, of nodes and of networks (a
network seed, its network key and network id); roster signing and validation (valid and invalid
cases, among them a roster whose primary is not the node that created the network); the registration signature; SPAKE2 (RFC 9382's, plus this
profile's); the Noise IK handshake and first transport messages; frame encoding; session message
encoding; rosters given as text (`rosterTexts` in `relay.json`), whose validity turns on the
bytes themselves: repeated names, `12.0`, `1.2e1`, `-0` and `1e309`, escaped lone surrogates,
nesting; Ed25519 verification (`ed25519` in `relay.json`): small-order, non-canonical and
mixed-order keys and `R`, `S >= L`, and the order-4 forgery; placing a network
(`roster.placing` in `client.json`: an unplaced version 1 made with a second member listed, its
placed version 2, placings at other relay URLs, and placings refused); pairing parameters
(`pairing.params`: built, wrapped as a pairing link and as an https fragment, a non-ASCII relay,
and cases a reader takes or refuses). Every implementation runs all that apply to it.
