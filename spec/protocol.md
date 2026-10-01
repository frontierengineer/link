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
| Identity and signatures | Ed25519 (RFC 8032) |
| Session key agreement | X25519 |
| Sessions | `Noise_IK_25519_ChaChaPoly_SHA256`, Noise revision 34 |
| Pairing | SPAKE2, RFC 9382, ciphersuite P256-SHA256-HKDF-HMAC |
| Key derivation | HKDF-SHA256 (RFC 5869) |
| Hash | SHA-256 |
| Pairing transport | ChaCha20-Poly1305 (RFC 8439) |
| Canonical JSON for signing | JSON Canonicalization Scheme, RFC 8785 (JCS) |

## 2. Keys and ids

- Each node has a 32-byte **seed** from a secure random source. It never leaves the node.
- `ed25519Seed = HKDF-SHA256(ikm = seed, salt = empty, info = "frontier-link/1/ed25519", L = 32)`;
  the Ed25519 keypair is derived from it as RFC 8032 specifies.
- `x25519Private = HKDF-SHA256(ikm = seed, salt = empty, info = "frontier-link/1/x25519", L = 32)`,
  clamped as X25519 requires.
- **Node id** = `b32(SHA-256(ed25519Public)[0..16])`: 26 characters.
- **Network id** = the node id of the network's primary.
- Public keys in JSON are `b64u` of the raw 32 bytes.

## 3. The roster

```json
{
  "network": "<network id>",
  "version": 12,
  "issuedAt": 1790000000000,
  "relay": "wss://eu.frontierengineer.link/v1",
  "primary": { "ed25519": "<b64u>" },
  "members": [
    { "id": "<node id>", "ed25519": "<b64u>", "x25519": "<b64u>", "kind": "primary" }
  ],
  "signature": "<b64u>"
}
```

- `version` is a positive integer that increases with every change. `issuedAt` is Unix
  milliseconds. `kind` is one of `primary`, `worker`, `surface`, `mcp`.
- `members` is sorted by `id`. Exactly one member has kind `primary`, and its `ed25519` equals
  `primary.ed25519`. Its `id` equals `network`.
- **Signature** = Ed25519 by the primary over
  `UTF-8("frontier-link/1/roster") || JCS(roster with the "signature" member removed)`.
- **Valid** when: the signature verifies against `primary.ed25519`; `network` equals the node id
  derived from `primary.ed25519`; every member's `id` is derived from its `ed25519`; the rules
  above hold.
- A member **accepts** a roster only if it is valid, `primary.ed25519` equals the key the member
  pinned at pairing, and `version` is greater than the version it holds.

## 4. Connecting to the relay

WebSocket over TLS, path `/v1`. Text frames carry control messages, one JSON object each with a
`type`, at most 64 KiB. Binary frames carry routed frames (section 6).

### 4.1 Registration

1. Relay → node: `{"type":"hello","version":1,"challenge":"<b64u 32 bytes>"}`
2. Node → relay:
   ```json
   {"type":"register","network":"<id>","node":"<id>","ed25519":"<b64u>",
    "ts":1790000000000,"sig":"<b64u>","roster":{ ... }}
   ```
   `sig` = Ed25519 by the node over
   `lenStr("frontier-link/1/register") || lenStr(network) || lenStr(node) || challenge (32 raw bytes) || u64be(ts) || lenStr(origin)`,
   where `origin` is the lowercased `host[:port]` of the URL the node dialled (the port only if
   it is not the scheme's default).
3. The relay checks, in this order, and closes with the given code on the first failure:
   1. the message's shape (`4000`);
   2. `node` equals the id derived from `ed25519` (`4007`);
   3. the signature, rebuilt with the relay's own origin and the challenge it sent (`4007`);
   4. `|now - ts| <= 300000` (`4007`);
   5. the roster is valid and its `network` equals `network` (`4008`);
   6. `node` is a member of the roster (`4008`);
   7. the roster's version is not lower than the newest the relay holds for the network
      (`4008`).
4. Relay → node: `{"type":"registered","node":"<id>","rosterVersion":12}`

A node must send nothing but `register` before `registered`. A second registration for the same
node replaces the first connection, which is closed `4005`.

### 4.2 Rosters at the relay

- The relay keeps, in memory, the newest valid roster per network.
- The primary pushes every new roster: `{"type":"roster","roster":{ ... }}`. The relay accepts it
  from the primary only, if valid and newer, and then closes `4008` every connection of that
  network whose node is no longer a member.
- The relay forgets a network's roster once it has had no connected member for
  `LINK_NETWORK_TTL` (default 7 days).

### 4.3 Usage

- The primary may send `{"type":"usage","id":"<request id>"}`. The relay answers:
  ```json
  {"type":"usage","id":"<request id>",
   "network":{"bytesHour":0,"bytesDay":0,"connections":3,
              "limits":{"rateBps":1048576,"quotaBytesHour":0,"trickleBps":16384},
              "quotaUsed":0.0,"slowed":false},
   "members":[{"id":"<node id>","bytesHour":0,"bytesDay":0,"connected":true}]}
  ```
  `bytes*` count bytes relayed from that member (frame bodies and headers). A `quotaBytesHour` of
  `0` means no quota, and `quotaUsed` is then `0`.
- The relay pushes `{"type":"usageAlert","quotaUsed":0.8,"slowed":false}` to the primary when
  `quotaUsed` crosses 0.5, 0.8, 0.95 or 1 in either direction, or `slowed` changes; at most once a
  second.
- A `usage` request from a node that is not the primary is answered
  `{"type":"error","code":"forbidden","id":"<request id>"}`.

### 4.4 Errors

Non-fatal problems are answered `{"type":"error","code":"<code>","message":"<text>"}`, with `id`
when answering a request. Codes: `forbidden`, `bad_request`, `unreachable`, `rate_limited`.

## 5. Pairing

### 5.1 Codes

- A pairing code is 8 characters from Crockford's base32 alphabet
  (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`), displayed as `XXXX-XXXX`. The hyphen is not part of the
  code; input is upper-cased, and `I`/`L` read as `1`, `O` as `0`.
- Each code has a **code id**: 8 random bytes, `b64u` in links and JSON.
- A code lives 15 minutes, admits one node, and fixes its kind (`worker`, `surface`, `mcp`).
- Five failed confirmations burn the code. A slot is reserved when an attempt starts; a failed
  confirmation keeps it; a timeout or a dropped connection refunds it.
- Pairing link: `frontier://pair?v=1&n=<network id>&c=<code>&i=<code id b64u>&r=<relay URL, percent-encoded>`.

### 5.2 Finding the primary

1. The newcomer connects to the relay, receives `hello`, and sends
   `{"type":"pair","network":"<id>","code":"<code id b64u>"}` instead of `register`.
2. If the network's primary is not connected, the relay answers
   `{"type":"error","code":"unreachable"}` and closes `1000`.
3. Otherwise the relay picks a random 16-byte **channel id**, sends
   `{"type":"pairing","channel":"<b64u>"}` to the newcomer, and
   `{"type":"pairing","channel":"<b64u>","code":"<code id b64u>"}` to the primary.
4. From then on, binary frames of type `pair` (section 6) between them carry the channel id in
   the peer field, and the relay forwards them. The relay ends the channel (and closes the
   newcomer's connection `1000`) when either side sends `{"type":"pairEnd","channel":"<b64u>"}`,
   when the newcomer disconnects, or after 60 seconds.
5. Pairing attempts are limited per IP address (section 9).

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

After P6 the primary burns the code, pushes the new roster to the relay and its members, and
sends `pairEnd`. The newcomer pins `primary.ed25519` from the roster, checks it lists itself, and
reconnects to register as a member.

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

- The maximum binary frame is 1 MiB (1048576 bytes) including the header. Larger frames close
  the connection `4000`.
- The relay forwards `0x01`–`0x03` and `0x05` only between registered members of the same
  network, and answers `0x04` when the peer is not connected. It never parses bodies.

## 7. Sessions

### 7.1 Handshake

`Noise_IK_25519_ChaChaPoly_SHA256`. The initiator takes the responder's static key from the
roster.

- Prologue: `UTF-8("frontier-link/1/session") || UTF-8(network id)`.
- Message 1 payload and message 2 payload: `u64be(roster version the sender holds)`.
- **Indices.** Each side picks a random non-zero 32-bit index for the session and sends it as
  `sender index`. A data frame names the **receiver's** index, so a receiver can tell sessions
  apart during rekeying.
- The responder looks up the initiator's static key (learned from message 1) on its current
  roster. Not found: it answers `refused` with reason `1` and drops the handshake. The initiator
  likewise checks the responder's key when it reads message 2.
- If a payload shows the peer holds a newer roster, the side that is behind asks the primary for
  it (section 7.3).
- Handshake timeout: 10 seconds per message.

### 7.2 Transport

- After the handshake, each direction uses its Noise CipherState: ChaCha20-Poly1305 with the
  64-bit counter nonce, never transmitted. Frames for one pair arrive in order, so a frame that
  fails to decrypt ends the session; the next send starts a new one.
- **Rekeying:** the initiator starts a new handshake after 10 minutes or 2^32 messages in either
  direction, whichever comes first. Both sides keep the previous session's keys for 30 seconds,
  for frames already in flight.
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

- **Messages** larger than one frame are split into fragments, joined by the receiver, and
  delivered to the application whole and in order. Maximum message size: 64 MiB.
- **Credit (flow control).** Each side starts with a credit window for the other (a client
  setting, default 1 MiB). A sender may only send message bytes (the `bytes` of `message` plain
  texts) up to the credit it holds, and waits otherwise. The receiver sends `credit` as its
  application consumes messages.
- **Rosters.** Any member answers `roster-request` with the newest roster it holds. A member
  that receives a `roster` applies the acceptance rules of section 3.
- **Resigning.** `sig` = Ed25519 by the member over
  `lenStr("frontier-link/1/resign") || lenStr(network) || lenStr(node) || u64be(ts)`. The primary
  publishes a roster without the member.

## 8. Revocation

- The primary publishes a roster without the member, pushes it to the relay (section 4.2) and to
  every member.
- Members drop sessions with peers no longer on the roster, and refuse their handshakes.
- A client whose registration is closed `4008` enters a terminal `revoked` state and stops
  retrying.

## 9. Relay limits and flow control

All limits apply per network unless stated, slow traffic rather than closing, and are settings.
A self-hosted relay defaults every limit to off; the values below are the public relay's.

| Setting | Meaning | Public default |
|---|---|---|
| `LINK_RATE_BPS` | bytes per second relayed for a network | 1048576 |
| `LINK_QUOTA_BYTES_HOUR` | rolling hourly quota (0 = none) | set per deployment |
| `LINK_TRICKLE_BPS` | rate once the quota is spent | 16384 |
| `LINK_QUEUE_BYTES` | queued bytes for one recipient before senders are paused | 4194304 |
| `LINK_SLOW_PEER_SEC` | a recipient that drains nothing this long with a full queue is closed `4006` | 30 |
| `LINK_IP_REGISTER_PER_MIN` | registrations per IP address | 60 |
| `LINK_IP_PAIR_PER_MIN` | pairing attempts per IP address | 60 |
| `LINK_IP_NETWORKS_PER_HOUR` | new networks first seen from one IP address | 10 |
| `LINK_NETWORK_TTL` | forget an idle network's roster after | 168h |
| `LINK_ORIGIN` | the origin used to check signatures (else the request's Host) | — |
| `LINK_TRUST_PROXY` | take the client IP from the first `X-Forwarded-For` hop | false |
| `LINK_ADDR` | listen address | `:8080` |

- **Shaping.** When a network is over its rate, the relay stops reading from the sending
  connection until its bucket allows more; frames are never dropped.
- **Back-pressure.** When the bytes queued for one recipient exceed `LINK_QUEUE_BYTES`, the relay
  stops reading from connections that have frames waiting for it, and resumes below the
  threshold.
- **Liveness.** The relay sends a WebSocket ping every 30 seconds and closes a connection that
  has not answered by the next one.

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
  Never after `4008`.
- A send to a peer that answers `unreachable` fails at once with a typed error. Nothing is queued
  for absent peers.
- On `4009`, look the network up again and reconnect.

## 12. Vectors

`spec/vectors/` holds JSON vectors for: key and id derivation; roster signing and validation
(valid and invalid cases); the registration signature; SPAKE2 (RFC 9382's, plus this
profile's); the Noise IK handshake and first transport messages; frame encoding; session message
encoding. Every implementation runs all that apply to it.
