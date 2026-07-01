# The Link protocol

This is the normative wire specification for Link. It is deliberately tiny: Link
is a **content-blind relay**, so the whole protocol is "introduce two parties, then
forward sealed bytes between them." If you implement these messages, your client
and host interoperate with any Link.

If you want the *why* (the threat model, how SPAKE2 and Noise make a malicious Link
harmless), read [SECURITY.md](./SECURITY.md). This document is the *what*.

---

## 1. The cast: two roles, one relay

There are only ever three parties, and only two **kinds** of party:

```
   ┌────────┐        introduce + relay        ┌────────┐
   │ CLIENT │ ─────────────────────────────── │  HOST  │
   └────────┘            ┌──────┐              └────────┘
   connects out          │ LINK │              registers an address,
   to an address         └──────┘              waits to be reached
                    sees only ciphertext
                    + a random routing id
```

- A **host** registers an *address* with one or more Links and waits. It listens on
  no ports of its own — it only ever holds **outbound** sockets to its Links.
- A **client** is anything that connects *to* a host: it resolves the host's
  address through a Link and is introduced. (A host can also be a client of another
  host — the roles are about direction, not identity.)
- **Link** introduces a client to a host and then splices their two sockets
  together, forwarding the encrypted bytes. It never terminates the end-to-end
  crypto, never sees a secret, and never decides who gets in.

Every connection goes through a Link relay. There is **no** direct/LAN bypass in
the protocol, so a host never exposes an inbound port.

## 2. Vocabulary (three nouns)

| Noun | What it is | Entropy | Who sees it | Secret? |
|---|---|---|---|---|
| **address** | The host's routing handle — its "phone number". A client resolves it to be introduced. Stable; reused across reconnections. | High — `base64url(SHA-256(register key))` by default (a commitment to a key nobody else holds), or any ≥128-bit random handle in legacy opaque mode | Link + anyone the host hands it to | **No.** Knowing it lets you *ask* to connect; entry is gated by the handshake. |
| **pairing code** | A short, single-use secret shown when a host opens pairing (a QR, or typed). Proves, this one time, that the client is the intended one. | Low (e.g. 6 chars) | **Only the two endpoints** | **Yes** — and it is **never sent to Link in any form, raw or hashed.** It is only ever a SPAKE2 input. |
| **credential** | What a client persists after first pairing: a 256-bit `token`, the host's pinned static public key, and the address. Used for all later reconnections — no code ever again. | High | **Only the client** (it is a secret at rest) | **Yes** |

There is also a per-introduction **`linkId`** (a random UUID Link assigns) that
names one live relay so the three parties can refer to the same introduction.

> **There is no field anywhere in this protocol for a pairing secret.** Link's
> rendezvous key is the high-entropy, signed `address`. The short code lives only
> inside the endpoints' SPAKE2 handshake (which rides the relay as opaque frames).
> This is the property that makes "what the endpoints do" irrelevant to Link's
> safety — see [SECURITY.md](./SECURITY.md).

## 3. Transport & framing

- One WebSocket per socket, at `/v1/link`. The transport is a **plain WebSocket**
  (`ws`) carrying **message-layer**-encrypted frames — it is *not* a "secure
  WebSocket", and Link's confidentiality/integrity/authenticity do **not** come from
  the transport. Every relayed byte is already sealed end-to-end (SPAKE2 then Noise)
  before it reaches the socket, so a plain-`ws` Link loses nothing. Clients usually
  dial `wss://<link-host>/v1/link` only because a TLS-terminating front (e.g.
  Cloudflare) sits ahead of Link for ordinary web hygiene; Link itself speaks `ws`.
  See [DEPLOY.md](./DEPLOY.md) and [SECURITY.md](./SECURITY.md).
- **Control frames** are UTF-8 **text** frames carrying one JSON object with a
  `type` field. Max 4096 bytes. Used during introduction.
- **Relay frames** are **binary** frames. The instant a socket goes into the
  `relaying` state, *every* frame on it — in both directions — is opaque payload
  that Link forwards verbatim. Max 16 MiB per frame.
- A binary frame *before* the splice is live, or a control frame *after* it, is a
  protocol violation and the socket is closed.

## 4. Control messages

`C→L` = client→Link, `L→H` = Link→host, etc. Read the arrow as the direction the
frame travels.

| Message | Direction | Fields | Meaning |
|---|---|---|---|
| `register` | H→L | `address`, `auth` | "I am the host at `address`; here is my signature." `auth` is **required** (see §6). |
| `registered` | L→H | `address` | "Verified and pinned. You are reachable." |
| `resolve` | C→L | `address` | "Introduce me to the host at `address`." |
| `found` | L→C | `linkId` | "There is a host there; this introduction is `linkId`." |
| `arrived` | L→H | `linkId`, `address` | "A client asked for you on `address`; the introduction is `linkId`." (Informational.) |
| `relay` | C→L | `linkId` | "Set up a relay for `linkId`." |
| `relay` | L→H | `linkId` | "Dial back a fresh relay socket for `linkId`." |
| `accept` | H→L | `linkId` | Sent on a **new** socket: "this socket is the host's relay end for `linkId`." |
| `relaying` | L→C and L→H | `linkId` | "The splice is live. Everything after this is opaque payload." |
| `usage` | L→H | `connections[]` | Relay usage for **every** connection this host owns, each a 0–1 `used` fraction + `throttled` (or `unlimited` when no quota is configured). Never absolute bytes, never the limit. Sent two ways with this same shape: **pushed** on a tier crossing / throttle flip, and **pulled** in reply to `getUsage`. |
| `getUsage` | H→L | — | "Report the usage of every connection I own." No link selector — a host only ever gets its own connections. Reply is a `usage`. |
| `error` | L→C / L→H | `error` | A **non-fatal** problem (e.g. `unknown_address`). The socket stays open. |

Each entry in a `usage` message's `connections` array is
`{ "linkId": …, "used": 0..1, "throttled": bool }` when the operator set an hourly
quota, or `{ "linkId": …, "unlimited": true }` when they did not — so "no limit" is
explicit and a byte budget can never be inferred from the wire.

Fatal problems are signalled by a WebSocket **close code** instead (see §7).

## 5. The three flows (swim-lanes with real frames)

### 5a. A host comes online

The host holds this control socket open for its whole lifetime and re-registers on
any reconnect.

```
HOST                                   LINK
 │  register {address:"k7Qe…", auth:{…}} ─────▶│   verify sig; pin the key (first time)
 │ ◀──────────────── registered {address:"k7Qe…"}│   "you're live"
 │                                              │
 │  (socket stays open; Link sends `arrived` / `relay` on it as clients show up)
```

### 5b. First pairing — a brand-new client (SPAKE2)

Out of band (a QR the host shows, or copy-paste), the client receives **two**
things: the host's `address` (routing) and a short single-use `code` (the secret).

```
        ┌──── out of band: address "k7Qe…"  +  code "K7P2QX" ────┐
        ▼                                                        ▼
CLIENT                         LINK                         HOST
 │ resolve {address:"k7Qe…"} ──▶│                              │
 │ ◀──── found {linkId:"a1f…"} ─│                              │
 │                              │── arrived {linkId,address} ─▶│
 │ relay {linkId:"a1f…"} ─────▶ │                              │
 │                              │── relay {linkId:"a1f…"} ────▶│  (host dials back…)
 │                              │◀─ accept {linkId:"a1f…"} ────│  …on a NEW socket
 │ ◀──── relaying {linkId} ─────│── relaying {linkId} ────────▶│  ░░ SPLICE LIVE ░░
 │                              │                              │
 │ ░░░░░ from here Link forwards OPAQUE bytes — it sees only ciphertext ░░░░░
 │                              │                              │
 │ pake share  X* = x·G + w·M ─▶│ ───────────────────────────▶│  w = SPAKE2(code)
 │ ◀───────── pake share  Y* = y·G + w·N ◀──────────────────  │  (the code is mixed
 │ confirm MAC  cA ───────────▶│ ───────────────────────────▶│   INTO the curve math,
 │ ◀──────────────────── confirm MAC  cB ◀───────────────────  │   never sent)
 │ ◀──── sealed welcome { token, hostStaticPub, address } ◀──  │  issued + sealed
 │                              │                              │
 (client persists the credential; the code is now burned, single-use)
```

What Link saw: one random `address`, one random `linkId`, and a stream of
ciphertext. It could not read the handshake, derive the key, or learn the code.

### 5c. Reconnecting — a paired client (Noise)

No code, ever again. The introduction (resolve → relay → accept → relaying) is
identical to 5b; only the handshake over the splice differs:

```
 │ ░░ SPLICE LIVE ░░                                           │
 │ Noise NKpsk0 msg1 (e, es, psk=token) ─────────────────────▶│  host authenticates the
 │ ◀───────────────── Noise NKpsk0 msg2 (ee) ─────────────────│  client by the TOKEN…
 │ ░░ sealed, forward-secret application stream both ways ░░   │  …client authenticates the
 │                                                            │   host by its PINNED key
```

A substituted host key fails the handshake; a client without the token fails it. A
malicious Link can drop the connection (denial of service) but cannot read it,
forge it, or join it.

## 6. Registration is always signed (anti-squat)

`register` **must** carry an `auth` object or it is refused (close `4007`):

```json
"auth": {
  "alg": "ed25519",
  "pub": "<base64url 32-byte Ed25519 public key>",
  "ts":  1782748890262,
  "nonce": "<base64url random>",
  "sig": "<base64url 64-byte signature>"
}
```

The signature is over the canonical byte string
`"frontier-link-register-v1" ‖ len(address) ‖ len(ts) ‖ len(nonce) ‖ len(origin)`
(each `len(x)` is a 4-byte big-endian length followed by the UTF-8 bytes). `origin`
is the Link authority the frame is meant for (the `host[:port]` the client dialed);
binding it means a captured, still-fresh frame does **not** verify at a *different*
Link. Link:

1. Verifies the Ed25519 signature (rebuilding the message with its **own** origin,
   from the request's `Host` header or a configured value) and that `ts` is within
   ±5 min of its clock.
2. **Trust-on-first-use:** the first `register` for an `address` pins `pub`.
3. Every later `register` for that address must use the **same** `pub` and a
   **strictly newer** `ts`. A different key → `address_pinned` (refused, the genuine
   holder is undisturbed). A replayed/old `ts` → `register_stale`.

So learning an address is not enough to steal it — you must hold its key. The pin
is memory-only and lasts exactly as long as the registration (a host holds its
socket and re-registers with the same key on reconnect).

**Address-key binding (default on).** By default Link additionally requires the
`address` to be the **commitment** to the register key:
`address == base64url(SHA-256(pub))`. A register whose address is not that is
refused (`4007`). This makes the routing layer spoof-*proof*, not merely
spoof-survivable: a squatter cannot even present a frame for your address, because
no key it holds hashes to it — the race in step 3 disappears. Operators who want the
legacy opaque-address model (any high-entropy operator-chosen handle) disable it
(`LINK_BIND_ADDRESS_TO_KEY=0`).

**Open vs closed (default open).** In **open** mode any host with a valid signature
may register (today's behaviour). In **closed** mode the operator supplies an
**allowlist** of authorized register keys (config only — no dynamic pairing state);
a genuine signature whose `pub` is not on the list is refused with `4010`. See
[DEPLOY.md](./DEPLOY.md).

## 7. Relay lifecycle & close codes

A link (one introduction) moves through: `introduced` → `pending` (relay
requested) → `relaying` (spliced) → `closed`. A relaying link dies only with its
relay ends; the host's *control* socket dropping does not tear down live relays.

Fatal conditions close the WebSocket with an application code (4000–4999):

| Code | Name | Meaning |
|---|---|---|
| 4000 | bad request | Malformed/oversized frame, unknown type, or a message illegal for the socket's role/state. |
| 4002 | rate limited | Per-IP register/resolve limit tripped (DoS control, see [DEPLOY.md](./DEPLOY.md)). |
| 4003 | peer gone | The other end of the relay vanished. |
| 4004 | idle timeout | The relay sat with no traffic past the idle window. |
| 4005 | replaced | A newer, validly-signed socket re-registered this address; this older one is retired. |
| 4006 | slow peer | The peer stopped draining and too much piled up in its send buffer. |
| 4007 | register auth | `register` lacked a valid signature, it failed/was stale, or (with binding on) its address was not the commitment to its key. |
| 4010 | register unauthorized | The signature was valid, but the relay is in **closed** mode and this host's register key is not on the operator's allowlist. |

`error` frames (non-fatal, socket stays open): `unknown_address` (resolve found
nothing), `unknown_link` (accept named no pending link), `address_pinned`,
`register_stale`.

## 8. What Link stores

In memory only, never on disk, no accounts:

- **address → { socket, pinned key, last-ts }** — the registration + its anti-squat
  pin.
- **live links** — for each: the two sockets, byte counters, and rate-limit state.

The closed-mode **allowlist** and the address-binding / origin knobs are static
operator **config**, not per-host state — Link still holds nothing durable and
coordinates nothing across replicas. A restart forgets everything; hosts
re-register and clients reconnect. The entire
service is one small stateless relay — which is what makes "run your own, and the
'it can't read anything' claim is checkable" true.

## 9. Health & stats (HTTP)

Plain HTTP `GET` on the same port:

- `GET /health` (or `/healthz`) → `{"status":"ok"}` (load-balancer probe).
- `GET /v1/stats` → counts only (live links, bytes relayed, address registrations,
  recently-closed link summaries). Never any address, code, or frame content —
  Link has nothing sensitive to leak.
