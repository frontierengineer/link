# @frontierengineer/link-client

An auditable **secure-connection library** for the [Link](https://github.com/frontierengineer/link) relay
model: reach a NAT'd host from anywhere, through relays you don't have to trust,
with no accounts — end-to-end encrypted, authenticated by a per-host credential.

One library is both ends of the model: a **host** uses it to register with its
relays and accept clients; a **client** uses it to connect. The relay only ever
moves ciphertext.

- **First-pair:** [SPAKE2 (RFC 9382)](https://www.rfc-editor.org/rfc/rfc9382) so a
  hand-typed 6-character code is safe over an untrusted relay — proven against the
  RFC's own test vectors.
- **Reconnect:** [Noise](https://noiseprotocol.org/) `NKpsk0` (X25519 +
  ChaCha20-Poly1305 + SHA-256) — proven byte-for-byte against the published Noise
  vectors.
- **Primitives adopted, never hand-rolled:** [`@noble/curves`](https://github.com/paulmillr/noble-curves),
  [`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers),
  [`@noble/hashes`](https://github.com/paulmillr/noble-hashes).

## The model in one paragraph

The host opens **no inbound port**. It holds an outbound control socket to each of
its relays and registers a high-entropy **address** (signed, so it can't be
squatted). A client connects outbound to a relay, is introduced to the host, the
relay splices their two sockets, and the two endpoints run an end-to-end handshake
the relay cannot see inside. Two cleanly separated guards: the **relay** guards
*introduction* (you resolve an address to be spliced — but that's just a phone
ring), and the **end-to-end credential** (a pinned host key + device token) guards
*access*. Register with several relays and the client fails over silently.

## Quick start

```ts
import { connect, serveHost, generateHostIdentity } from '@frontierengineer/link-client';

// ── host ──
const identity = generateHostIdentity();           // persist identity.priv forever
const host = await serveHost({
  uplinks: ['wss://link.example.com/v1/link'],
  hostStatic: identity,
  onRequest: async (cmd) => handle(cmd),            // your app protocol
});
host.setPairingCode('K7P2QX');                      // open pairing; show host.address + code out of band

// ── a new client first-pairs (address from the QR, code typed/scanned with it) ──
const conn = await connect({
  uplinks: ['wss://link.example.com/v1/link'],
  address: host.address,                            // a QR/deep-link carries this
  code: 'K7P2QX',                                   // the short code keys SPAKE2 only
  onState: (s) => console.log('state:', s),
});
const credential = conn.credential;                 // PERSIST THIS (token + pinned key + address)
await conn.request({ hello: 'world' });             // sealed round-trip

// ── every later connection reuses the credential (the code was one-time) ──
const back = await connect({
  uplinks: ['wss://link.example.com/v1/link'],
  address: credential.address,
  credential,
});
```

`connect()` returns an **already-secure, auto-reconnecting** channel: it tries
uplinks in order, relays through the first that works, and on any drop it
re-handshakes — failing over across uplinks — using the credential. `request()`
transparently rides out a reconnect.

## Public API

### `connect(options) → Promise<Connection>`

| option | meaning |
|---|---|
| `uplinks: string[]` | ordered relay URLs (failover order) |
| `address: string` | the host's routing address (always required) |
| `code?: string` | **first pair**: the short pairing code — keys SPAKE2 only, never sent to the relay |
| `credential?: DeviceCredential` | **reconnect**: token + pinned host static key + address |
| `recoveryKey?: string` | **recover**: a high-entropy secret to enroll a brand-new device from nothing |
| `onState?` | `connecting`→`connected`→`reconnecting`→… ; terminal `failed` or `revoked` |
| `onRequest?` | handle host-initiated requests on this client |
| `dial?` | per-attempt timeouts (`connectTimeoutMs`, `controlTimeoutMs`) |

If the host has **revoked** this device, reconnect is refused with a typed
`DeviceRevokedError` (and `state` → `revoked`): the managed connection stops
retrying instead of spinning forever, so the app can forget the credential and
re-pair.

Exactly one of `code` / `credential` / `recoveryKey` selects the mode.
`Connection`: `request(cmd)`, `send(evt)`, `sendWithPayload(evt, bytes)`,
`supportsPayload`, `onMessage(fn)`, `credential`, `address`, `state`, `via`,
`close()`.

**Bulk rides as bytes, not base64.** `send(evt)` puts one JSON object on the
sealed stream. `sendWithPayload(evt, bytes)` puts the same JSON beside a RAW
byte payload — audio, terminal output, a forwarded port, a file — so bulk is
not inflated 33% to survive a JSON field. `onMessage(fn)` receives it as the
handler's second argument, `undefined` for an ordinary frame.

The far end must be new enough to read it, so peers announce that once at
session start and `supportsPayload` reports the answer. Read it per STREAM
(a reconnect re-negotiates) and take the other path when it is false;
`sendWithPayload` throws rather than silently base64-ing bytes you asked it not
to. The wire, and why the negotiation only runs one way, is normative in
[docs/PROTOCOL.md §6](https://github.com/frontierengineer/link/blob/master/docs/PROTOCOL.md).

### `serveHost(options) → Promise<Host>`

Registers `address` (signed) with **every** uplink — N outbound control sockets,
re-registered on reconnect/relay-restart — accepts introduced clients, runs the
host handshake, and issues/verifies credentials.

| option | meaning |
|---|---|
| `uplinks: string[]` | relay URLs to register with |
| `hostStatic?: KeyPair` | the host's static identity (defaults fresh — persist `.priv`). The routing address is always the **commitment to the register key** derived from this identity, `base64url(SHA-256(key))`, so it's spoof-proof and not configurable |
| `pairingCode?: string` | open pairing immediately (else call `setPairingCode`) |
| `recoveryKey?: string` | enable cold-start recovery with this high-entropy secret |
| `tokens?: TokenStore` | a persisted device store (defaults empty) |
| `onRequest?` / `onConnect?` / `onLog?` | app protocol / per-session hook / structured logs |
| `onUsage?` | per-connection relay usage — a 0–1 fraction + `throttled`, or `unlimited` when the relay sets no quota; fires on Link's pushes **and** in answer to `requestUsage()` |
| `maxPairAttempts?` | wrong-guess lockout per code (default 5) |

`Host`: `address`, `hostStatic`, `hostStaticPub`, `tokens`, `sessions`,
`registeredCount`, `setPairingCode(code|null)`, `revoke(keyId)`, `requestUsage()`,
`stop()`.

**Usage telemetry.** Link reports usage only in **relative** terms — a fraction of
the hourly allowance per connection, or `unlimited` — never absolute bytes and never
its own limit config, so a byte budget can't be reverse-engineered. `onUsage`
receives the usage of *every* connection this host owns; call `requestUsage()` to
pull the current values on demand (the answer arrives on `onUsage` with the same
shape as an unprompted push).

## Security properties

- **First pair (short code).** SPAKE2 turns the code into a strong shared key.
  Against an active man-in-the-middle (including a malicious relay) it is
  *online-only*: the attacker must commit to one guess per live attempt and learns
  nothing it can test offline, so the host's K-try lockout (default 5) caps success
  at `attempts / charset^len`. The lockout slot is reserved **atomically at attempt
  entry**, so concurrent attempts cannot bypass the cap (it doubles as a per-code
  concurrency cap on the unauthenticated handshake). Inside that channel the host
  sends its **static public key** and a **256-bit token**; the client pins the key
  and stores the token. The code is **never sent to the relay in any form.**
- **Reconnect.** Noise `NKpsk0` authenticates the **host by its pinned static key**
  (a substituted key fails the AEAD) and the **client by token possession** (the
  token is the PSK; an unknown/revoked `keyId` is refused up front). Forward-secret
  per connection via the ephemeral-ephemeral DH.
- **Transport.** Every frame is ChaCha20-Poly1305 under a per-direction, monotonic,
  never-transmitted nonce, so tamper, replay, reorder, and truncation are all
  rejected by the tag. **There is no plaintext mode.**
- **Rendezvous is address-only.** The relay introduces by the high-entropy,
  signed `address`. The short code is *never* a relay lookup key (it would be
  brute-forceable) — only a SPAKE2 secret. So a malicious relay has nothing
  code-derived to attack. See [docs/SECURITY.md](https://github.com/frontierengineer/link/blob/master/docs/SECURITY.md).
- **Recovery.** A high-entropy host secret lets a brand-new device enroll from
  nothing — the same flow as pairing, with the recovery key as the authenticator
  (concurrency-capped but intentionally not permanently locked out, so it can't be
  DoS'd).
- **Revocation.** Drop the token (`host.revoke(keyId)`); the next reconnect finds no
  token and is refused. The host sends the refused device a **typed** signal, so the
  client surfaces a terminal `DeviceRevokedError` / `revoked` state (distinguishable
  from a transient drop) and stops retrying instead of looping forever. Revocation
  lives at the host, never at the relay.
- **Untrusted-relay hardening.** Every socket is capped at the relay's 16 MiB frame
  ceiling; a tampered frame tears down *and closes* its socket; and a host bounds
  concurrent relay dial-backs per uplink (default 64) so a malicious relay can't
  drive unbounded outbound sockets.

## Secrets at rest & delivery semantics

- **Tokens are secrets.** A device token *is* the Noise PSK, so it cannot be stored
  hashed. Persist `TokenStore` (host) and the `DeviceCredential` (client) only
  through encryption you control; `TokenStore.export()/import()` is the seam for
  encrypt-at-rest.
- **`request()` is at-least-once.** It retries across a reconnect, so a command
  whose response was lost may run twice on the host. Keep commands idempotent or
  carry an app-level idempotency key.

## Architecture

Small, single-purpose modules — the whole crypto surface is meant to be read.

| module | role |
|---|---|
| `src/crypto.ts` | the only place primitives are bound (`@noble/*`); nonce/DH/HKDF encodings pinned |
| `src/noise.ts` | a complete, minimal Noise engine (CipherState/SymmetricState/HandshakeState) |
| `src/spake2.ts` | SPAKE2 over P-256 to RFC 9382 |
| `src/secureChannel.ts` | the e2e layer: NKpsk0 reconnect, the sealed stream, the app session |
| `src/pairing.ts` | SPAKE2 choreography, token store, lockout, the device credential |
| `src/registerAuth.ts` | the signed-address registration (Ed25519, anti-squat) |
| `src/linkClient.ts` | the multi-uplink transport over the relay wire (resolve/relay/failover, host register) |
| `src/index.ts` | `connect()` / `serveHost()` |
| `src/pipe.ts` · `src/bytes.ts` | the transport abstraction · framing + constant-time compare |

## Tests — everything is checkable

```bash
npm install
npm test          # typecheck + unit (KAT) + the end-to-end self-test
```

- **`test/secureChannel.test.ts`** — the Noise vectors (NN/NK/**NKpsk0**/XX/…) with
  byte-equality of every message + handshake hash + transport stream; the live
  reconnect handshake (substituted-key and wrong-token rejection); and the sealed
  stream's tamper/replay/reorder rejection.
- **`test/pairing.test.ts`** — the four RFC 9382 SPAKE2 vectors; a proof that an
  **active MITM who guesses the wrong code cannot derive the key**; and the K-try
  lockout.
- **`test/hardening.test.ts`** — the lockout TOCTOU mechanism (reserve() caps
  concurrent attempts at K) and the relay dial-back cap (a flood of relay requests
  opens at most N concurrent dial-backs, held through the handshake).
- **`test/registerAuth.test.ts`** — signed-registration interop (@noble sign ↔ Node
  verify), the full anti-squat sequence against a real relay (unsigned refused,
  TOFU-pinned, wrong-key refused, same-key replaces, replay refused), and
  **address-key binding** (only the committed address registers; a squatter can't
  even craft a passable frame).
- **`test/e2e.selftest.ts`** — spawns **two real relay processes**, registers a host
  with both, then: pair (address rendezvous + 6-char code) over uplink A → sealed
  request → **pull usage (per-connection, `unlimited`)** → **kill A, fail over to B
  by token reconnect** → fresh token reconnect → **revoke → reconnect refused with a
  typed `DeviceRevokedError` + terminal `revoked` state (no endless retry).** Prints
  PASS/FAIL per stage; non-zero exit on any failure.

## License

MIT — see [LICENSE](https://github.com/frontierengineer/link/blob/master/LICENSE).
