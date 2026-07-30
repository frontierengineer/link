# Security — why a malicious relay (or a malicious client) can't hurt you

Link's job is to introduce two parties and forward bytes between them **without
being trusted**. This document explains, in plain terms, how that holds — including
how SPAKE2 and Noise work and why a short pairing code is safe to use over a relay
you don't trust.

If you only read one section, read **The promise**.

---

## The promise (threat model)

We assume **Link is run by an attacker**, and that someone can wiretap the network.
Everything below holds anyway. A hostile Link **cannot**:

- **Read your traffic.** Every byte between a client and a host is encrypted
  end-to-end. Link forwards opaque ciphertext and counts bytes. That's all it can do.
- **Learn your pairing code.** The short code is *never sent to Link* — not the
  code, not a hash of it, not anything derived from it. It is used only inside the
  handshake between the two endpoints.
- **Impersonate a host.** A client pins the host's public key at first pairing; any
  later connection presenting a different key fails the handshake.
- **Pair as a client, or take over a host.** Pairing requires the code (which Link
  never gets); reconnecting requires the device token (which Link never gets).

The **only** power a malicious Link has is to **refuse to introduce you** — denial
of service. That's why a host can register with several Links: if one misbehaves,
use another. A Link going down is a non-event.

There are **no accounts and no passwords**. The unit of trust is a *credential* the
host issues directly to a client during pairing — held by the client, verified by
the host, never by Link.

## The principle: security lives at the endpoints, by construction

The guarantee is **two-directional**, and neither side relies on the other behaving:

1. **A malicious Link can't hurt honest endpoints** — because the endpoints do all
   the crypto end-to-end (SPAKE2, then Noise). Link only ever holds ciphertext.
2. **A malicious or buggy *client* can't hurt the system *through* Link** — because
   Link's wire vocabulary is minimal and strict. There is **no message and no field**
   that lets anyone hand Link a secret, register an address they don't hold a key
   for, or make Link route anywhere but to the addressed host. The dangerous thing
   simply isn't expressible.

That second point is the important one, and it's why "what the other side does
doesn't matter": you cannot make Link unsafe by using it wrong, because the unsafe
operations don't exist in its protocol. (For example, the protocol has **no field
for a pairing code**. A client that tried to send one is just sending a malformed
frame, which Link rejects.)

## How pairing stays safe over an untrusted relay — SPAKE2

The hard problem: two parties share a **short** secret (the pairing code) and want
to prove to each other that they both know it — over a wire an attacker controls —
**without revealing it**, and such that the attacker can't guess it offline.

This is a *password-authenticated key exchange* (PAKE). Link uses **SPAKE2**
(RFC 9382). Here's the intuition:

> You and the host both know the code. Each of you takes the code, **scrambles it
> together with a fresh random number of your own**, and sends the scrambled result
> across the room (the room is Link, full of eavesdroppers).
>
> - Nobody in the room can un-scramble it to recover the code *or* your random
>   number — they hear noise.
> - But *you* can combine the host's noise with **your** code and **your** random
>   number to compute a shared key, and the host computes the **same** key — *only
>   because you both started from the same code*.
> - You each then send a short checksum (a MAC) of your key. Match → you're paired
>   and share a strong key. Mismatch → someone guessed wrong; you both hang up.

Concretely, each side sends one elliptic-curve point with the code-derived value
`w` blinded in: the client sends `X* = x·G + w·M`, the host sends `Y* = y·G + w·N`
(`M`, `N` are fixed public points; `x`, `y` are fresh random scalars). An observer
sees `X*`/`Y*` but cannot separate the random part from the code part. Both sides
unblind with the code they know and arrive at the same shared secret — then confirm
with MACs.

**Why there's no offline attack** (this is the crux): the code is woven *into the
curve math*, not used to encrypt something an attacker could take home and grind. A
man-in-the-middle gets to test **exactly one** code guess per live attempt, and
learns nothing on a wrong guess. There is no recorded value it can brute-force
against offline.

> **The mistake we don't make.** A naive scheme derives a key the normal way and
> then *encrypts a known value with the code* (e.g. `HKDF(DH ‖ code)`). An attacker
> who relays the connection knows the DH value, records that ciphertext, and tries
> all possible codes against it **offline** — a short code falls in seconds. SPAKE2
> never puts such a grindable value on the wire. That difference is the entire
> reason a PAKE exists, and why a 6-character code is safe here.

**Why a 6-character code is enough.** SPAKE2 allows only *online* guessing — one
guess per handshake — and the host **locks out** after a few wrong tries (default
5) and burns the code. To brute-force a 6-char code (≈10⁹ possibilities) an attacker
would need ~10⁹ live handshakes against the host before the code expires and after
the host stopped answering at try 5. That is not an attack.

After a successful pair, the host hands the client (inside the now-sealed channel) a
**256-bit token** and its **static public key**. The client persists both. The code
is burned.

## How reconnecting stays safe — Noise

Every connection after the first uses no code. The client has the token + the host's
pinned public key, and they run a **Noise NKpsk0** handshake (the same pattern
WireGuard uses: X25519 + ChaCha20-Poly1305):

- The **host** is authenticated by its **pinned static key** — a substituted key
  fails the handshake, so a malicious Link cannot impersonate the host.
- The **client** is authenticated by **possessing the token** (used as the Noise
  pre-shared key).
- The session is **forward-secret**: each connection uses fresh ephemeral keys, so
  recording today's ciphertext and stealing a key tomorrow reveals nothing.

A wiretapper or hostile Link sees a random address and ciphertext: no key, no
impersonation, no entry.

## The transport, once a handshake completes

Every frame after the handshake is AEAD-sealed (ChaCha20-Poly1305) with a
per-direction monotonic counter nonce. Tampering fails the authentication tag; a
replayed or reordered frame is rejected by the counter. Distinct keys per direction
guarantee a nonce is never reused under a key.

This is **message-layer** encryption on a **plain** WebSocket (`ws`) — *not* a
"secure WebSocket", and the guarantee does **not** depend on TLS. A TLS-terminating
front (so clients dial `wss://`) is ordinary web hygiene and may add a thin privacy
layer against a passive on-path observer, but Link's confidentiality, integrity, and
authenticity are already complete before a byte reaches the socket. Run Link over
plain `ws` and you lose none of them.

## Anti-squat: even the routing layer is authenticated

The address is not secret, so what stops someone who learns it from registering it
out from under the genuine host (a denial of rendezvous)? Every `register` is
**signed** (Ed25519), and Link **pins** the key on first use (trust-on-first-use):
thereafter only the holder of that key can register the address, and only with a
strictly newer timestamp (so a captured frame can't be replayed). A party that
knows the address but not the key is refused — and, if the genuine host registered
first, without disturbing it. See [PROTOCOL.md §7](./PROTOCOL.md).

Three additive gates harden the **introduction plane** further. None touches the
end-to-end crypto — a hostile Link is exactly as harmless with them as without — and
all are pure config, so Link stays stateless and content-blind:

- **Address-key binding (default on).** The address *is* the commitment to the
  register key, `base64url(SHA-256(pub))`. A squatter can no longer even *present* a
  frame for your address — no key it holds hashes to it — so the "who registers
  first" race disappears and the routing layer becomes spoof-**proof**, not merely
  spoof-survivable.
- **Origin binding.** A register signature is bound to the specific Link authority
  it is sent to, so a still-fresh frame captured at one Link cannot be replayed to a
  different one.
- **Closed mode.** An operator can require every register key to be on a supplied
  allowlist, so only known hosts may register on that instance. This gates *who may
  use the relay*; it does not weaken *anyone's* end-to-end guarantees.

(End-to-end crypto would stop impersonation even without any of this — but the
introduction plane protects the *introduction itself* from being hijacked or denied.)

## Revoking a lost device

A device authenticates on reconnect by **possessing its token** (the Noise PSK),
looked up by `keyId`. Revoking a device is simply **dropping that token** from the
host's store: the very next reconnect finds no token and is refused. Revocation
lives entirely at the **host**, never at Link — Link is content-blind and never sees
a token. So a lost phone is cut off the instant it is revoked, and stays cut off
across host restarts (the store is the source of truth). The host tells the refused
device so *distinguishably* — a typed "revoked" signal it can tell apart from a
transient drop — so the client stops retrying and prompts a re-pair instead of
spinning forever. That signal is a courtesy to the honest client; a revoked or
hostile device learns only that it was revoked, which changes nothing it can do.

## What a malicious Link *can* do, and the answer

- **Refuse to introduce / drop the relay** — denial of service. *Answer:* register
  with multiple Links; clients fail over. Run your own (the whole server is in this
  repo).
- **See metadata** — that *some* address is being connected to, byte counts, timing.
  It cannot tie that to who or what without already knowing your addresses. *Answer:*
  addresses are opaque random handles; nothing in the relayed content is visible.
- **Lie on `/v1/stats`** — it's the operator's own server. Irrelevant to your
  security; those are operational counters, not authority.

It cannot read, inject, impersonate, pair, or take over. By construction.

## Checkable, not just claimed

Link's value rests on "it can't read anything," and that claim is *checkable*: the
entire relay is the small, dependency-light server in this repo. Read it, audit it,
run your own. The protocol is specified in [PROTOCOL.md](./PROTOCOL.md) and the
cryptographic handshakes have known-answer tests in the client test suite.
