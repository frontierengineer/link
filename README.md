# Link

**Connect to a host that's behind any NAT or firewall — end-to-end encrypted,
through a relay you don't have to trust.** No port-forwarding, no accounts, no
passwords, and nothing the relay can read.

Link is two small things:

- a **relay server** (`server/`) — a content-blind switchboard that introduces two
  parties and forwards the encrypted bytes between them, and
- a **client library** (`client/`, `@frontierengineer/link-client`) — the host and client
  ends of an opinionated, secure-by-construction handshake (SPAKE2 + Noise).

The relay is the only thing that needs a public address. A **host** registers an
*address* with one or more relays and listens on no ports of its own; a **client**
resolves that address and is introduced. From there the two endpoints run a
handshake the relay cannot see, and everything after it is sealed.

```
   ┌────────┐        encrypted end-to-end        ┌────────┐
   │ CLIENT │ ───────────────────────────────────│  HOST  │
   └────────┘               ┌──────┐             └────────┘
   connects out             │ LINK │             registers an address,
   to an address            └──────┘             never opens a port
                       sees only ciphertext
                       + a random routing id
```

## The promise

Assume the relay is **run by an attacker**. It still **cannot** read your traffic,
learn your pairing code, impersonate a host, or pair as a client. The only thing a
malicious relay can do is *refuse to introduce you* — so register with several and
fail over. The security lives entirely at the two endpoints, by construction.

Full threat model and the SPAKE2/Noise explanations: **[docs/SECURITY.md](docs/SECURITY.md)**.

## How pairing works, in one breath

A host shows two things out of band (e.g. a QR): its **address** (a high-entropy
routing handle — not secret) and a short, single-use **pairing code** (the secret).
The client rendezvouses on the address through the relay, then proves it knows the
code using **SPAKE2** — a handshake where the code is mixed into the math and never
sent, so the relay (or any wiretapper) can't learn it or guess it offline. On
success the host issues the client a long-lived **credential**; every reconnection
after that uses **Noise** (the WireGuard handshake) with that credential — no code
ever again.

## Quickstart

### Run a relay

```bash
docker build -t link -f Dockerfile .
docker run -d --restart unless-stopped -p 80:80 --name link link
curl localhost:80/health        # {"status":"ok"}
```

Link speaks plain `ws`/HTTP; it expects TLS to be terminated in front of it (a
managed cert, or any reverse proxy). Running it for real — Cloud Run, the config
knobs, scaling — is in **[docs/DEPLOY.md](docs/DEPLOY.md)**.

### Host side (`@frontierengineer/link-client`)

```ts
import { serveHost, generateHostIdentity } from '@frontierengineer/link-client';

const host = await serveHost({
  uplinks: ['wss://link.example.com/v1/link'],
  hostStatic: generateHostIdentity(),     // persist .priv; clients pin .pub on first pair
  onRequest: async (cmd) => ({ echo: cmd }), // answer requests from connected clients
});

// Open pairing for one client. Show host.address + the code out of band (a QR, or
// copy-paste). The code keys SPAKE2 only — it is never sent to the relay.
host.setPairingCode('K7P2QX');
console.log('address:', host.address);
```

### Client side

```ts
import { connect } from '@frontierengineer/link-client';

// First time: pair with the address + code from the QR.
const conn = await connect({
  uplinks: ['wss://link.example.com/v1/link'],
  address: 'k7Qe…',   // the host's address
  code: 'K7P2QX',     // the one-time pairing code
});
const reply = await conn.request({ hello: 'world' });

// Persist conn.credential. Next time, reconnect with it — no code:
//   await connect({ uplinks, address: cred.address, credential: cred });
```

The connection auto-reconnects and fails over across uplinks transparently. Full
API: **[client/README.md](client/README.md)**.

## Layout

```
server/          the relay (TypeScript; one runtime dependency: ws)
client/          @frontierengineer/link-client — the host + client library
docs/PROTOCOL.md the wire protocol (messages, swim-lanes, close codes)
docs/SECURITY.md threat model + how SPAKE2 and Noise make the relay harmless
docs/DEPLOY.md   running a relay: Docker, Cloud Run, a VM, the config knobs
Dockerfile       builds the relay image
```

## Relay configuration (env)

| Var | Default | Meaning |
|---|---|---|
| `LINK_PORT` | `80` | listen port |
| `LINK_RELAY_MAX_BPS` | `1048576` | per-link rate (bytes/s, burst = 2×). Shapes by pausing the sender — never closes. `0` = unshaped. |
| `LINK_RELAY_HOURLY_BYTES` | `0` | per-link rolling hourly quota. When dry, the link drops to the trickle floor instead of closing. `0` = off. |
| `LINK_RELAY_TRICKLE_BPS` | `16384` | floor rate a quota-exhausted link keeps flowing at (so heartbeats survive). |
| `LINK_RELAY_IDLE_SEC` | `300` | links idle this long are reaped. |
| `LINK_IP_RATE_PER_MIN` | `60` | per-IP `register`/`resolve` budget (DoS control). `0` = off. |
| `LINK_TRUST_PROXY` | `0` | `1` = read the client IP from the first `X-Forwarded-For` hop (set this behind a proxy — see DEPLOY). |

What each knob does, in engineer terms, is in [docs/DEPLOY.md](docs/DEPLOY.md).

## Develop

```bash
# relay
cd server && npm install && npm test && npm start    # boots on :80

# client library
cd client && npm install && npm test                 # unit + e2e (spawns real relays)
```

## License

MIT — see [LICENSE](LICENSE).
