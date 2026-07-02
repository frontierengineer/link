# @frontierengineer/link-server

**The embeddable, content-blind [Link](https://github.com/frontierengineer/link)
relay** — a switchboard that introduces two parties and forwards the encrypted bytes
between them, and can read *none* of it.

Run it as a standalone public relay, or embed it in-process — e.g. a desktop app that
runs its own loopback relay so a local connection needs no open ports. Its only
runtime dependency is `ws`.

> Assume the relay is run by an attacker: it still cannot read your traffic, learn a
> pairing code, or impersonate either end. All security lives at the two endpoints
> (SPAKE2 + Noise, in
> [`@frontierengineer/link-client`](https://www.npmjs.com/package/@frontierengineer/link-client)).
> The relay sees only ciphertext and a random routing id.

## Install

```bash
npm install @frontierengineer/link-server ws
```

`ws` is a peer dependency (the relay speaks WebSocket) — the host provides the single
shared instance.

## Embed it

`createLinkServer(config)` returns a `LinkServer` whose `.server` is a Node
`http.Server` you `listen()` yourself, so you own the lifecycle (and can pick the bind
address). `loadConfig()` gives you a full config from the environment to start from.

```ts
import { createLinkServer, loadConfig } from '@frontierengineer/link-server';

// A private, loopback-only relay (e.g. for a local, port-free connection).
const relay = createLinkServer({ ...loadConfig(), port: 8787 });
relay.server.listen(8787, '127.0.0.1', () => {
  console.log('link relay on ws://127.0.0.1:8787');
});

// ...later, graceful shutdown (drains links, closes sockets):
await relay.stop();
```

```ts
interface LinkServer {
  server: import('node:http').Server; // listen()/close() it yourself
  registry: Registry;                 // live links + hosts (introspection)
  stop(): Promise<void>;              // graceful shutdown
}
```

## Run it standalone

```ts
import { createLinkServer, loadConfig } from '@frontierengineer/link-server';
const cfg = loadConfig();             // reads LINK_* env vars (below)
createLinkServer(cfg).server.listen(cfg.port);
```

For a real production relay (Docker image, Cloud Run, TLS termination, scaling), use
the [repo](https://github.com/frontierengineer/link) — `docs/DEPLOY.md`.

## Config

`createLinkServer` takes a full `Config`; `loadConfig()` builds one from these env
vars (all optional). Every shaping cap **paces** traffic — it pauses the sender, it
never closes a link.

| `Config` field | Env var | Default | Meaning |
|---|---|---|---|
| `port` | `LINK_PORT` | `80` | listen port |
| `relayMaxBps` | `LINK_RELAY_MAX_BPS` | `1048576` | per-link rate (bytes/s, burst 2×). `0` = unshaped |
| `relayHourlyBytes` | `LINK_RELAY_HOURLY_BYTES` | `0` | rolling per-link hourly quota; drops to the trickle floor when spent. `0` = off |
| `relayTrickleBps` | `LINK_RELAY_TRICKLE_BPS` | `16384` | floor rate a quota-exhausted link keeps flowing at |
| `relayIdleSec` | `LINK_RELAY_IDLE_SEC` | `300` | links idle this long are reaped |
| `ipRatePerMin` | `LINK_IP_RATE_PER_MIN` | `60` | per-IP `register`/`resolve` budget (DoS control). `0` = off |
| `trustProxy` | `LINK_TRUST_PROXY` | `false` | read the client IP from the first `X-Forwarded-For` hop (set only behind a proxy that refuses direct connections) |
| `allowedRegisterKeys` | `LINK_ALLOWED_REGISTER_KEYS`(`_FILE`) | *(empty)* | empty ⇒ **open** (any signed host may register); non-empty ⇒ **closed** (only these register keys) |
| `origin` | `LINK_ORIGIN` | *(from `Host`)* | canonical `host[:port]` clients dial, bound into register signatures (replay protection) |

## How it fits

- **[`@frontierengineer/link-client`](https://www.npmjs.com/package/@frontierengineer/link-client)** — the host + client ends of the handshake (SPAKE2 pairing → Noise reconnect).
- **`@frontierengineer/link-server`** (this) — the relay in the middle.

Wire protocol, threat model, and deploy guide live in the
**[link repo](https://github.com/frontierengineer/link)**.

## License

MIT
