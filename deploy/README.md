# Deploying Link

## Running a self-hosted relay

A relay is one static binary with no state on disk: it holds each network's newest roster in
memory and learns it again from the first member that registers. Members dial it at
`wss://<host>/v1` (the URL in their roster's `relay` field); `GET /health` answers `ok`.

Run it in any of three ways.

**Binary.** Build it with Go 1.27 or later:

```sh
cd relay
CGO_ENABLED=0 go build -trimpath -o link-relay ./cmd/link-relay
LINK_ADDR=:8080 ./link-relay
```

**npm.** [`@frontierengineer/link-server`](../relay/npm/README.md) carries the binary for Linux
(x64, arm64), macOS (x64, arm64) and Windows (x64), and a `link-relay` launcher that runs the
right one with arguments, environment and signals passed through:

```sh
LINK_ADDR=:8080 npx @frontierengineer/link-server
```

**Docker.** A distroless image with the static binary, running as a non-root user:

```sh
docker build -t link-relay relay/
docker run -d --name link-relay -p 8080:8080 link-relay
docker run -d -p 9000:9000 -e LINK_ADDR=:9000 -e LINK_RATE_BPS=1048576 link-relay
```

### TLS

Members dial `wss://`. Either put the relay behind a TLS terminator (a load balancer, Caddy,
nginx) that forwards WebSocket upgrades to it over plain HTTP, or give it a certificate with
`LINK_TLS_CERT` and `LINK_TLS_KEY`. A member signs its registration over the host and port it
dialled (section 4.1 of [the spec](../spec/protocol.md)), and the relay checks it against the
`Host` header it receives, without `:80` or `:443`. If the terminator rewrites `Host`, set
`LINK_ORIGIN` to the host members dial (for example `relay.example.com`). If it adds
`X-Forwarded-For`, set `LINK_TRUST_PROXY=true` so the per-IP limits see the members' addresses.

### Settings

Every setting is an environment variable. Unset, every limit is off, which suits a relay that
serves one install; the "public" column is what the shared relay runs with.

| Variable | Default | Public | Meaning |
|---|---|---|---|
| `LINK_ADDR` | `:8080` | | listen address |
| `LINK_ORIGIN` | the request's `Host` | | origin registration signatures are checked against |
| `LINK_TRUST_PROXY` | `false` | | take the client IP from the first `X-Forwarded-For` hop |
| `LINK_TLS_CERT`, `LINK_TLS_KEY` | unset | | serve TLS directly |
| `LINK_RATE_BPS` | off | 1048576 | bytes per second relayed per network; senders are paused, never dropped |
| `LINK_QUOTA_BYTES_HOUR` | off | per deployment | rolling hourly quota per network |
| `LINK_TRICKLE_BPS` | off | 16384 | rate once the quota is spent |
| `LINK_QUEUE_BYTES` | off | 4194304 | bytes queued for one recipient before its senders pause |
| `LINK_SLOW_PEER_SEC` | off | 30 | close (4006) a recipient that drains nothing this long with a full queue |
| `LINK_IP_REGISTER_PER_MIN` | off | 60 | registrations per IP address |
| `LINK_IP_PAIR_PER_MIN` | off | 60 | pairing attempts per IP address |
| `LINK_IP_NETWORKS_PER_HOUR` | off | 10 | new networks first seen from one IP address |
| `LINK_NETWORK_TTL` | `168h` | `168h` | forget a network's roster after this long with nobody connected |

Durations take a Go duration (`168h`, `30s`) or a number of seconds. `LINK_PING_INTERVAL`,
`LINK_PAIR_TIMEOUT` and `LINK_HELLO_TIMEOUT` exist only so tests can shorten timings the spec
fixes; leave them unset.

### Operating it

- SIGTERM or SIGINT closes every connection with code 1001 (after writing what is queued for
  it) and exits 0; members reconnect with backoff, to this relay or its replacement.
- A restart loses nothing that matters: each network's roster comes back with its first member.
- Memory is about 10 KB per idle connection. One relay process serves a network; to spread
  networks over several, route each network's members to the same process.
- The primary can read its network's usage (`Primary.usage()` in the client) and is told when a
  quota crosses 50, 80, 95 and 100 %.
