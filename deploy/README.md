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
`LINK_TLS_CERT` and `LINK_TLS_KEY`. For many connections, terminate in front: TLS in the relay
costs about 12 KB more per connection (Go's TLS buffers, and a reader goroutine per connection
that it cannot do without), where the relay behind a terminator needs about 3.8 KB. The
certificate settings suit a small self-hosted relay.

A member signs its registration over the host and port it dialled (section 4.1 of
[the spec](../spec/protocol.md)), and the relay checks it against the `Host` header it
receives, without `:80` or `:443`. If the terminator rewrites `Host`, set `LINK_ORIGIN` to the
host members dial (for example `relay.example.com`). If it adds `X-Forwarded-For`, set
`LINK_TRUST_PROXY` to the number of proxies in front of the relay (`1` for one load balancer),
so the per-IP limits see the address the outermost proxy saw. The entries to the left of that
are whatever the client wrote, and are never used.

### Settings

Every setting is an environment variable. Unset, every limit is off, which suits a relay that
serves one install; the "public" column is what the shared relay runs with.

| Variable | Default | Public | Meaning |
|---|---|---|---|
| `LINK_ADDR` | `:8080` | | listen address |
| `LINK_ORIGIN` | the request's `Host` | | origin registration signatures are checked against |
| `LINK_TRUST_PROXY` | `0` | | how many proxies are in front (`true` = 1): the client IP is the `X-Forwarded-For` entry the outermost one added, never one the client wrote |
| `LINK_TLS_CERT`, `LINK_TLS_KEY` | unset | | serve TLS directly |
| `LINK_RATE_BPS` | off | 1048576 | bytes per second charged to a network (everything its members send and are answered); senders are paused, never dropped |
| `LINK_QUOTA_BYTES_HOUR` | off | per deployment | quota per network over the last hour (five-minute steps) |
| `LINK_TRICKLE_BPS` | off | 16384 | rate once the quota is spent |
| `LINK_QUEUE_BYTES` | `0` | `0` | bytes held for one recipient before its senders pause; at 0 each sender has at most one frame waiting |
| `LINK_SLOW_PEER_SEC` | off | 30 | close (4006) a recipient that drains nothing this long with a full queue |
| `LINK_IP_REGISTER_PER_MIN` | off | 60 | registrations per IP address |
| `LINK_IP_PAIR_PER_MIN` | off | 60 | pairing attempts per IP address |
| `LINK_IP_NETWORKS_PER_HOUR` | off | 10 | new networks first seen from one IP address |
| `LINK_IP_PENDING` | off | 16 | connections per IP address not registered yet; over it the upgrade is answered 429 |
| `LINK_IP_CONNECTIONS` | off | 1024 | connections per IP address in all; over it the upgrade is answered 429 |
| `LINK_NETWORK_TTL` | `168h` | `168h` | forget a network's roster after this long with nobody connected |
| `LINK_IDLE_ROSTERS_BYTES` | off | 1073741824 | rosters kept for networks nobody is connected to; beyond it the longest idle are forgotten first |
| `LINK_PARK_IDLE` | `true` | `true` | on Linux, an idle connection holds no goroutine (its socket waits in epoll); `false` keeps a reader goroutine per connection. Not used with `LINK_TLS_CERT` |

Durations take a Go duration (`168h`, `30s`) or a number of seconds. `LINK_PING_INTERVAL`,
`LINK_PAIR_TIMEOUT` and `LINK_HELLO_TIMEOUT` exist only so tests can shorten timings the spec
fixes; leave them unset.

### Operating it

- SIGTERM or SIGINT closes every connection with code 1001 (after writing what is queued for
  it) and exits 0; members reconnect with backoff, to this relay or its replacement.
- A restart loses nothing that matters: each network's roster comes back with its first member.
  The relay's roster is a cache; it is kept while anyone of the network is connected and then
  for `LINK_NETWORK_TTL`, within `LINK_IDLE_ROSTERS_BYTES`, so creating networks to fill memory
  only pushes other idle caches out. While kept, it closes revoked members at registration and
  updates members that were offline, even with the primary offline.
- Memory is about 3.8 KB per idle connection on Linux behind a TLS terminator (measured at
  60 000 connections), plus about 3.6 KB of kernel memory per socket: about 7.5 GB for a
  million idle members, if it stays linear. One relay
  process serves a network; to spread networks over several, route each network's members to
  the same process. Raise the open-file limit (`ulimit -n`) and, on a NAT gateway or behind a
  load balancer, the conntrack table, to the number of connections expected.
- Everything a network's members send, and every answer the relay sends them, is charged to
  the network: the rate and the quota cannot be stepped around by sending to absent peers or by
  asking. The relay keeps no per-member figures; each client counts its own traffic
  (`member.traffic()` in the client).
- The primary can ask for its network's usage (`Primary.usage()`): three asks at once, then one
  every 10 seconds, per network. Nothing is pushed; a primary that wants to know whether the
  network is slowed asks.
