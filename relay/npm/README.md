# @frontierengineer/link-server

The Link relay as an npm package: the static Go binary for Linux (x64, arm64), macOS (x64,
arm64) and Windows (x64), and a small launcher that runs the right one. The relay routes
end-to-end encrypted frames between the members of a network, joins newcomers to their
primary while they pair, and never sees content. The protocol is
[`spec/protocol.md`](https://github.com/frontierengineer/link/blob/master/spec/protocol.md).

```sh
npx @frontierengineer/link-server                    # listens on :8080
LINK_ADDR=127.0.0.1:9000 npx @frontierengineer/link-server
curl http://127.0.0.1:9000/health                    # ok
```

Or install it and run `link-relay`. Clients connect to `ws://<host>/v1`, or `wss://` behind a
TLS terminator (or with `LINK_TLS_CERT` and `LINK_TLS_KEY` set).

The relay is configured only by environment variables, which the launcher passes through with
its arguments, signals and exit code. Unset, every limit is off, which suits a self-hosted relay.

| Variable | Default | |
|---|---|---|
| `LINK_ADDR` | `:8080` | listen address |
| `LINK_ORIGIN` | the request's `Host` | origin registration signatures are checked against; set it behind a proxy that rewrites `Host` |
| `LINK_TRUST_PROXY` | `0` | how many proxies are in front (`true` = 1): the client IP is the `X-Forwarded-For` entry the outermost one added, never one the client wrote |
| `LINK_TLS_CERT`, `LINK_TLS_KEY` | unset | serve TLS directly |
| `LINK_RATE_BPS` | off | bytes per second charged to a network (everything its members send and are answered) |
| `LINK_QUOTA_BYTES_HOUR` | off | quota per network over the last hour (five-minute steps) |
| `LINK_TRICKLE_BPS` | off | rate once the quota is spent |
| `LINK_QUEUE_BYTES` | `0` | bytes held for one recipient before its senders pause; at 0 each sender has at most one frame waiting |
| `LINK_SLOW_PEER_SEC` | off | close a recipient that drains nothing this long with a full queue |
| `LINK_IP_REGISTER_PER_MIN` | off | registrations per IP address |
| `LINK_IP_PAIR_PER_MIN` | off | pairing attempts per IP address |
| `LINK_IP_NETWORKS_PER_HOUR` | off | new networks per IP address |
| `LINK_IP_PENDING` | off | connections per IP address not registered yet; over it the upgrade is answered 429 |
| `LINK_IP_CONNECTIONS` | off | connections per IP address in all; over it the upgrade is answered 429 |
| `LINK_NETWORK_TTL` | `168h` | forget a network's roster after this long with nobody connected |
| `LINK_IDLE_ROSTERS_BYTES` | off | rosters kept for networks nobody is connected to; beyond it the longest idle are forgotten first |
| `LINK_PARK_IDLE` | `true` | on Linux, an idle connection holds no goroutine (its socket waits in epoll); `false` keeps a reader goroutine per connection. Not used with `LINK_TLS_CERT` |

SIGTERM or SIGINT closes every connection with code 1001 and exits 0.

MIT licensed.
