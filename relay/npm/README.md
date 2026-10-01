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
| `LINK_TRUST_PROXY` | `false` | take the client IP from the first `X-Forwarded-For` hop |
| `LINK_TLS_CERT`, `LINK_TLS_KEY` | unset | serve TLS directly |
| `LINK_RATE_BPS` | off | bytes per second relayed per network |
| `LINK_QUOTA_BYTES_HOUR` | off | rolling hourly quota per network |
| `LINK_TRICKLE_BPS` | off | rate once the quota is spent |
| `LINK_QUEUE_BYTES` | off | bytes queued for one recipient before its senders pause |
| `LINK_SLOW_PEER_SEC` | off | close a recipient that drains nothing this long with a full queue |
| `LINK_IP_REGISTER_PER_MIN` | off | registrations per IP address |
| `LINK_IP_PAIR_PER_MIN` | off | pairing attempts per IP address |
| `LINK_IP_NETWORKS_PER_HOUR` | off | new networks per IP address |
| `LINK_NETWORK_TTL` | `168h` | forget a network's roster after this long with nobody connected |

SIGTERM or SIGINT closes every connection with code 1001 and exits 0.

MIT licensed.
