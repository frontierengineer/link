# link-relay

The Link relay: sections 4, 5.2, 6 and 9 of [`spec/protocol.md`](../spec/protocol.md). It
verifies registrations and rosters, routes frames between members of one network, joins
newcomers to their primary while they pair, and shapes traffic. It never parses a frame body.

```sh
CGO_ENABLED=0 go build -o link-relay ./cmd/link-relay   # one static binary
LINK_ADDR=:8080 ./link-relay                            # WebSocket at /v1, GET /health -> "ok"
```

## Configuration

The environment variables of section 9. Unset, every limit is off (a self-hosted relay).

| Variable | Default | |
|---|---|---|
| `LINK_ADDR` | `:8080` | listen address |
| `LINK_ORIGIN` | the request's `Host` | origin the registration signature is checked against |
| `LINK_TRUST_PROXY` | `false` | client IP from the first `X-Forwarded-For` hop |
| `LINK_TLS_CERT`, `LINK_TLS_KEY` | unset | serve TLS directly instead of behind a terminator |
| `LINK_RATE_BPS` | off | bytes per second relayed per network |
| `LINK_QUOTA_BYTES_HOUR` | off | rolling hourly quota per network |
| `LINK_TRICKLE_BPS` | off | rate once the quota is spent |
| `LINK_QUEUE_BYTES` | off | bytes queued for one recipient before its senders pause |
| `LINK_SLOW_PEER_SEC` | off | close `4006` after draining nothing this long with a full queue |
| `LINK_IP_REGISTER_PER_MIN` | off | registrations per IP |
| `LINK_IP_PAIR_PER_MIN` | off | pairing attempts per IP |
| `LINK_IP_NETWORKS_PER_HOUR` | off | new networks per IP |
| `LINK_NETWORK_TTL` | `168h` | forget a network's roster after this long with nobody connected (Go duration or seconds) |

SIGTERM closes every connection `1001` (after writing what is queued for it) and exits.

## Shape

- **Per connection, idle:** one goroutine blocked reading a frame header straight from the
  socket. No bufio and no buffers; the HTTP server's buffers are released at the upgrade. A
  writer goroutine exists only while something is queued. Measured on the static binary with
  20 000 idle registered connections, each its own network: about 10 KB of RSS per connection
  (about 4.5 KB goroutine stack, 2.7 KB heap).
- **Shaping and back-pressure** pause the reading goroutine of the sending connection (a timer
  for the network's token bucket, a wait on the recipient's queue). Frames are never dropped.
  Answers the relay queues to a sender (errors, `unreachable`) count towards its own queue.
- **Liveness:** one ticker pings every connection each 30 s and drops one that has not answered
  the previous ping. A connection the relay is holding back is not judged, since its pong may
  be sitting unread behind frames it was paused on.
- **Rosters** are verified with an in-tree RFC 8785 canonicaliser (`internal/link`), checked
  against the RFC's examples.

## Vectors

`go run ./cmd/vectors` writes [`spec/vectors/relay.json`](../spec/vectors/relay.json): keys and
ids from fixed seeds, valid and invalid signed rosters with their JCS bytes, registration
signatures, and routed frames. `go test ./...` fails if the committed file differs.
