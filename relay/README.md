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
| `LINK_TRUST_PROXY` | `0` | how many proxies are in front (`true` = 1): the client IP is the `X-Forwarded-For` entry the outermost one added, never one the client wrote |
| `LINK_TLS_CERT`, `LINK_TLS_KEY` | unset | serve TLS directly instead of behind a terminator |
| `LINK_RATE_BPS` | off | bytes per second charged to a network (everything its members send and are answered) |
| `LINK_QUOTA_BYTES_HOUR` | off | quota per network over the last hour (five-minute steps) |
| `LINK_TRICKLE_BPS` | off | rate once the quota is spent |
| `LINK_QUEUE_BYTES` | `0` | bytes held for one recipient before its senders pause; at 0 each sender has at most one frame waiting |
| `LINK_SLOW_PEER_SEC` | off | close `4006` after draining nothing this long with a full queue |
| `LINK_IP_REGISTER_PER_MIN` | off | registrations per IP |
| `LINK_IP_PAIR_PER_MIN` | off | pairing attempts per IP |
| `LINK_IP_NETWORKS_PER_HOUR` | off | new networks per IP |
| `LINK_IP_PENDING` | off | connections per IP address not registered yet; over it the upgrade is answered 429 |
| `LINK_IP_CONNECTIONS` | off | connections per IP address in all; over it the upgrade is answered 429 |
| `LINK_NETWORK_TTL` | `168h` | forget a network's roster after this long with nobody connected (Go duration or seconds) |
| `LINK_IDLE_ROSTERS_BYTES` | off | rosters kept for networks nobody is connected to; beyond it the longest idle are forgotten first |
| `LINK_PARK_IDLE` | `true` | on Linux, an idle connection holds no goroutine (its socket waits in epoll); `false` keeps a reader goroutine per connection. Not used with `LINK_TLS_CERT` |

Three timings are fixed by the spec and settable only so tests can shorten them (Go duration
or seconds): `LINK_PING_INTERVAL` (`30s`, section 9), `LINK_PAIR_TIMEOUT` (`60s`, section 5.2)
and `LINK_HELLO_TIMEOUT` (`30s`, section 4.1). Leave them unset in production.

SIGTERM closes every connection `1001` (after writing what is queued for it) and exits.

## Shape

The relay is meant to be thin: bandwidth should be the only thing that limits it.

- **Per connection, idle:** on Linux, no goroutine at all. A registered connection with nothing
  to read is armed, one-shot, in an epoll set (`poll_linux.go`), and a reader goroutine is
  started when its socket is readable. What remains is the `conn` (a 14-byte header scratch, no
  buffers) and the socket. Elsewhere, behind the relay's own TLS, or with
  `LINK_PARK_IDLE=false`, each connection keeps one reader goroutine. Nothing is written by a
  goroutine of its own either: frames are written inline, without blocking, and a writer
  goroutine is started only for a frame the socket does not take at once.
- **Measured** (`LINK_MEASURE=60000 go test -run MeasureIdle -v ./internal/relay`: the binary in
  its own process, 60 000 registered connections in networks of three, one frame through each
  network, Linux, Go 1.27): **3.8 KB of RSS per idle connection** parked, 9.7 KB with a
  goroutine each; the relay before this design measured 11.3 KB the same way. The kernel adds
  about 3.6 KB per socket on top. TLS terminated in the relay costs about 12 KB more per
  connection (the `crypto/tls` buffers, and a goroutine it cannot do without), so a large relay
  runs behind a TLS terminator.
- **Per frame:** two reads (the header and whatever follows it in one, the rest of the body in
  another), one write, one allocation (the payload buffer, with room in front for the outgoing
  header, so a frame leaves in one write and one TLS record), no goroutine started.
  Payload buffers grow as bytes arrive: a frame's declared length is never allocated up front.
- **Per network:** the roster, the connected members, and three counters: twelve five-minute
  slots of charged bytes (the hourly quota), and three theoretical arrival times (the rate
  bucket, the control budget, the usage-ask budget). No per-member figures; members count their
  own traffic.
- **Shaping** is deferred to the body of the next data frame: the relay reads a frame, charges
  it, and holds the sender's next data body back until the network's bucket allows. Control
  (text, pings, handshakes, `refused`, `reset`, `control`) in one unfragmented frame goes ahead
  within the network's control budget. Frames are never dropped.
- **Back-pressure** is TCP's: a sender whose frame a recipient's socket did not take is not read
  again until that frame is written (`LINK_QUEUE_BYTES`, default 0). A connection's own answers
  pause it beyond 64 KiB. Pongs are coalesced to the latest ping.
- **Liveness:** each interval the relay pings every connection, one shard of the table at a
  time, so a large relay's pings are spread out, and drops one that has not answered the
  previous ping. A connection the relay is holding back is not judged.
- **Usage** is request-only (section 4.3): a few asks per network, every answer charged.
- **Rosters** are verified with an in-tree RFC 8785 canonicaliser (`internal/link`), checked
  against the RFC's examples.

`LINK_TEST_NO_PARK=1 go test ./internal/relay` runs the suite with a reader goroutine per
connection; CI runs it both ways.

## Vectors

`go run ./cmd/vectors` writes [`spec/vectors/relay.json`](../spec/vectors/relay.json): keys and
ids from fixed seeds, valid and invalid signed rosters with their JCS bytes, registration
signatures, and routed frames. `go test ./...` fails if the committed file differs.
