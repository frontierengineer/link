# Cross-implementation tests

The TypeScript client (`../client`, as a `file:` dependency) driven against the real Go relay,
and every client implementation (TypeScript, Go, Rust) driven against the others through its
driver.
No mocks: each test file builds the relay with `go build` into a temporary directory, and each
test starts its own relay process on a random loopback port, configured only through `LINK_*`
environment variables (short timings and limits where a test needs them).

```sh
npm ci
npm test        # pretest rebuilds the client, so the tests never run an old dist/
```

Set `LINK_RELAY_BIN` to use a relay binary already built. Needs Go, Node 22 or later, and
Playwright's Chromium at the version `package.json` pins (`npx playwright install chromium`).

- `pairing.test.ts` — codes and links, SPAKE2, the roster push, the effective-roster rule at
  registration, the pairing channel's end (a dropped newcomer, the relay's timeout) refunding
  the code's slot, the hello timeout.
- `sessions.test.ts` — several-MiB messages, credit flow control, rekeying on a timer and a
  count, reset after a peer loses its state, responder expiry, unreachable peers, 4005.
- `membership.test.ts` — revocation (4008), resignation, refusal by a member whose roster is
  behind, the relay forgetting an idle network, usage, the quota and its trickle rate.
- `browser.test.ts` — the client bundled for the browser with esbuild and loaded into headless
  Chromium, where a surface pairs with a Node primary, exchanges small and several-MiB
  messages with it and with a Node worker, receives a roster push, and is revoked.
- `origin.test.ts` — members dialling `ws://127.0.0.1:443` register: both sides drop `:443`.
  Needs permission to listen on 443 (root, or `net.ipv4.ip_unprivileged_port_start=0`); without
  it the test is skipped and says why, except with `LINK_REQUIRE_PORT_443=1`, as in CI.
- `limits.test.ts` — shaping with `LINK_RATE_BPS`, liveness pings, the 65000-byte roster limit,
  the 1 MiB control message limit, control messages a member may not send.
- `interop.test.ts` — the clients against one another, each node a **driver** of its
  implementation (below): pairing by link and by code fields; wrong, burned, expired and
  cancelled codes; small and several-MiB messages both ways (sha256); flow control with a
  receiver that does not take; rekeying on a timer and on a message count, seen through
  `sessions` and counted from the traffic report; reset after a peer restarts from its seed; unreachable peers; refusal by a
  member whose roster is behind; revocation; resignation; a revocation spreading member to
  member with the primary offline; replacement (4005) by a copy of another implementation;
  usage and its budget; traffic counters agreeing between sender and receiver; a network of
  every implementation at once; and, per implementation, the driver's lifecycle and error codes.

## Drivers

A driver runs one node and is steered over stdio; [`drivers/PROTOCOL.md`](drivers/PROTOCOL.md)
is the contract. `drivers/typescript.ts` is the TypeScript client's, and the reference: the Go
and Rust drivers behave as it does. `support/driver.ts` starts a driver as a child process and
gives tests a typed API over it, and fails a test whose driver wrote to stdout outside the
protocol or exited non-zero; when a test fails, every driver's stderr and the relay's log are
printed.

Each scenario runs once per *cast*: the implementation of the primary and of two other nodes,
covering every ordered pair of the two, each implementation as primary equally often, and (with
three implementations) networks of all three: one cast with one implementation, four with two,
nine with three.

| Variable | |
|---|---|
| `LINK_DRIVER_TS` | the TypeScript driver's command line; default `node --import tsx drivers/typescript.ts` |
| `LINK_DRIVER_GO` | default: `go build ./cmd/link-driver` in `../client-go`, then run it |
| `LINK_DRIVER_RUST` | default: `cargo build --release --bin link-driver` in `../client-rust`, then run `target/release/link-driver` |
| `LINK_DRIVERS` | a comma list such as `ts,go`: only those run (default: all three) |
| `LINK_REQUIRE_DRIVERS` | a comma list such as `go,rust`: those must be available, or the suite fails |

Commands run from `test/`. An implementation whose driver is not available (its directory does
not exist yet, or the build fails) is skipped with the reason, unless `LINK_REQUIRE_DRIVERS`
names it. One that builds but misbehaves fails: `LINK_DRIVERS=ts` runs without it. To prove every combination with the TypeScript driver standing in for the others:

```sh
LINK_DRIVER_GO="node --import tsx drivers/typescript.ts" \
LINK_DRIVER_RUST="node --import tsx drivers/typescript.ts" \
LINK_REQUIRE_DRIVERS=ts,go,rust npm run test:interop
```
