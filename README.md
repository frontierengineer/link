# Link

A private network for one install. Every member holds one outbound connection to a relay and
exchanges end-to-end encrypted messages with the other members of its network. Nothing listens
on a port, and the relay never sees content.

- `spec/` — the protocol (`protocol.md`) and the test vectors every implementation must pass:
  `vectors/relay.json` from the relay, `vectors/client.json` from the client. Each side checks
  the other's file in its own suite.
- `relay/` — the relay, in Go. One static binary; a Dockerfile for a distroless image; and
  `relay/npm/`, the npm package `@frontierengineer/link-server` that carries the binary for
  five platforms behind a `link-relay` launcher.
- `client/` — the client library, in TypeScript; published to npm as `@frontierengineer/link-client`.
- `client-go/` — the client library in Go, module `github.com/frontierengineer/link/client-go`,
  released by `client-go/v<version>` tags.
- `client-rust/` — the client library in Rust, crate `link-client`.
- `test/` — every client driven against the real relay binary and against each other through
  per-implementation drivers (`test/drivers/PROTOCOL.md`): pairing, registration, sessions,
  rekeying, revocation, usage and the relay's limits, end to end.
- `deploy/` — running a self-hosted relay from the binary, npm or Docker, and its settings.

```sh
(cd relay && go vet ./... && go test -race -count=1 ./...)
(cd relay && LINK_TEST_NO_PARK=1 go test -race -count=1 ./internal/relay)   # a goroutine per connection
(cd client-typescript && npm ci && npm run typecheck && npm test && npm run build)
(cd client-go && go vet ./... && go test -race -count=1 ./...)
(cd client-rust && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)
(cd test && npm ci && LINK_REQUIRE_DRIVERS=go,rust npm test)   # builds the clients and the relay first
(cd client-typescript/scripts/check-vectors-go && go run .)   # the client's vectors, checked in Go
(cd relay/npm && npm run build && npm test)        # cross-compile, pack, run the launcher
```

CI runs all of these on every pull request and push to main. Tags publish: `client-v<version>`
publishes the client and `server-v<version>` the relay package, each with npm provenance, and
the relay image `ghcr.io/frontierengineer/link-relay:<version>` (linux/amd64 and linux/arm64).
