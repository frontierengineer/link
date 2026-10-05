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
- `test/` — the client driven against the real relay binary: pairing, registration, sessions,
  rekeying, revocation, usage and the relay's limits, end to end.
- `deploy/` — running a self-hosted relay from the binary, npm or Docker, and its settings.

```sh
(cd relay && go vet ./... && go test -race -count=1 ./...)
(cd relay && LINK_TEST_NO_PARK=1 go test -race -count=1 ./internal/relay)   # a goroutine per connection
(cd client && npm ci && npm run typecheck && npm test && npm run build)
(cd test && npm ci && npm test)                    # builds the client and the relay first
(cd client/scripts/check-vectors-go && go run .)   # the client's vectors, checked in Go
(cd relay/npm && npm run build && npm test)        # cross-compile, pack, run the launcher
```

CI runs all of these on every pull request and push to master. Tags publish: `client-v<version>`
publishes the client and `server-v<version>` the relay package, each with npm provenance.
