# Link

A private network for one install. Every member holds one outbound connection to a relay and
exchanges end-to-end encrypted messages with the other members of its network. Nothing listens
on a port, and the relay never sees content.

- `spec/` — the protocol (`protocol.md`) and the test vectors every implementation must pass.
- `relay/` — the relay, in Go. One static binary; published to npm as `@frontierengineer/link-server`.
- `client/` — the client library, in TypeScript; published to npm as `@frontierengineer/link-client`.
- `test/` — tests that run the client against the real relay.
