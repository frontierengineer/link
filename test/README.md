# Cross-implementation tests

The TypeScript client (`../client`, as a `file:` dependency) driven against the real Go relay.
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
- `limits.test.ts` — shaping with `LINK_RATE_BPS`, liveness pings, the 1 MiB control message
  limit, control messages a member may not send.
