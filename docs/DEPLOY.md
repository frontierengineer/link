# Deploying a Link relay

Link is one stateless container with a single runtime dependency (`ws`). It keeps
everything in memory, so there are no volumes, no database, and no migrations — a
restart just drops live relays and clients reconnect. That makes it a perfect fit
for a serverless container runtime.

This doc covers an **example deployment** (Google Cloud Run), how to **ship an
update**, the **config knobs** in engineer terms, and **self-hosting** anywhere
else — Cloud Run is only one option (see §6).

---

## 1. Example deployment: Cloud Run (no CDN in front)

One simple way to run the relay is a single **Cloud Run** service, reached directly
over the platform's edge — with deliberately **no CDN/reverse-proxy** in front of it
(see §3). Substitute your own project / region / registry / hostname:

| | |
|---|---|
| GCP project | `<your-gcp-project>` |
| Service | `link` (region `<your-region>`) |
| Image | `<your-registry>/link:<tag>` (manual `vN` tags) |
| Public name | `link.example.com` via a Cloud Run **domain mapping** → the service |
| TLS | terminated by the platform with a managed cert (the domain mapping provisions it). The raw `…-uc.a.run.app` URL also answers. |
| DNS | point a DNS record (e.g. a `CNAME`) at your relay's public address, and keep any DNS provider *out* of the request path (DNS-only, no proxy) — see §3. |
| Ingress | `all`, public (`allUsers` → `run.invoker`) |
| Scaling | single instance (`maxScale = 1`), session affinity on, `containerConcurrency = 1000`, startup-CPU-boost; request timeout `3600s` |
| Resources | 1 vCPU / 512 MiB |
| Env (example) | `LINK_PORT=8080`, `LINK_TRUST_PROXY=1`, `LINK_RELAY_HOURLY_BYTES=2147483648` (2 GiB/hr/link); everything else = code defaults |

Two Cloud Run specifics matter for a WebSocket relay:

- **`maxScale = 1` is deliberate.** Link's registry is **in-memory and
  per-instance**: a host registers its address on the instance it connected to, and
  that same instance must handle the client `resolve` and the host's relay
  dial-back. A single instance keeps that consistent. Session affinity is on for the
  same reason. To scale past one instance you must route by `address` so a host and
  its clients land on the same replica — see §5.
- **Cloud Run caps a single request (a WebSocket) at 60 minutes** (`timeoutSeconds:
  3600`). A long-lived relay is dropped at that ceiling; the client library
  auto-reconnects, so it's transparent — but it's why the idle reaper and reconnect
  logic exist.

## 2. Ship an update

Building and deploying is a plain **build → push → deploy** loop; the env/port
persist across revisions, so a redeploy is just an image swap. The repo ships
`.bin/deploy-cloudrun.sh` to do all of this:

```bash
cd link
TAG=v3 PROJECT=<your-gcp-project> REGION=<your-region> \
  REPO=<your-registry>/link ./.bin/deploy-cloudrun.sh    # build → push → deploy
```

Equivalently, by hand:

```bash
cd link
TAG=v3
IMG=<your-registry>/link:$TAG

# Auth Docker to your registry (example: Google Artifact Registry).
gcloud auth print-access-token \
  | docker login -u oauth2accesstoken --password-stdin https://us-docker.pkg.dev

# Build (the prod stage runs `tsc --noEmit` as a gate), push, deploy.
docker build -f Dockerfile --target prod -t "$IMG" .
docker push "$IMG"
gcloud run deploy link \
  --project <your-gcp-project> --region <your-region> --image "$IMG"
```

Cloud Run shifts traffic to the new revision once it passes its health check
(`GET /health`). Rollback: `gcloud run services update-traffic link
--region <your-region> --to-revisions <old-revision>=100`.

> A Cloud Run deploy service account needs `roles/run.admin` +
> `roles/iam.serviceAccountUser` (and `run.invoker` for `allUsers` if you (re)set the
> public-invoker policy).

## 3. TLS and the front door — why there's no CDN

The relay answers directly at its public name, but **nothing proxies it**: Cloud
Run's domain mapping terminates TLS at the platform edge with a managed
certificate, and the DNS record is DNS-only (no proxy in front).

This is **intentional.** A CDN/proxy in front of Link buys nothing and can hurt:
Link's traffic is bulk, opaque, **end-to-end-encrypted frames over long-lived
WebSockets** — the opposite of the cacheable, short-request workload a CDN is for.
Proxying it adds a hop, can interfere with long-lived upgrades, and protects nothing
(the payload is already ciphertext the proxy can't read). So Link is served directly
off Cloud Run's edge.

Consequences for abuse defense and `X-Forwarded-For`:

- **The origin is public** (`ingress: all`, `allUsers` invoker — the branded name
  *and* the raw `*.run.app` URL answer). There is no edge allowlist because there is
  no edge proxy. **Abuse defense is entirely in-app:** the per-IP rate limit on
  `register`/`resolve` (`LINK_IP_RATE_PER_MIN`), relay shaping + the hourly quota,
  the content-blind splice, and signed (anti-squat) registration. None of these are
  load-bearing for *security* — the end-to-end crypto is — they bound *abuse*.
- **`LINK_TRUST_PROXY=1` here trusts Cloud Run's frontend, not a CDN.** Behind Cloud
  Run, the socket's peer is the platform frontend, which sets `X-Forwarded-For` to
  the real client IP (first hop). With trust-proxy on, the per-IP limiter reads that
  hop. This is safe because the client cannot reach Link *except* through that
  frontend, so it cannot forge the hop the frontend writes.

> **If you self-host *and* put your own reverse-proxy/CDN in front** (§6), then the
> usual caveat applies: only set `LINK_TRUST_PROXY=1` if your origin refuses
> connections that don't come through your proxy (otherwise a client hits the origin
> directly and spoofs `X-Forwarded-For` to dodge the per-IP limit). With Cloud Run's
> built-in frontend there's no such gap.

## 4. Configuration knobs, in engineer terms

All optional; all read from env at boot. The relay-shaping knobs are the
interesting ones — they **shape** traffic (pause + pace the sender) rather than
close connections, so a noisy link degrades smoothly instead of dying.

### The two buckets and the floor

Each live relay has up to three token buckets:

- **`LINK_RELAY_MAX_BPS`** (default `1048576` = 1 MiB/s) — a **rate** bucket,
  refilled at this many bytes/sec, burst capacity `2×` (it can absorb ~2 s of
  traffic instantly). A frame that would overdraw it is **not** dropped: Link stops
  reading that socket (so TCP backpressure stalls the *real* sender) and forwards
  the frame once the bucket has refilled enough to pay for it. Net effect: a smooth
  per-link speed limit that never breaks a connection. `0` disables.

- **`LINK_RELAY_HOURLY_BYTES`** (default `0` = off; example `2147483648` = 2 GiB)
  — a **rolling hourly quota** per link: a second bucket whose capacity is one
  hour's allowance, refilled continuously (a sliding window, not a top-of-the-hour
  reset). While the link has quota, it runs at full `MAX_BPS`. When the quota runs
  dry, the link does **not** close — it drops to the trickle floor.

- **`LINK_RELAY_TRICKLE_BPS`** (default `16384` = 16 KiB/s) — the **floor** a
  quota-exhausted link keeps flowing at. Heartbeats and small control traffic still
  get through, so a link that has burned its hourly quota slows to a crawl instead of
  dying. Full speed returns as the rolling hourly bucket refills.

**Worked example** (example settings: 1 MiB/s rate, 2 GiB/hr quota, 16 KiB/s floor): a
link can move bytes at up to 1 MiB/s. It can sustain that for ~35 minutes before the
2 GiB hourly quota is spent; after that it's paced at 16 KiB/s (enough to stay
alive) while the rolling quota refills — about 30 s of refill buys back ~1 MiB of
full-rate budget. The link never closes from rate or quota; the only relay condition
that *closes* is a peer that stops draining (below).

### Lifecycle & DoS

- **`LINK_RELAY_IDLE_SEC`** (default `300`) — a relay with **no** traffic for this
  long is reaped (close `4004`). A held/paced frame counts as activity, so a slow
  link isn't mistaken for a dead one.
- **`LINK_IP_RATE_PER_MIN`** (default `60`) — per-IP budget for `register`/`resolve`
  control messages per minute (fixed window). Pure DoS control on the introduction
  plane. It is **not** what protects the pairing code (that's the host's SPAKE2
  lockout, end-to-end). `0` disables. Behind any frontend, needs `LINK_TRUST_PROXY=1`
  to see real IPs.
- **`LINK_TRUST_PROXY`** (default `0`; set to `1` behind a trusted frontend) — read
  the client IP from the first `X-Forwarded-For` hop. See §3.
- **`LINK_PORT`** (default `80`; Cloud Run uses `8080`, the value of `$PORT`) — listen
  port.

### Access control (introduction plane)

These gate *who may register* and bind the register signature more tightly. They are
additive checks on the introduction plane — they never touch the end-to-end crypto,
and they are pure config (no per-host state, so Link stays stateless and scales the
same way).

- **`LINK_ALLOWED_REGISTER_KEYS`** (default empty ⇒ **open**) — a comma-separated
  list of authorized register public keys (base64url). Non-empty ⇒ **closed** mode:
  only a host whose register key is listed may register; any other *validly signed*
  register is refused with close `4010`. A host's register key is
  `registerSignerFromStatic(hostStatic.priv).pub` (the client library exposes it);
  the address it derives is `base64url(SHA-256(that key))`.
- **`LINK_ALLOWED_REGISTER_KEYS_FILE`** (default empty) — a file of allowlisted keys
  (one per line, blank lines and `#` comments ignored), unioned with the inline list.
  Handy for a longer or externally-managed allowlist. Adding/removing a host is a
  config change + restart — deliberately simple, with no dynamic pairing state.
- **Address-key binding is always on (no knob).** Every register's address must be
  `base64url(SHA-256(register key))` — an address is a commitment to a key nobody
  else holds, so it cannot be squatted or raced *at all* (a mismatch is refused
  `4007`). There is no opaque-address mode: the routing layer is spoof-*proof* by
  construction.
- **`LINK_ORIGIN`** (default: derived from each request's `Host` header) — the
  canonical `host[:port]` clients dial this instance at, folded into register
  signatures so a captured frame can't be replayed at a *different* Link. The default
  is correct unless a proxy rewrites `Host`; if it does, set this to the public
  authority (e.g. `link.example.com`).

Hard limits that are *not* env-tunable (they bound memory/abuse): control frames
≤ 4 KiB, relay frames ≤ 16 MiB, ≤ 64 concurrent dial-backs per host per uplink. A
peer that stops draining past 64 MiB buffered is cut (close `4006`).

## 5. Scaling past one instance

Link's registry is per-instance, so horizontal scaling requires that a host and the
clients resolving its address reach the **same** replica. Put a layer in front that
hashes on the `address` (consistent / ring hash) and pins each address to a replica.
Because every registration is signed and pinned (TOFU), and each replica is
independent, an address simply lives on whichever replica its host connected to; the
hash makes clients find it. Until you need it, `maxScale = 1` is simplest and
correct.

## 6. Self-hosting anywhere

```bash
# Docker (the simplest thing that works)
docker build -t link -f Dockerfile .
docker run -d --restart unless-stopped -p 80:80 \
  -e LINK_TRUST_PROXY=1 -e LINK_RELAY_HOURLY_BYTES=2147483648 \
  --name link link
curl localhost:80/health
```

`deploy/link.yaml` is a minimal Kubernetes example (Namespace + ClusterIP Service +
single-replica Deployment) — point your ingress at the Service for TLS. There are no
volumes on purpose.

Anything that runs a container works: Cloud Run, Fly.io, a plain VM with Caddy/nginx
terminating TLS, k8s. The requirements are: WebSockets pass through, TLS terminates
in front (a managed cert, or your own proxy), and — if you scale past one instance —
address-affinity routing per §5. If you put your own proxy/CDN in front, mind the
`X-Forwarded-For` caveat in §3.
