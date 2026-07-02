#!/usr/bin/env sh
# Build, push, and deploy the Link relay to Google Cloud Run.
#
# The env/port persist across revisions, so a redeploy is just an image swap.
# Configure via env (image coordinates are required — there are no baked-in
# defaults):
#   TAG       image tag to build + deploy    (REQUIRED; e.g. TAG=v3)
#   PROJECT   GCP project                    (REQUIRED; e.g. my-project)
#   REGION    Cloud Run region               (REQUIRED; e.g. us-central1)
#   SERVICE   Cloud Run service name         (default: link)
#   REPO      registry image path            (REQUIRED; e.g. us-docker.pkg.dev/<project>/<repo>/link)
#
# Prereqs: gcloud authed (roles/run.admin + roles/iam.serviceAccountUser) + Docker.
set -ue

TAG="${TAG:?set TAG, e.g. TAG=v3}"
PROJECT="${PROJECT:?set PROJECT, e.g. PROJECT=my-project}"
REGION="${REGION:?set REGION, e.g. REGION=us-central1}"
SERVICE="${SERVICE:-link}"
REPO="${REPO:?set REPO, e.g. REPO=us-docker.pkg.dev/<project>/<repo>/link}"
IMG="${REPO}:${TAG}"

cd "$(dirname "$0")/.."

echo "→ auth Docker to Artifact Registry"
gcloud auth print-access-token \
  | docker login -u oauth2accesstoken --password-stdin https://us-docker.pkg.dev

echo "→ build ${IMG} (the prod stage runs tsc --noEmit as a gate)"
docker build -f Dockerfile --target prod -t "${IMG}" .

echo "→ push ${IMG}"
docker push "${IMG}"

echo "→ deploy ${SERVICE} (${REGION})"
# The serving shape is pinned here rather than left to persist implicitly, so a
# fresh service — or a careless redeploy — can't drift into an expensive or a
# broken shape. Two independent reasons it must look exactly like this:
#   COST    : --min-instances=0 scales the relay to zero when no socket is open,
#             and --cpu-throttling bills CPU only while a request/WebSocket is in
#             flight (request-based, NOT always-allocated). A single parked host
#             control socket already pins one instance 24/7 (~$60/mo at 1 vCPU);
#             minScale>=1 or --no-cpu-throttling would bill a full instance around
#             the clock even with nobody connected — don't set them.
#   CORRECT : --max-instances=1 and --session-affinity are load-bearing, not tuning.
#             Link's registry is in-memory and per-instance, so a host and the
#             clients resolving it MUST land on the same replica (docs/DEPLOY.md §5).
#             --concurrency=1000 lets that one instance hold many WebSockets — it is
#             also why CPU can't go below 1 (Cloud Run forbids <1 vCPU when
#             concurrency>1). --timeout=3600 is Cloud Run's 60-min WebSocket ceiling.
# Ingress and the public allUsers invoker policy need extra IAM, so they are set
# once out-of-band and persist across image-only redeploys — see docs/DEPLOY.md §2.
gcloud run deploy "${SERVICE}" \
  --project "${PROJECT}" --region "${REGION}" --image "${IMG}" \
  --cpu=1 --memory=512Mi \
  --min-instances=0 --max-instances=1 \
  --concurrency=1000 --timeout=3600 \
  --cpu-throttling --session-affinity --cpu-boost

echo "✓ deployed ${SERVICE} ← ${IMG}"
