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
gcloud run deploy "${SERVICE}" \
  --project "${PROJECT}" --region "${REGION}" --image "${IMG}"

echo "✓ deployed ${SERVICE} ← ${IMG}"
