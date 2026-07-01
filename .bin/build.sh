#!/usr/bin/env sh

# Shell 'strict' mode
set -ue

docker build -f Dockerfile --target prod --tag link .
