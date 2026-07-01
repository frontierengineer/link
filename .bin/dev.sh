#!/usr/bin/env bash

docker build -f Dockerfile --target dev --tag link .

# No volumes beyond the source mount: Link is in-memory only, there is nothing
# to persist.
docker rm -fv link || true
docker run \
-it \
--rm \
--workdir /server \
-v $(pwd)/server:/server \
-p 8383:80 \
--name link \
--hostname link \
link \
/bin/bash
