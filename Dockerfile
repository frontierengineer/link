FROM debian:bookworm as dev
ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /server
EXPOSE 80
CMD node_modules/.bin/ts-node index.ts

RUN apt-get update \
  && apt-get install -y \
  nodejs \
  npm \
  curl \
  ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Pin Node to an LTS line (>= 22) — Debian's packaged nodejs is older.
RUN npm install -g \
  n \
  && n lts

FROM dev as prod

# Server dependencies first so a source-only change doesn't bust the npm layer.
COPY server/package* /server/
RUN npm install

# Server source.
COPY server /server

# Typecheck before shipping. index.ts runs through ts-node at container start
# with no compile step, so a strict TS error would otherwise only surface as a
# module-load crash in prod. Fail the build here instead.
RUN cd /server && ./node_modules/.bin/tsc --noEmit
