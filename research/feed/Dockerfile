# The isolate for `watch.py check`, which downloads and runs published MCP
# servers. Built and run by .github/workflows/feed.yml; locally:
#
#   docker build -f research/feed/Dockerfile -t heldfast-feed .
#   docker run --rm --cap-drop ALL --security-opt no-new-privileges \
#     --memory 6g --cpus 2 --pids-limit 2048 --user "$(id -u):$(id -g)" \
#     -v "$PWD/feed-data:/data" heldfast-feed check --data /data --jobs 2
#
# For npm servers, watch.py check-isolated runs on the host and starts this
# image twice per server, with only that server's scratch folder mounted:
# `fetch-one` (network, install scripts off) and `measure-one` (--network
# none). `check-remote` still runs as below, with the feed data mounted.
#
# The only host path it can write is what is mounted. Nothing from the host
# environment is passed in, and measure.py strips the environment again
# before each child starts. It runs as whatever uid owns the mount, so every
# path it writes to at runtime is under /tmp or /data.
# Pinned by digest, like every action in the workflows: a tag can be moved,
# and this image is the sandbox. To update, look up the new index digest
# (docker buildx imagetools inspect node:22-bookworm-slim) and replace it.
FROM node:22-bookworm-slim@sha256:43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 ca-certificates git \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY src/ src/
COPY research/churn/measure.py research/churn/
COPY research/feed/watch.py research/feed/

ENV npm_config_cache=/tmp/npm-cache \
    HOME=/tmp
ENTRYPOINT ["python3", "research/feed/watch.py"]
