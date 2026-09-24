# The isolate for `watch.py check`, which downloads and runs published MCP
# servers. Built and run by .github/workflows/feed.yml; locally:
#
#   docker build -f research/feed/Dockerfile -t heldfast-feed .
#   docker run --rm --cap-drop ALL --security-opt no-new-privileges \
#     --memory 6g --cpus 2 --pids-limit 2048 --user "$(id -u):$(id -g)" \
#     -v "$PWD/feed-data:/data" heldfast-feed check --data /data --jobs 2
#
# The only host path it can write is the feed data. Nothing from the host
# environment is passed in, and measure.py strips the environment again
# before each child starts. It runs as whatever uid owns the mount, so every
# path it writes to at runtime is under /tmp or /data.
FROM node:22-bookworm-slim

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
