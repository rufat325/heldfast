# The isolate for measure.py, which downloads and runs published MCP servers.
#
#   docker build -f research/churn/Dockerfile -t heldfast-churn .
#   docker run --rm --cap-drop ALL --security-opt no-new-privileges \
#     --memory 4g --cpus 2 --pids-limit 2048 \
#     -v "$PWD/research/churn/sample.json:/work/research/churn/sample.json:ro" \
#     -v "$PWD/research/churn/results:/work/research/churn/results" \
#     heldfast-churn --jobs 2
#
# The only host path it can write is results/; the sample is mounted
# read-only. Nothing from the host environment is passed in, and measure.py
# strips the environment again before each child starts.
FROM node:22-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 ca-certificates git \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY src/ src/
COPY research/churn/measure.py research/churn/
RUN mkdir -p research/churn/results /tmp/npm && chown -R node:node /work /tmp/npm

USER node
ENV npm_config_cache=/tmp/npm
ENTRYPOINT ["python3", "research/churn/measure.py"]
