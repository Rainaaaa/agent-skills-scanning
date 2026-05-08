# syntax=docker/dockerfile:1.7
#
# agent-skills-scanning — pipeline image for static_rule + llm_filter +
# alignment scanners. Includes Python 3.12, the click-based MASB scanner
# stack, and the official Claude Code CLI (used over OAuth).
#
# NOT for the `behavioral` scanner. That one launches Docker containers
# itself (sandbox/run_skill.sh) and must run on a host with Docker, not
# inside a container (Docker-in-Docker is awkward + breaks --cap-add).
#
# Build:
#     docker build -t agent-skills-scanning .
#
# Run (mounting host's ~/.claude/ for OAuth + your work area):
#     docker run --rm -it \
#         -v $(pwd)/inputs:/app/inputs \
#         -v $(pwd)/outputs:/app/outputs \
#         -v $HOME/.claude:/root/.claude:ro \
#         agent-skills-scanning \
#         pipeline/run_pipeline.py --config /app/config.yaml

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# --- System deps + Node 20 + Claude Code CLI ----------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# Claude Code CLI (the OAuth client). The user runs `claude login` on
# the host once; we mount the resulting ~/.claude/ at /root/.claude/.
RUN npm install -g @anthropic-ai/claude-code

WORKDIR /app

# Python deps first (cached layer).
COPY requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

# Pipeline source.
COPY pipeline /app/pipeline
COPY scanners /app/scanners
COPY config.yaml /app/config.yaml
COPY README.md /app/README.md

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Run scanners as a non-root user when possible. Skipped here because
# Claude Code's home-dir search defaults to $HOME and we mount
# /root/.claude; switching users would require re-mounting at /home/x.
ENV HOME=/root

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["--help"]
