# syntax=docker/dockerfile:1

# Base image: python:3.12-slim, pinned by digest so that rebuilds start from the same layers. Both stages name the
# same digest: Dependabot updates each FROM line, and tests/unit/test_dockerfile.py keeps them equal. By hand:
#   docker pull python:3.12-slim && docker inspect --format '{{index .RepoDigests 0}}' python:3.12-slim

# ── build: install the package into a self-contained virtualenv ─────────────
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# No pip, setuptools or wheel in the runtime venv: the builder's own pip installs into it (`--python`).
RUN python -m venv --without-pip /opt/ratatoskr
WORKDIR /src
# pyproject.toml names README.md (readme) and LICENSE (license-files): hatchling needs both to build.
# constraints.txt pins the whole runtime dependency closure to the tested versions (see CLAUDE.md).
COPY pyproject.toml README.md LICENSE constraints.txt ./
COPY src/ src/
RUN python -m pip --python /opt/ratatoskr/bin/python install -c constraints.txt . \
 && /opt/ratatoskr/bin/python -m compileall -q /opt/ratatoskr

# ── runtime: non-root, read-only friendly; only /data is written ────────────
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

# Debian security fixes released after the base image was built: the digest pins the base layers, not their fixes,
# and the image scan (Trivy in CI) fails on a fixed HIGH or CRITICAL vulnerability.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/*

ARG VERSION=dev
# CI (docker/metadata-action) sets source, version and revision from the repository and tag at build time.
LABEL org.opencontainers.image.title="ratatoskr" \
      org.opencontainers.image.description="Secure multi-connection MCP server for PostgreSQL, Prometheus and Loki" \
      org.opencontainers.image.source="https://github.com/keremkocatus/claude-postgresql" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="MIT"

# Pre-compiled bytecode plus PYTHONDONTWRITEBYTECODE: nothing is written outside /data, so the container runs with
# `--read-only` (add `--tmpfs /tmp` if anything ever needs scratch space).
ENV PATH=/opt/ratatoskr/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RATATOSKR_CONFIG=/config/config.yaml

RUN groupadd --system --gid 10001 ratatoskr \
 && useradd --system --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent \
      --shell /usr/sbin/nologin ratatoskr \
 && mkdir -p /data /config \
 && chown 10001:10001 /data \
 && chmod 0750 /data

COPY --from=builder /opt/ratatoskr /opt/ratatoskr

USER 10001:10001
WORKDIR /data
VOLUME ["/data"]
# Keep server.port at 8000 and server.host at 0.0.0.0 in containers; the health check below relies on it.
# server.metrics_port is deliberately not exposed: it has no authentication; reach it only on an internal network.
EXPOSE 8000

# /healthz is exempt from the Host check, so the loopback address is fine.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"]

# uvicorn handles SIGTERM: it stops accepting connections, waits for in-flight requests (bounded by the server's
# graceful-shutdown timeout) and runs the shutdown lifespan (backends closed, audit queue flushed to SQLite). Keep the
# container's stop grace period at 10 s or more (Docker's default; `docker stop -t`, compose `stop_grace_period`), or
# SIGKILL can cut off the audit flush. Exec form keeps ratatoskr as PID 1, so it receives the signal.
# The image installs plain `uvicorn` (h11 parser), not `uvicorn[standard]`/httptools.
STOPSIGNAL SIGTERM
ENTRYPOINT ["ratatoskr"]
CMD ["serve"]
