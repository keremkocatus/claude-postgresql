# syntax=docker/dockerfile:1

# Base image: python:3.12-slim, pinned by digest so that rebuilds start from the same layers. To move to a newer one:
#   docker pull python:3.12-slim && docker inspect --format '{{index .RepoDigests 0}}' python:3.12-slim
ARG PYTHON_IMAGE=python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

# ── build: install the package into a self-contained virtualenv ─────────────
FROM ${PYTHON_IMAGE} AS builder

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
FROM ${PYTHON_IMAGE}

ARG VERSION=dev
LABEL org.opencontainers.image.title="ratatoskr" \
      org.opencontainers.image.description="Secure multi-connection MCP server for PostgreSQL" \
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
