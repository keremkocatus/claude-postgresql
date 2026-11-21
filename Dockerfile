# syntax=docker/dockerfile:1

# ── build: install the package into a self-contained virtualenv ─────────────
FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN python -m venv /opt/ratatoskr
WORKDIR /src
# pyproject.toml names README.md (readme) and LICENSE (license-files): hatchling needs both to build.
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
RUN /opt/ratatoskr/bin/pip install . \
 && /opt/ratatoskr/bin/python -m compileall -q /opt/ratatoskr

# ── runtime: non-root, read-only friendly; only /data is written ────────────
FROM python:3.12-slim

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
