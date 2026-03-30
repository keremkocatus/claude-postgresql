FROM python:3.11-slim AS builder

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src/ src/

RUN pip install --no-cache-dir .

# ── Runtime ───────────────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/claude-postgresql /usr/local/bin/claude-postgresql

ENV PG_MCP_TRANSPORT=streamable-http
ENV PG_MCP_HOST=0.0.0.0

EXPOSE 8000

CMD ["claude-postgresql"]
