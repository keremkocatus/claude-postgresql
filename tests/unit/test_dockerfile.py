"""The Dockerfile: one digest-pinned base image for both stages, OCI labels, the uid and port compose relies on."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")


def test_both_stages_use_the_same_digest_pinned_base() -> None:
    bases = re.findall(r"^FROM (\S+)", DOCKERFILE, flags=re.MULTILINE)
    assert len(bases) == 2 and bases[0] == bases[1], "Dependabot updates each FROM line; keep them identical"
    assert re.fullmatch(r"python:3\.12-slim@sha256:[0-9a-f]{64}", bases[0])


def test_labels_and_runtime_contract() -> None:
    assert 'org.opencontainers.image.description="Secure multi-connection MCP server for PostgreSQL, Prometheus' in (
        DOCKERFILE
    )
    assert "USER 10001:10001" in DOCKERFILE
    assert "EXPOSE 8000" in DOCKERFILE
    assert 'ENTRYPOINT ["ratatoskr"]' in DOCKERFILE


def test_runtime_stage_takes_debian_security_fixes() -> None:
    runtime = DOCKERFILE.split("AS builder", 1)[1].split("\nFROM ", 1)[1]
    assert "apt-get upgrade -y" in runtime and "rm -rf /var/lib/apt/lists/*" in runtime
