# Contributing

Thanks for helping. Bugs and ideas go into [issues](https://github.com/keremkocatus/ratatoskr-mcp/issues);
security problems go through [`SECURITY.md`](SECURITY.md), never into a public issue.

## Setup

Python 3.12 or 3.13, and Docker for the integration tests and the image.

```bash
python -m venv .venv
. .venv/bin/activate                     # Windows: .venv\Scripts\activate
python -m pip install -c constraints.txt -c constraints-dev.txt -e ".[dev]"
```

`constraints.txt` pins the runtime dependencies the image ships, `constraints-dev.txt` the dev tools CI uses, so your
results match CI.

## Checks (all run in CI)

```bash
python -m ruff check src tests
python -m ruff format --check src tests
python -m mypy src                       # strict
python -m pytest -q                      # unit tests: no network, no Docker
python -m pytest -m integration -q       # Docker: testcontainers starts PostgreSQL, Prometheus and Loki
docker build -t ratatoskr:dev .
docker compose -f compose.yml config --quiet       # needs a .env and config.yaml (copy the examples)
docker compose -f compose.dev.yml config --quiet
```

The workflows cannot run locally; lint them with actionlint (their policy, such as SHA-pinned actions and minimal
permissions, is checked by `tests/unit/test_workflows.py`):

```bash
docker run --rm -v "$PWD:/repo" -w /repo rhysd/actionlint:1.7.12
```

The image scan CI runs:

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:0.76.2 image \
  --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed ratatoskr:dev
```

To try changes by hand, use the dev stack in [`compose.dev.yml`](compose.dev.yml) (see the README).

## Rules

The conventions are in [`CLAUDE.md`](CLAUDE.md); read it before changing code. In short:

- Tests first: a failing test, then the code. Unit tests never touch the network or Docker (`tests/fakes.py`);
  anything that needs a real PostgreSQL, Prometheus or Loki goes in `tests/integration/` with
  `pytestmark = pytest.mark.integration`, and only ever uses local containers.
- Every tool call goes through `ToolRuntime`; no secrets in errors, logs or metrics labels; logs go to stderr.
- Docs describe what the code does now. A change of behaviour updates the docs and `CHANGELOG.md` in the same pull
  request.
- Dependencies: a new or upgraded runtime dependency also updates `constraints.txt` (how: `CLAUDE.md`, "Runtime
  constraints"); the image build and the full test suite must pass with it.

## Pull requests

- One topic per pull request, with a description of what changes and why.
- Commit subjects in the imperative ("Add ...", "Fix ..."), and CI green.
- New behaviour comes with tests; a bug fix with a test that failed before it.
