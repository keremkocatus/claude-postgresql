"""COPY, server-file functions and DO blocks never reach the server through the read tools (pg_query, pg_explain).

Defence in depth: the container user is a superuser, so without the read-path pre-check these statements would
run programs and touch files on the database host. The real boundary is a restricted DB role.
"""

import uuid

import pytest

from tests.integration.helpers import MakeHarness, fetch_value, make_pg_config

pytestmark = pytest.mark.integration

ROLES = {"admins": {"*": "write"}, "readers": {"db": "read"}}


def _scratch_path() -> str:
    return f"/tmp/ratatoskr-{uuid.uuid4().hex}"


async def _exists_on_server(dsn: str, path: str) -> bool:
    # .size, not the whole record: "record IS NOT NULL" is false when any field (creation, on Linux) is NULL
    return bool(await fetch_value(dsn, f"SELECT (pg_stat_file('{path}', true)).size IS NOT NULL"))


def _statements(path: str) -> list[tuple[str, str]]:
    """(sql, expected message) pairs; *path* is a file any of them would create on the server."""
    return [
        (f"COPY (SELECT 1) TO PROGRAM 'touch {path}'", "COPY is not supported here"),
        (f"COPY items TO '{path}'", "COPY is not supported here"),
        ("COPY items TO STDOUT", "COPY is not supported here"),
        (f"/* c */ COPY items TO '{path}'", "COPY is not supported here"),
        (f"DO $$ BEGIN EXECUTE 'CO' || 'PY (SELECT 1) TO PROGRAM ''touch {path}'''; END $$", "DO blocks"),
        ("SELECT pg_read_file('postgresql.conf')", "Blocked operation: pg_read_file"),
        ("SELECT * FROM pg_ls_dir('.')", "Blocked operation: pg_ls_dir"),
        ("SELECT pg_stat_file('postgresql.conf')", "Blocked operation: pg_stat_file"),
    ]


CALLS = [
    ("pg_query", {}),
    ("pg_explain", {}),
    ("pg_explain", {"analyze": True}),
]


@pytest.mark.parametrize("role", ["readers", "admins"])
@pytest.mark.parametrize(("tool", "extra"), CALLS)
@pytest.mark.parametrize("index", range(len(_statements("x"))))
async def test_read_tools_reject_before_the_server(
    seeded: str, make_harness: MakeHarness, role: str, tool: str, extra: dict[str, object], index: int
) -> None:
    path = _scratch_path()
    sql, expected = _statements(path)[index]
    harness = make_harness(make_pg_config(seeded, mode="write", roles=ROLES), role)
    text = await harness.call(tool, sql=sql, **extra)
    assert not await _exists_on_server(seeded, path), f"{tool} created {path} on the server"
    assert text.startswith("Error: "), text
    assert expected in text
    [event] = harness.sink.events
    assert (event.tool, event.result, event.error_class) == (tool, "error", "InvalidRequestError")


async def test_ordinary_reads_still_work(seeded: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_pg_config(seeded, roles=ROLES), "readers")
    text = await harness.call("pg_query", sql="SELECT name FROM items WHERE name = 'apple'")
    assert "apple" in text and not text.startswith("Error")
