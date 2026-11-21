from __future__ import annotations

import pytest

from ratatoskr.auth.redirects import redirect_uri_problem

ALLOWED = ["claude.ai", "claude.com", "localhost", "127.0.0.1"]


@pytest.mark.parametrize(
    "uri",
    [
        "https://claude.ai/api/mcp/auth_callback",
        "https://CLAUDE.com/api/mcp/auth_callback",
        "http://localhost:6274/oauth/callback",
        "http://127.0.0.1:33418/callback",
        "https://localhost/callback",
    ],
)
def test_allowed_redirects(uri: str) -> None:
    assert redirect_uri_problem(uri, ALLOWED) is None


@pytest.mark.parametrize(
    ("uri", "reason"),
    [
        ("https://evil.example/callback", "allowed_redirect_hosts"),
        ("https://claude.ai.evil.example/cb", "allowed_redirect_hosts"),
        ("http://claude.ai/api/mcp/auth_callback", "https"),
        ("https://claude.ai/cb#frag", "fragment"),
        ("https://user:pw@claude.ai/cb", "credentials"),
        ("myapp://callback", "host"),
        ("https://claude.ai:99999/cb", "valid URL"),
        ("javascript:alert(1)", "host"),
    ],
)
def test_rejected_redirects(uri: str, reason: str) -> None:
    problem = redirect_uri_problem(uri, ALLOWED)
    assert problem is not None and reason in problem


@pytest.mark.parametrize(
    "uri",
    [
        "https://evil.com#claude.ai",
        "https://evil.com/#https://claude.ai/cb",
        "https://claude.ai@evil.com/cb",
        "https://claude.ai:443@evil.com/cb",
        "https://claude.ai\\@evil.com/cb",
        "https://evil.com\\.claude.ai/cb",
        "https://claude.ai.evil.com/cb",
        "https://evilclaude.ai/cb",
        "https://claude.ai./cb",
        "https://claude.ai:443.evil.com/cb",
        "https://claude%2eai/cb",
        "https://xn--clude-6ve.ai/cb",
        "https://cl\u0430ude.ai/cb",
        "https://\uff43laude.ai/cb",
        "https:///cb",
        "https:claude.ai/cb",
        "//claude.ai/cb",
        "/cb",
        "",
        "javascript://claude.ai/%0aalert(1)",
        "data:text/html,<script>alert(1)</script>",
        "data://claude.ai/cb",
        "file://claude.ai/cb",
        "ftp://claude.ai/cb",
        "http://localhost.evil.com/cb",
        "http://127.0.0.1.evil.com/cb",
        "http://127.0.0.2/cb",
        "http://[::1]:8080/cb",
    ],
)
def test_suffix_userinfo_idn_scheme_and_host_tricks_are_rejected(uri: str) -> None:
    assert redirect_uri_problem(uri, ALLOWED) is not None


def test_ports_do_not_change_the_host_match() -> None:
    assert redirect_uri_problem("https://claude.ai:8443/cb", ALLOWED) is None
    assert redirect_uri_problem("https://evil.com:443/cb", ALLOWED) is not None


def test_ipv6_loopback_allows_http_when_listed() -> None:
    for allowed in (["::1"], ["[::1]"]):
        assert redirect_uri_problem("http://[::1]:8080/cb", allowed) is None
        assert redirect_uri_problem("https://[::1]/cb", allowed) is None
    assert redirect_uri_problem("http://[::2]:8080/cb", ["::2"]) is not None


def test_http_is_only_for_loopback_even_when_the_host_is_allowed() -> None:
    assert redirect_uri_problem("http://intranet.example/cb", ["intranet.example"]) is not None


def test_allowed_hosts_match_case_insensitively() -> None:
    assert redirect_uri_problem("https://claude.ai/cb", ["Claude.AI"]) is None


def test_non_ascii_hosts_are_rejected_even_when_they_fold_to_an_allowed_host() -> None:
    # U+212A KELVIN SIGN lower-cases to ASCII "k"; urlsplit().hostname lower-cases, so this must be caught first.
    assert redirect_uri_problem("https://\u212aerem.dev/cb", ["kerem.dev"]) is not None


@pytest.mark.parametrize("entry", ["*", "*.claude.ai", ".claude.ai"])
def test_wildcard_entries_never_match(entry: str) -> None:
    for uri in ("https://*.claude.ai/cb", "https://*/cb", "https://api.claude.ai/cb", "https://x.claude.ai/cb"):
        assert redirect_uri_problem(uri, [entry]) is not None


def test_problem_text_does_not_echo_userinfo() -> None:
    problem = redirect_uri_problem("https://user:hunter2@claude.ai/cb", ALLOWED)
    assert problem is not None and "hunter2" not in problem
