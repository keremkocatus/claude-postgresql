"""Redirect allowlist tests.

Production (DCR) receives redirect URIs through ``OAuthClientMetadata`` (pydantic ``AnyUrl``) and checks
``str(uri)``, so most cases first go through :func:`normalised`. The raw-string tests at the end cover inputs pydantic
already refuses or rewrites: the check must not depend on that normalisation.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import pytest
from mcp.shared.auth import OAuthClientMetadata
from pydantic import ValidationError

from ratatoskr.auth.redirects import MAX_REDIRECT_URI_LENGTH, redirect_uri_problem

ALLOWED = ["claude.ai", "claude.com", "localhost", "127.0.0.1"]


def normalised(uri: str) -> str:
    """What the provider's ``register_client`` sees: ``str(AnyUrl)`` after the SDK's DCR model validation."""
    metadata = OAuthClientMetadata.model_validate({"redirect_uris": [uri]})
    assert metadata.redirect_uris is not None
    return str(metadata.redirect_uris[0])


def problem(uri: str, allowed: list[str] = ALLOWED) -> str | None:
    return redirect_uri_problem(normalised(uri), allowed)


@pytest.mark.parametrize(
    "uri",
    [
        "https://claude.ai/api/mcp/auth_callback",
        "https://CLAUDE.com/api/mcp/auth_callback",
        "http://localhost:6274/oauth/callback",
        "http://127.0.0.1:33418/callback",
        "https://localhost/callback",
        "https://claude.ai:8443/cb",
    ],
)
def test_allowed_redirects(uri: str) -> None:
    assert problem(uri) is None


@pytest.mark.parametrize(
    ("uri", "reason"),
    [
        ("https://evil.example/callback", "allowed_redirect_hosts"),
        ("https://claude.ai.evil.example/cb", "allowed_redirect_hosts"),
        ("http://claude.ai/api/mcp/auth_callback", "https"),
        ("https://claude.ai/cb#frag", "fragment"),
        ("https://user:pw@claude.ai/cb", "credentials"),
        ("myapp://callback", "allowed_redirect_hosts"),
        ("javascript:alert(1)", "host"),
    ],
)
def test_rejected_redirects(uri: str, reason: str) -> None:
    result = problem(uri)
    assert result is not None and reason in result


@pytest.mark.parametrize(
    "uri",
    [
        "https://evil.com#claude.ai",
        "https://evil.com/#https://claude.ai/cb",
        "https://claude.ai@evil.com/cb",
        "https://claude.ai:443@evil.com/cb",
        "https://evil.com\\.claude.ai/cb",
        "https://claude.ai.evil.com/cb",
        "https://evilclaude.ai/cb",
        "https://claude.ai./cb",
        "https://xn--clude-6ve.ai/cb",
        "https://cl\u0430ude.ai/cb",
        "https://evil.com:443/cb",
        "https:///cb",
        "javascript://claude.ai/%0aalert(1)",
        "data:text/html,<script>alert(1)</script>",
        "data://claude.ai/cb",
        "file://claude.ai/cb",
        "ftp://claude.ai/cb",
        "http://localhost.evil.com/cb",
        "http://127.0.0.1.evil.com/cb",
        "http://127.0.0.2/cb",
        "http://[::1]:8080/cb",
        "https://*.claude.ai/cb",
    ],
)
def test_suffix_userinfo_idn_scheme_and_host_tricks_are_rejected(uri: str) -> None:
    assert problem(uri) is not None


@pytest.mark.parametrize(
    "uri",
    [
        "https://claude.ai\\@evil.com/cb",  # backslash is a path separator: https://claude.ai/@evil.com/cb
        "https://claude%2eai/cb",
        "https://\uff43laude.ai/cb",  # fullwidth c maps to ASCII c (IDNA/UTS 46)
        "https:claude.ai/cb",
    ],
)
def test_inputs_pydantic_rewrites_to_an_allowed_host_are_allowed_for_that_host(uri: str) -> None:
    # The stored and later used redirect URI is the normalised one, which really points at claude.ai.
    assert urlsplit(normalised(uri)).hostname == "claude.ai"
    assert problem(uri) is None


def test_kelvin_sign_is_normalised_to_its_ascii_host() -> None:
    # U+212A KELVIN SIGN maps to "k": the normalised URI points at kerem.dev, as a browser would.
    assert normalised("https://\u212aerem.dev/cb") == "https://kerem.dev/cb"
    assert problem("https://\u212aerem.dev/cb", ["kerem.dev"]) is None
    assert problem("https://\u212aerem.dev/cb", ALLOWED) is not None


@pytest.mark.parametrize(
    "uri", ["", "/cb", "//claude.ai/cb", "https://claude.ai:443.evil.com/cb", "https://claude.ai:99999/cb"]
)
def test_pydantic_refuses_these_before_the_allowlist(uri: str) -> None:
    with pytest.raises(ValidationError):
        normalised(uri)


def test_ipv6_loopback_allows_http_when_listed() -> None:
    for allowed in (["::1"], ["[::1]"]):
        assert problem("http://[::1]:8080/cb", allowed) is None
        assert problem("https://[::1]/cb", allowed) is None
    assert problem("http://[::2]:8080/cb", ["[::2]"]) is not None


def test_http_is_only_for_loopback_even_when_the_host_is_allowed() -> None:
    assert problem("http://intranet.example/cb", ["intranet.example"]) is not None


def test_allowed_hosts_match_case_insensitively() -> None:
    assert problem("https://claude.ai/cb", ["Claude.AI"]) is None


@pytest.mark.parametrize("entry", ["*", "*.claude.ai", ".claude.ai"])
def test_wildcard_entries_never_match(entry: str) -> None:
    for uri in ("https://*.claude.ai/cb", "https://*/cb", "https://api.claude.ai/cb", "https://x.claude.ai/cb"):
        assert problem(uri, [entry]) is not None


@pytest.mark.parametrize(
    "uri",
    [
        "https://user:hunter2@claude.ai/cb#frag",
        "https://user:hunter2@claude.ai/cb",
        "http://user:hunter2@claude.ai/cb",
        "https://claude.ai/cb?token=hunter2#frag",
        "http://claude.ai/cb?token=hunter2",
        "javascript:hunter2",
    ],
)
def test_problem_text_never_echoes_the_uri(uri: str) -> None:
    result = problem(uri)
    assert result is not None and "hunter2" not in result and "/cb" not in result


def test_overlong_redirect_uris_are_rejected() -> None:
    base = "https://claude.ai/"
    assert problem(base + "a" * (MAX_REDIRECT_URI_LENGTH - len(base))) is None
    result = problem(base + "a" * (MAX_REDIRECT_URI_LENGTH - len(base) + 1))
    assert result is not None and str(MAX_REDIRECT_URI_LENGTH) in result


# ── raw strings: the check does not rely on pydantic's normalisation ─────────────────────────


@pytest.mark.parametrize(
    "uri",
    [
        "",
        "/cb",
        "//claude.ai/cb",
        "https:claude.ai/cb",
        "https://claude.ai:443.evil.com/cb",
        "https://claude.ai:99999/cb",
        "https://claude.ai\\@evil.com/cb",
        "https://evil.com\\.claude.ai/cb",
        "https://claude%2eai/cb",
        "https://\uff43laude.ai/cb",
        "https://*.claude.ai/cb",
    ],
)
def test_raw_strings_pydantic_refuses_or_rewrites_are_rejected(uri: str) -> None:
    assert redirect_uri_problem(uri, ALLOWED) is not None


def test_raw_non_ascii_host_folding_to_an_allowed_host_is_rejected() -> None:
    # urlsplit().hostname lower-cases U+212A to "k"; the raw check must catch it before that.
    assert redirect_uri_problem("https://\u212aerem.dev/cb", ["kerem.dev"]) is not None
