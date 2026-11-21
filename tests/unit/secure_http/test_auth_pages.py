from __future__ import annotations

import base64
import hashlib
import re

import pytest
from starlette.responses import HTMLResponse, RedirectResponse

from ratatoskr.auth.pages import apply_security_headers, login_page, message_page, origin_of


def render(**overrides: object) -> HTMLResponse:
    values: dict[str, object] = {
        "request_id": "req-1",
        "csrf_token": "tok",
        "client_name": "Claude",
        "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
        **overrides,
    }
    return login_page(**values)  # type: ignore[arg-type]


def test_login_page_shows_client_and_redirect_host() -> None:
    body = render().body.decode()
    assert "<strong>Claude</strong>" in body and "<strong>claude.ai</strong>" in body
    assert 'name="request" value="req-1"' in body and 'name="csrf_token" value="tok"' in body
    assert '<form method="post" action="/login">' in body


def test_login_page_escapes_attacker_controlled_values() -> None:
    body = render(client_name='<script>alert("x")</script>', username='"><img src=x>').body.decode()
    assert "<script>" not in body and "<img" not in body
    assert "&lt;script&gt;" in body


def test_login_page_escapes_every_field() -> None:
    body = render(
        request_id='"><b>r',
        csrf_token='"><b>t',
        redirect_uri="https://claude.ai/cb",
        error="<b>Wrong</b> & bad",
    ).body.decode()
    assert "<b>" not in body
    assert "&lt;b&gt;Wrong&lt;/b&gt; &amp; bad" in body
    assert 'value="&quot;&gt;&lt;b&gt;r"' in body and 'value="&quot;&gt;&lt;b&gt;t"' in body


def test_login_page_has_no_script() -> None:
    body = render().body.decode().lower()
    assert "<script" not in body and "javascript:" not in body
    assert re.search(r"\son[a-z]+\s*=", body) is None


def test_long_client_names_are_truncated() -> None:
    assert "A" * 81 not in render(client_name="A" * 500).body.decode()


def test_client_name_control_and_bidi_characters_are_removed() -> None:
    body = render(client_name="Cla‮ude\u0000​\nApp").body.decode()
    assert "<strong>Claude App</strong>" in body
    assert "‮" not in body and "\u0000" not in body and "​" not in body


def test_missing_or_blank_client_name_has_a_neutral_label() -> None:
    assert "An unnamed application" in render(client_name=None).body.decode()
    assert "An unnamed application" in render(client_name="‮ ​").body.decode()


def test_security_headers_on_login_page() -> None:
    headers = render().headers
    csp = headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "form-action 'self' https://claude.ai" in csp
    assert "base-uri 'none'" in csp
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["cross-origin-opener-policy"] == "same-origin"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["cache-control"] == "no-store"
    assert headers["content-type"].startswith("text/html")


def test_inline_style_is_allowed_only_by_hash() -> None:
    response = render()
    style = re.search(r"<style>(.*?)</style>", response.body.decode(), re.S)
    assert style is not None
    digest = base64.b64encode(hashlib.sha256(style.group(1).encode()).digest()).decode()
    assert f"style-src 'sha256-{digest}'" in response.headers["content-security-policy"]
    assert "unsafe-inline" not in response.headers["content-security-policy"]
    assert "script-src" not in response.headers["content-security-policy"]


def test_redirect_uri_cannot_inject_into_the_csp() -> None:
    csp = render(redirect_uri="https://claude.ai;script-src *").headers["content-security-policy"]
    assert "script-src" not in csp and "*" not in csp
    assert "form-action 'self';" in csp


def test_message_page_and_redirect_headers() -> None:
    page = message_page("Expired <b>", "Try again & again", 400)
    assert page.status_code == 400 and "Expired &lt;b&gt;" in page.body.decode()
    assert "Try again &amp; again" in page.body.decode()
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert "form-action 'self';" in page.headers["content-security-policy"]
    redirect = apply_security_headers(RedirectResponse("https://claude.ai/cb", status_code=302))
    assert redirect.headers["referrer-policy"] == "no-referrer"
    assert redirect.headers["cross-origin-opener-policy"] == "same-origin"
    assert page.headers["cross-origin-opener-policy"] == "same-origin"
    assert redirect.headers["cache-control"] == "no-store"


def test_origin_of() -> None:
    assert origin_of("https://claude.ai/api/mcp/auth_callback?x=1") == "https://claude.ai"
    assert origin_of("http://localhost:6274/cb") == "http://localhost:6274"
    assert origin_of("HTTPS://Claude.AI/cb") == "https://claude.ai"
    assert origin_of("http://[::1]:8080/cb") == "http://[::1]:8080"


@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(1)",
        "https://claude.ai;script-src */cb",
        "https://claude.ai cb.example/",
        "https://user:pw@claude.ai/cb",
        "https://claude.ai:99999/cb",
        "https://*.claude.ai/cb",
        "https://clаude.ai/cb",
        "https://[fe80::1%25eth0]/cb",
        "/relative",
        "",
    ],
)
def test_origin_of_rejects_anything_that_is_not_a_plain_origin(url: str) -> None:
    assert origin_of(url) is None
