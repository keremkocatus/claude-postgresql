from __future__ import annotations

from collections.abc import Callable

import pytest
from starlette.responses import Response

from ratatoskr.auth import csrf as csrf_module
from ratatoskr.auth.crypto import Keyring
from ratatoskr.auth.csrf import CSRF_COOKIE_MAX_AGE, CsrfProtector


def protector(secure: bool = True, clock: Callable[[], float] | None = None) -> CsrfProtector:
    if clock is None:
        return CsrfProtector(Keyring("s" * 32).csrf, secure=secure)
    return CsrfProtector(Keyring("s" * 32).csrf, secure=secure, clock=clock)


def test_issued_pair_verifies() -> None:
    csrf = protector()
    cookie, form_token = csrf.issue("req-1")
    assert csrf.verify("req-1", cookie, form_token)


def test_missing_or_mismatched_values_fail() -> None:
    csrf = protector()
    cookie, form_token = csrf.issue("req-1")
    assert not csrf.verify("req-1", None, form_token)
    assert not csrf.verify("req-1", cookie, None)
    assert not csrf.verify("", cookie, form_token)
    assert not csrf.verify("req-2", cookie, form_token)
    other_cookie, _ = csrf.issue("req-1")
    assert not csrf.verify("req-1", other_cookie, form_token)


def test_token_from_another_secret_fails() -> None:
    cookie, form_token = CsrfProtector(Keyring("x" * 32).csrf, secure=True).issue("req-1")
    assert not protector().verify("req-1", cookie, form_token)


def test_fields_are_encoded_unambiguously(monkeypatch: pytest.MonkeyPatch) -> None:
    # With a plain "request_id:cookie" message, ("a", "b:c") and ("a:b", "c") would sign the same bytes.
    monkeypatch.setattr(csrf_module, "new_token", lambda: "b:c")
    csrf = protector()
    cookie, form_token = csrf.issue("a")
    assert cookie == "b:c" and csrf.verify("a", "b:c", form_token)
    assert not csrf.verify("a:b", "c", form_token)


def test_form_token_expires_with_the_cookie(clock) -> None:
    csrf = protector(clock=clock)
    cookie, form_token = csrf.issue("req-1")
    clock.advance(CSRF_COOKIE_MAX_AGE - 1)
    assert csrf.verify("req-1", cookie, form_token)
    clock.advance(2)
    assert not csrf.verify("req-1", cookie, form_token)


def test_form_token_issued_in_the_future_fails(clock) -> None:
    csrf = protector(clock=clock)
    cookie, form_token = csrf.issue("req-1")
    clock.advance(-3600)
    assert not csrf.verify("req-1", cookie, form_token)


def test_tampered_timestamp_fails(clock) -> None:
    csrf = protector(clock=clock)
    cookie, form_token = csrf.issue("req-1")
    _, _, signature = form_token.partition(".")
    clock.advance(CSRF_COOKIE_MAX_AGE + 100)
    assert not csrf.verify("req-1", cookie, f"{int(clock())}.{signature}")


@pytest.mark.parametrize(
    "form_token",
    ["", "abc", ".", "x.y", "1.", "-1.abc", "1e9.abc", "١٢٣.abc", "9" * 40 + ".abc", "1.\udcff", "1.é"],
)
def test_malformed_form_tokens_fail_without_raising(form_token: str) -> None:
    csrf = protector()
    cookie, _ = csrf.issue("req-1")
    assert not csrf.verify("req-1", cookie, form_token)


def test_non_string_values_fail_without_raising() -> None:
    csrf = protector()
    cookie, form_token = csrf.issue("req-1")
    assert not csrf.verify("req-1", cookie, 123)  # type: ignore[arg-type]
    assert not csrf.verify("req-1", ["x"], form_token)  # type: ignore[arg-type]


def test_cookie_attributes() -> None:
    response = Response()
    csrf = protector(secure=True)
    csrf.set_cookie(response, "value")
    header = response.headers["set-cookie"]
    assert header.startswith("__Host-ratatoskr-csrf=value")
    for attribute in ("HttpOnly", "Path=/", "SameSite=strict", "Secure", "Max-Age=600"):
        assert attribute in header
    assert "Domain" not in header


def test_insecure_dev_cookie_has_no_host_prefix_or_secure_flag() -> None:
    response = Response()
    csrf = protector(secure=False)
    csrf.set_cookie(response, "value")
    header = response.headers["set-cookie"]
    assert csrf.cookie_name == "ratatoskr-csrf"
    assert header.startswith("ratatoskr-csrf=value") and "Secure" not in header
    assert "HttpOnly" in header and "SameSite=strict" in header


def test_clear_cookie_expires_the_same_cookie() -> None:
    response = Response()
    csrf = protector(secure=True)
    csrf.clear_cookie(response)
    header = response.headers["set-cookie"]
    assert header.startswith("__Host-ratatoskr-csrf=")
    for attribute in ("Max-Age=0", "Path=/", "Secure", "HttpOnly", "SameSite=strict"):
        assert attribute in header
