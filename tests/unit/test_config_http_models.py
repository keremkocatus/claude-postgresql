from pathlib import Path
from typing import Any

import pytest
from pydantic import AnyHttpUrl, BaseModel, SecretStr, ValidationError

from ratatoskr.config.http_models import (
    BasicAuth,
    BearerAuth,
    HttpAuth,
    HttpTlsSettings,
    NoAuth,
    check_base_url,
    check_headers,
    stringify_header_values,
)

SECRET = "s3cr3t-VALUE-never-shown"


class _Holder(BaseModel):
    auth: HttpAuth


def _messages(exc: ValidationError) -> str:
    return " | ".join(str(error["msg"]) for error in exc.errors(include_input=False, include_url=False))


def test_auth_variants() -> None:
    assert isinstance(_Holder.model_validate({"auth": {"type": "none"}}).auth, NoAuth)
    basic = _Holder.model_validate({"auth": {"type": "basic", "username": "u", "password": "p"}}).auth
    assert isinstance(basic, BasicAuth)
    assert basic.password.get_secret_value() == "p"
    bearer = _Holder.model_validate({"auth": {"type": "bearer", "token": SECRET}}).auth
    assert isinstance(bearer, BearerAuth)
    assert SECRET not in repr(bearer)


@pytest.mark.parametrize(
    ("auth", "expected"),
    [
        ({"type": "bearer", "token": ""}, "auth.token must not be empty"),
        ({"type": "basic", "username": "u", "password": ""}, "auth.password must not be empty"),
        ({"type": "basic", "username": "a:b", "password": "p"}, "auth.username must not contain ':'"),
        ({"type": "bearer", "token": SECRET, "extra": SECRET}, "Extra inputs are not permitted"),
    ],
)
def test_auth_errors_never_echo_values(auth: dict[str, Any], expected: str) -> None:
    with pytest.raises(ValidationError) as caught:
        _Holder.model_validate({"auth": auth})
    assert expected in _messages(caught.value)
    assert SECRET not in _messages(caught.value)


def test_tls_defaults_and_ca_file(tmp_path: Path) -> None:
    assert HttpTlsSettings() == HttpTlsSettings(verify=True, ca_file=None)
    ca = tmp_path / "ca.pem"
    ca.write_text("pem", encoding="utf-8")
    assert HttpTlsSettings(ca_file=ca).ca_file == ca
    with pytest.raises(ValidationError, match="does not exist"):
        HttpTlsSettings(ca_file=tmp_path / "missing.pem")
    with pytest.raises(ValidationError, match="no effect with tls.verify: false"):
        HttpTlsSettings(verify=False, ca_file=ca)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (f"http://user:{SECRET}@prometheus:9090", "must not contain credentials"),
        ("http://prometheus:9090/?token=x", "must not contain a query string or fragment"),
        ("http://prometheus:9090/#top", "must not contain a query string or fragment"),
    ],
)
def test_base_url_rules(url: str, expected: str) -> None:
    with pytest.raises(ValueError, match=expected) as caught:
        check_base_url(AnyHttpUrl(url))
    assert SECRET not in str(caught.value)


def test_base_url_with_a_path_prefix_is_fine() -> None:
    assert str(check_base_url(AnyHttpUrl("https://mimir.example.com/prometheus"))).endswith("/prometheus")


def test_header_values_are_stringified_before_validation() -> None:
    assert stringify_header_values({"X-Scope-OrgID": 42, "X-Flag": True, "X-Name": "a"}) == {
        "X-Scope-OrgID": "42",
        "X-Flag": True,
        "X-Name": "a",
    }
    assert stringify_header_values(None) is None


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ({"Bad Name": SECRET}, "entry 0 is not a valid header name"),
        ({"Authorization": SECRET}, "Authorization cannot be set here"),
        ({"host": SECRET}, "host cannot be set here"),
        ({"X-Tenant": f"a\r\nX-Injected: {SECRET}"}, "the value of X-Tenant contains a line break"),
    ],
)
def test_header_rules_never_echo_values(headers: dict[str, str], expected: str) -> None:
    with pytest.raises(ValueError, match=expected) as caught:
        check_headers({name: SecretStr(value) for name, value in headers.items()})
    assert SECRET not in str(caught.value)


def test_valid_headers_pass() -> None:
    headers = {"X-Scope-OrgID": SecretStr("team-a"), "X-Api-Key": SecretStr(SECRET)}
    assert check_headers(headers) == headers
