from datetime import timedelta
from pathlib import Path
from typing import Any, ClassVar, Literal

import pytest
from pydantic import AnyHttpUrl, BaseModel, SecretStr, ValidationError

from ratatoskr.config.http_models import (
    BasicAuth,
    BearerAuth,
    HttpAuth,
    HttpConnection,
    HttpTlsSettings,
    NoAuth,
    check_base_url,
    check_headers,
    stringify_header_values,
)

SECRET = "s3cr3t-VALUE-never-shown"
HEADER_VALUE_RULE = "the value of X-Tenant must be printable ASCII"
TOKEN_RULE = "auth.token must be printable ASCII without spaces or line breaks"
USERNAME_RULE = "auth.username must not contain line breaks, NUL or other control characters"
PASSWORD_RULE = "auth.password must not contain line breaks, NUL or other control characters"


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


def test_unusual_but_valid_credentials_pass() -> None:
    auth = {"type": "basic", "username": "jos\u00e9", "password": "p \u00e4ss word"}
    assert isinstance(_Holder.model_validate({"auth": auth}).auth, BasicAuth)  # base64: any printable text works
    bearer = _Holder.model_validate({"auth": {"type": "bearer", "token": "glsa_AbC.-~+/=="}}).auth
    assert isinstance(bearer, BearerAuth)


@pytest.mark.parametrize(
    ("auth", "expected"),
    [
        ({"type": "bearer", "token": ""}, "auth.token must not be empty"),
        ({"type": "basic", "username": "u", "password": ""}, "auth.password must not be empty"),
        ({"type": "basic", "username": "a:b", "password": "p"}, "auth.username must not contain ':'"),
        ({"type": "bearer", "token": SECRET, "extra": SECRET}, "Extra inputs are not permitted"),
        # The token goes into the Authorization header as it is: h11 refuses these and its error names the value.
        ({"type": "bearer", "token": f"{SECRET}\n"}, TOKEN_RULE),
        ({"type": "bearer", "token": f"{SECRET}\r\nX-Evil: 1"}, TOKEN_RULE),
        ({"type": "bearer", "token": f"{SECRET}\x00"}, TOKEN_RULE),
        ({"type": "bearer", "token": f"{SECRET} x"}, TOKEN_RULE),
        ({"type": "bearer", "token": f"{SECRET}\u00e9"}, TOKEN_RULE),
        # Basic credentials are base64-encoded, so they cannot break the header; a stray "\n" (a ${VAR} from a
        # secret) would only send wrong credentials, so it is refused at load time instead of failing as HTTP 401.
        ({"type": "basic", "username": "u\n", "password": "p"}, USERNAME_RULE),
        ({"type": "basic", "username": "u\x00", "password": "p"}, USERNAME_RULE),
        ({"type": "basic", "username": "u", "password": f"{SECRET}\n"}, PASSWORD_RULE),
        ({"type": "basic", "username": "u", "password": f"{SECRET}\r"}, PASSWORD_RULE),
        ({"type": "basic", "username": "u", "password": f"{SECRET}\x00"}, PASSWORD_RULE),
        ({"type": "basic", "username": "u", "password": f"{SECRET}\x1b"}, PASSWORD_RULE),
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
        ({"X-Tenant\n": SECRET}, "entry 0 is not a valid header name"),
        ({"X-A": "a", "X-Tenant\r\n": SECRET}, "entry 1 is not a valid header name"),
        ({"X-Tenant": f"a\r\nX-Injected: {SECRET}"}, HEADER_VALUE_RULE),
        ({"X-Tenant": f"{SECRET}\n"}, HEADER_VALUE_RULE),
        ({"X-Tenant": f"{SECRET}\x00"}, HEADER_VALUE_RULE),
        ({"X-Tenant": f"{SECRET} "}, HEADER_VALUE_RULE),
        ({"X-Tenant": f"\t{SECRET}"}, HEADER_VALUE_RULE),
        ({"X-Tenant": f"{SECRET}\x0b"}, HEADER_VALUE_RULE),
        ({"X-Tenant": f"{SECRET}\x7f"}, HEADER_VALUE_RULE),
        ({"X-Tenant": f"{SECRET}\u00e9"}, HEADER_VALUE_RULE),
    ],
)
def test_header_rules_never_echo_values(headers: dict[str, str], expected: str) -> None:
    with pytest.raises(ValueError, match=expected) as caught:
        check_headers({name: SecretStr(value) for name, value in headers.items()})
    assert SECRET not in str(caught.value)


def test_valid_headers_pass() -> None:
    headers = {
        "X-Scope-OrgID": SecretStr("team-a"),
        "X-Api-Key": SecretStr(SECRET),
        "X-Words": SecretStr("a b\tc"),
        "X-Empty": SecretStr(""),
    }
    assert check_headers(headers) == headers


class _DemoConnection(HttpConnection):
    KIND: ClassVar[str] = "demo"

    kind: Literal["demo"]


def test_http_connection_base_shares_fields_and_checks() -> None:
    connection = _DemoConnection.model_validate(
        {"kind": "demo", "url": "http://demo:80", "headers": {"X-A": 1}, "timeout": "1m"}
    )
    assert (connection.mode, connection.auth.type, connection.tls.verify) == ("read", "none", True)
    assert connection.headers["X-A"].get_secret_value() == "1"
    assert connection.timeout == timedelta(minutes=1)
    with pytest.raises(ValidationError, match="demo connections are read-only: omit mode or set it to read"):
        _DemoConnection.model_validate({"kind": "demo", "url": "http://demo:80", "mode": "write"})
    with pytest.raises(ValidationError, match="timeout must be between 1s and 10m"):
        _DemoConnection.model_validate({"kind": "demo", "url": "http://demo:80", "timeout": "11m"})
