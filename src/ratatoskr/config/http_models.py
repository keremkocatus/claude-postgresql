"""Config models shared by the HTTP-based connection kinds (Prometheus, Loki).

No validation message echoes a value: credentials, header values and URLs may hold secrets.
"""

from __future__ import annotations

import re
from datetime import timedelta
from pathlib import Path
from typing import Annotated, Any, ClassVar, Literal, Self

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from ratatoskr.config.shared import duration_value

# Whole-value checks use fullmatch: `$` would also match before a final "\n" (a ${VAR} read from a secret).
# RFC 9110 token characters.
_HEADER_NAME_RE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
# What h11 sends (visible characters, spaces and tabs only between them) and httpx can encode (ASCII). h11 refuses
# anything else with an error that quotes the whole value, so it is refused here, before any request.
_HEADER_VALUE_RE = re.compile(r"[\x21-\x7e]+(?:[ \t]+[\x21-\x7e]+)*")
_TOKEN_RE = re.compile(r"[\x21-\x7e]+")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
# Set by Ratatoskr or httpx; a configured value would conflict with them or bypass `auth`.
RESERVED_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "host",
        "content-length",
        "content-type",
        "transfer-encoding",
        "connection",
    }
)


def _not_empty(value: SecretStr, label: str) -> SecretStr:
    if not value.get_secret_value():
        raise ValueError(f"{label} must not be empty")
    return value


def _no_control_characters(value: str, label: str) -> None:
    """Basic credentials are base64-encoded, so they cannot break a header; a stray line break would only send
    wrong credentials (HTTP 401 later), so it is refused at load time."""
    if _CONTROL_RE.search(value):
        raise ValueError(f"{label} must not contain line breaks, NUL or other control characters")


class NoAuth(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["none"]


class BasicAuth(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["basic"]
    username: str = Field(min_length=1)
    password: SecretStr

    @field_validator("username")
    @classmethod
    def _check_username(cls, value: str) -> str:
        if ":" in value:
            raise ValueError("auth.username must not contain ':'")
        _no_control_characters(value, "auth.username")
        return value

    @field_validator("password")
    @classmethod
    def _check_password(cls, value: SecretStr) -> SecretStr:
        _no_control_characters(value.get_secret_value(), "auth.password")
        return _not_empty(value, "auth.password")


class BearerAuth(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["bearer"]
    token: SecretStr

    @field_validator("token")
    @classmethod
    def _check_token(cls, value: SecretStr) -> SecretStr:
        token = _not_empty(value, "auth.token").get_secret_value()
        if not _TOKEN_RE.fullmatch(token):  # sent as it is in the Authorization header
            raise ValueError("auth.token must be printable ASCII without spaces or line breaks")
        return value


HttpAuth = Annotated[NoAuth | BasicAuth | BearerAuth, Field(discriminator="type")]


class HttpTlsSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verify: bool = True
    ca_file: Path | None = None  # trust only this CA (instead of the default bundle)

    @model_validator(mode="after")
    def _check_ca_file(self) -> Self:
        if self.ca_file is None:
            return self
        if not self.verify:
            raise ValueError("tls.ca_file has no effect with tls.verify: false; remove one of them")
        if not self.ca_file.is_file():
            raise ValueError(f"tls.ca_file does not exist: {self.ca_file}")
        return self


def check_base_url(url: AnyHttpUrl) -> AnyHttpUrl:
    """The API root: credentials belong under ``auth``, and a query string or fragment would be dropped."""
    if url.username is not None or url.password is not None:
        raise ValueError("url must not contain credentials; use auth (basic or bearer) instead")
    if url.query is not None or url.fragment is not None:
        raise ValueError("url must not contain a query string or fragment")
    return url


def stringify_header_values(value: Any) -> Any:
    """``mode="before"``: YAML reads ``X-Scope-OrgID: 42`` as a number; header values are text."""
    if not isinstance(value, dict):
        return value
    return {
        name: str(item) if isinstance(item, int | float) and not isinstance(item, bool) else item
        for name, item in value.items()
    }


def check_headers(headers: dict[str, SecretStr]) -> dict[str, SecretStr]:
    for index, (name, value) in enumerate(headers.items()):
        if not _HEADER_NAME_RE.fullmatch(name):
            raise ValueError(f"headers: entry {index} is not a valid header name")
        if name.lower() in RESERVED_HEADERS:
            raise ValueError(f"headers: {name} cannot be set here (credentials go under auth)")
        text = value.get_secret_value()
        if text and not _HEADER_VALUE_RE.fullmatch(text):
            raise ValueError(
                f"headers: the value of {name} must be printable ASCII (spaces only between words), without line "
                "breaks, NUL or control characters"
            )
    return headers


class HttpConnection(BaseModel):
    """What every HTTP connection kind shares; a subclass adds ``kind`` (a ``Literal``), ``limits`` and ``KIND``.

    HTTP kinds are read-only: every tool is a read of the server's HTTP API, so ``write`` would grant nothing.
    """

    model_config = ConfigDict(extra="forbid")

    KIND: ClassVar[str] = "http"

    description: str = ""
    mode: Literal["read"] = "read"
    url: AnyHttpUrl
    auth: HttpAuth = NoAuth(type="none")
    headers: dict[str, SecretStr] = {}
    tls: HttpTlsSettings = HttpTlsSettings()
    timeout: timedelta = timedelta(seconds=30)

    @field_validator("mode", mode="before")
    @classmethod
    def _check_mode(cls, value: Any) -> Any:
        if value != "read":
            raise ValueError(f"{cls.KIND} connections are read-only: omit mode or set it to read")
        return value

    @field_validator("url")
    @classmethod
    def _check_url(cls, value: AnyHttpUrl) -> AnyHttpUrl:
        return check_base_url(value)

    @field_validator("headers", mode="before")
    @classmethod
    def _stringify_headers(cls, value: Any) -> Any:
        return stringify_header_values(value)

    @field_validator("headers")
    @classmethod
    def _check_headers(cls, value: dict[str, SecretStr]) -> dict[str, SecretStr]:
        return check_headers(value)

    @field_validator("timeout", mode="before")
    @classmethod
    def _parse_timeout(cls, value: Any) -> timedelta:
        return duration_value(value)

    @field_validator("timeout")
    @classmethod
    def _check_timeout(cls, value: timedelta) -> timedelta:
        if not timedelta(seconds=1) <= value <= timedelta(minutes=10):
            raise ValueError("timeout must be between 1s and 10m")
        return value
