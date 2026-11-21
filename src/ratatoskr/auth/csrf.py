"""Login-form CSRF protection: a random cookie plus a form token that signs (pending request id, cookie, time).

The cookie is ``HttpOnly`` and ``SameSite=Strict`` (``__Host-`` prefixed and ``Secure`` unless ``--insecure-dev``);
an attacker can neither read it nor make the browser send it cross-site, and the form token cannot be forged without
``server.secret_key``. The signed message is a JSON array, so the fields cannot be shifted into one another, and it
carries the issue time: a form token is refused once it is older than the cookie's lifetime.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable

from starlette.responses import Response

from ratatoskr.auth.crypto import Signer, new_token

CSRF_COOKIE_MAX_AGE = 600
# Tolerated backwards step of the wall clock between issuing and verifying (e.g. an NTP correction).
_CLOCK_SKEW = 60
_MAX_TIMESTAMP_DIGITS = 12
_PURPOSE = "ratatoskr-login-csrf/v1"


class CsrfProtector:
    def __init__(self, signer: Signer, *, secure: bool, clock: Callable[[], float] = time.time) -> None:
        self._signer = signer
        self._secure = secure
        self._clock = clock
        self.cookie_name = "__Host-ratatoskr-csrf" if secure else "ratatoskr-csrf"

    @staticmethod
    def _message(request_id: str, cookie_value: str, issued_at: int) -> str:
        return json.dumps([_PURPOSE, request_id, cookie_value, issued_at])

    def issue(self, request_id: str) -> tuple[str, str]:
        """Return ``(cookie_value, form_token)`` for a fresh login form; the form token is ``<issued_at>.<mac>``."""
        cookie_value = new_token()
        issued_at = int(self._clock())
        return cookie_value, f"{issued_at}.{self._signer.sign(self._message(request_id, cookie_value, issued_at))}"

    def verify(self, request_id: str, cookie_value: str | None, form_token: str | None) -> bool:
        """``True`` only for an unexpired form token issued for this request id and cookie; never raises."""
        if not isinstance(request_id, str) or not isinstance(cookie_value, str) or not isinstance(form_token, str):
            return False
        if not request_id or not cookie_value or not form_token:
            return False
        stamp, separator, signature = form_token.partition(".")
        if not separator or not stamp.isascii() or not stamp.isdigit() or len(stamp) > _MAX_TIMESTAMP_DIGITS:
            return False
        issued_at = int(stamp)
        age = self._clock() - issued_at
        if not -_CLOCK_SKEW <= age <= CSRF_COOKIE_MAX_AGE:
            return False
        return self._signer.verify(self._message(request_id, cookie_value, issued_at), signature)

    def set_cookie(self, response: Response, cookie_value: str) -> None:
        response.set_cookie(
            self.cookie_name,
            cookie_value,
            max_age=CSRF_COOKIE_MAX_AGE,
            path="/",
            secure=self._secure,
            httponly=True,
            samesite="strict",
        )

    def clear_cookie(self, response: Response) -> None:
        response.delete_cookie(self.cookie_name, path="/", secure=self._secure, httponly=True, samesite="strict")
