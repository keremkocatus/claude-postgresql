"""Local users from configuration, verified with argon2id (spec §5.1 ``local``).

Username rule: :func:`normalize_username` (surrounding whitespace stripped, then ``str.casefold``) is used both to
match a typed username against the configured ones and, by the login route, for the per-user rate-limit key, so
every spelling that can sign in as a user shares that user's lockout. The principal's subject is always the
username exactly as configured. Two configured usernames that normalise to the same value are a configuration error.
"""

from __future__ import annotations

import asyncio
import re
import secrets

from argon2 import PasswordHasher, extract_parameters
from argon2.exceptions import InvalidHashError, VerificationError
from argon2.low_level import Type

from ratatoskr.auth.principal import Principal
from ratatoskr.config.models import LocalUser

_HASHER = PasswordHasher()
# PHC string of argon2id v1.3: parameters, then unpadded standard-base64 salt (>= 8 bytes) and hash (>= 16 bytes).
_PHC_ARGON2ID = re.compile(r"\$argon2id\$v=19\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]{11,}\$[A-Za-z0-9+/]{22,}")


def _utf8(password: str) -> bytes:
    """UTF-8 that never raises: a lone surrogate from form input is hashed, not turned into an exception."""
    return password.encode("utf-8", "surrogatepass")


def normalize_username(username: str) -> str:
    """The one username normalisation: strip surrounding whitespace, then casefold."""
    return username.strip().casefold()


def hash_password(password: str) -> str:
    """argon2id hash in PHC string format, as stored in ``auth.local.users[].password_hash``."""
    return _HASHER.hash(_utf8(password))


def password_hash_problem(user: LocalUser) -> str | None:
    """Why ``user.password_hash`` is not a usable argon2id hash, or ``None``. The message never contains the value."""
    stored = user.password_hash.get_secret_value()
    try:
        parameters = extract_parameters(stored)
    except InvalidHashError:
        parameters = None
    if parameters is None or parameters.type is not Type.ID or _PHC_ARGON2ID.fullmatch(stored) is None:
        return (
            f"auth.local user {user.username!r}: password_hash must be an argon2id hash"
            " (generate one with `ratatoskr hash-password`)"
        )
    return None


def _verify(password_hash: str, password: str) -> bool:
    try:
        return _HASHER.verify(password_hash, _utf8(password))
    except (VerificationError, InvalidHashError):
        return False


class LocalIdentityProvider:
    def __init__(self, users: list[LocalUser]) -> None:
        self._users: dict[str, LocalUser] = {}
        for user in users:
            problem = password_hash_problem(user)
            if problem is not None:
                raise ValueError(problem)
            key = normalize_username(user.username)
            if not key:
                raise ValueError("auth.local: a username must not be empty")
            if key in self._users:
                raise ValueError(f"auth.local user {user.username!r} is configured more than once (names ignore case)")
            self._users[key] = user
        # Unknown usernames are checked against this hash so they cost the same time as a wrong password. It uses the
        # parameters of the first configured hash, so the cost matches even when they differ from the defaults.
        dummy_hasher = _HASHER
        if users:
            dummy_hasher = PasswordHasher.from_parameters(extract_parameters(users[0].password_hash.get_secret_value()))
        self._dummy_hash = dummy_hasher.hash(secrets.token_urlsafe(32))

    @staticmethod
    def _principal(user: LocalUser) -> Principal:
        return Principal(
            subject=user.username,
            display_name=user.username,
            groups=frozenset(user.groups),
            auth_source="local",
        )

    def lookup(self, subject: str) -> Principal | None:
        user = self._users.get(normalize_username(subject))
        return None if user is None else self._principal(user)

    async def verify_password(self, username: str, password: str) -> Principal | None:
        user = self._users.get(normalize_username(username))
        stored = user.password_hash.get_secret_value() if user is not None else self._dummy_hash
        ok = await asyncio.to_thread(_verify, stored, password)
        if user is None or not ok:
            return None
        return self._principal(user)
