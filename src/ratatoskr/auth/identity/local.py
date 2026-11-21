"""Local users from configuration, verified with argon2id (spec §5.1 ``local``).

Username rule: :func:`normalize_username` (surrounding whitespace stripped, Unicode NFKC, then ``str.casefold``) is
used both to match a typed username against the configured ones and, by the login route, for the per-user rate-limit
key, so every spelling that can sign in as a user shares that user's lockout. The principal's subject is always the
username exactly as configured. Two configured usernames that normalise to the same value are a configuration error.

Timing: an unknown username is verified against a dummy hash with the same argon2 parameters as the configured
users, and all configured users must share one parameter set, so response time does not reveal which names exist.
Verifications run on a small dedicated thread pool, so a login flood cannot occupy the event loop's default executor.
"""

from __future__ import annotations

import asyncio
import logging
import re
import secrets
import unicodedata
from concurrent.futures import ThreadPoolExecutor

from argon2 import Parameters, PasswordHasher, extract_parameters
from argon2.exceptions import Argon2Error, InvalidHashError, VerificationError
from argon2.low_level import Type

from ratatoskr.auth.principal import Principal
from ratatoskr.config.models import LocalUser

logger = logging.getLogger(__name__)

_HASHER = PasswordHasher()
# PHC string of argon2id v1.3: parameters, then unpadded standard-base64 salt (>= 8 bytes) and hash (>= 16 bytes).
_PHC_ARGON2ID = re.compile(r"\$argon2id\$v=19\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]{11,}\$[A-Za-z0-9+/]{22,}")
# Accepted cost range: refuses hashes that would be trivially cheap or would let one login take seconds or GBs.
MAX_TIME_COST = 10
MAX_PARALLELISM = 16
MAX_MEMORY_COST_KIB = 262144
# OWASP password storage cheat sheet minimum for argon2id; weaker hashes are accepted with a warning.
OWASP_MIN_MEMORY_COST_KIB = 19456
OWASP_MIN_TIME_COST = 2
MAX_CONCURRENT_VERIFICATIONS = 4
_VERIFY_POOL = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_VERIFICATIONS, thread_name_prefix="argon2")


def _utf8(password: str) -> bytes:
    """UTF-8 that never raises: a lone surrogate from form input is hashed, not turned into an exception."""
    return password.encode("utf-8", "surrogatepass")


def normalize_username(username: str) -> str:
    """The one username normalisation: strip surrounding whitespace, NFKC, then casefold."""
    return unicodedata.normalize("NFKC", username.strip()).casefold()


def hash_password(password: str) -> str:
    """argon2id hash in PHC string format, as stored in ``auth.local.users[].password_hash``."""
    return _HASHER.hash(_utf8(password))


def _format_error(user: LocalUser) -> str:
    return (
        f"auth.local user {user.username!r}: password_hash must be an argon2id hash"
        " (generate one with `ratatoskr hash-password`)"
    )


def _parameters(user: LocalUser) -> Parameters | None:
    stored = user.password_hash.get_secret_value()
    try:
        parameters = extract_parameters(stored)
    except InvalidHashError:
        return None
    if parameters.type is not Type.ID or _PHC_ARGON2ID.fullmatch(stored) is None:
        return None
    return parameters


def password_hash_problem(user: LocalUser) -> str | None:
    """Why ``user.password_hash`` is not a usable argon2id hash, or ``None``. The message never contains the value."""
    parameters = _parameters(user)
    if parameters is None:
        return _format_error(user)
    t, p, m = parameters.time_cost, parameters.parallelism, parameters.memory_cost
    if not (1 <= t <= MAX_TIME_COST and 1 <= p <= MAX_PARALLELISM and 8 * p <= m <= MAX_MEMORY_COST_KIB):
        return (
            f"auth.local user {user.username!r}: password_hash must be an argon2id hash with 1-{MAX_TIME_COST}"
            f" iterations, 1-{MAX_PARALLELISM} lanes and at most {MAX_MEMORY_COST_KIB} KiB memory"
            " (generate one with `ratatoskr hash-password`)"
        )
    return None


def password_hash_weakness(user: LocalUser) -> str | None:
    """A warning when a usable hash is below the OWASP minimum (m >= 19456 KiB, t >= 2), else ``None``."""
    parameters = _parameters(user)
    if parameters is None:
        return None
    if parameters.memory_cost < OWASP_MIN_MEMORY_COST_KIB or parameters.time_cost < OWASP_MIN_TIME_COST:
        return (
            f"auth.local user {user.username!r}: password_hash is weaker than the OWASP minimum"
            f" (m={OWASP_MIN_MEMORY_COST_KIB} KiB, t={OWASP_MIN_TIME_COST});"
            " regenerate it with `ratatoskr hash-password`"
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
            weakness = password_hash_weakness(user)
            if weakness is not None:
                logger.warning(weakness)
        costs = {user.username: _cost(user) for user in users}
        if len(set(costs.values())) > 1:
            names = ", ".join(repr(name) for name in costs)
            raise ValueError(
                f"auth.local users {names} must all use the same argon2 parameters (m, t, p); regenerate the hashes"
                " with `ratatoskr hash-password`"
            )
        # Unknown usernames are checked against this hash so they cost the same time as a wrong password.
        try:
            dummy_hasher = _HASHER
            if users:
                dummy_hasher = PasswordHasher.from_parameters(
                    extract_parameters(users[0].password_hash.get_secret_value())
                )
            self._dummy_hash = dummy_hasher.hash(secrets.token_urlsafe(32))
        except (Argon2Error, ValueError):
            raise ValueError(_format_error(users[0]) if users else "argon2 is not usable") from None

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
        ok = await asyncio.get_running_loop().run_in_executor(_VERIFY_POOL, _verify, stored, password)
        if user is None or not ok:
            return None
        return self._principal(user)


def _cost(user: LocalUser) -> tuple[int, int, int]:
    parameters = extract_parameters(user.password_hash.get_secret_value())
    return parameters.memory_cost, parameters.time_cost, parameters.parallelism
