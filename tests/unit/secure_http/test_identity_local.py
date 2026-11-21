from __future__ import annotations

import asyncio
import io
import re
import threading
import time

import pytest
from argon2 import PasswordHasher, extract_parameters
from argon2.exceptions import HashingError
from argon2.low_level import Type
from pydantic import SecretStr

from ratatoskr.auth.identity.local import (
    LocalIdentityProvider,
    hash_password,
    normalize_username,
    password_hash_problem,
    password_hash_weakness,
)
from ratatoskr.auth.password_cli import run_hash_password
from ratatoskr.config.models import LocalUser

PASSWORD = "correct horse battery staple"


def provider(password_hash: str) -> LocalIdentityProvider:
    return LocalIdentityProvider(
        [LocalUser(username="kerem", password_hash=SecretStr(password_hash), groups=["admins", "devops"])]
    )


def test_hash_password_produces_argon2id() -> None:
    assert hash_password("pw").startswith("$argon2id$")


async def test_correct_password_returns_principal(password_hash: str) -> None:
    principal = await provider(password_hash).verify_password("kerem", PASSWORD)
    assert principal is not None
    assert principal.subject == "kerem"
    assert principal.groups == frozenset({"admins", "devops"})
    assert principal.auth_source == "local"


async def test_wrong_password_and_unknown_user_return_none(password_hash: str) -> None:
    local = provider(password_hash)
    assert await local.verify_password("kerem", "wrong") is None
    assert await local.verify_password("nobody", PASSWORD) is None


async def test_unknown_user_still_runs_argon2(password_hash: str, monkeypatch: pytest.MonkeyPatch) -> None:
    import ratatoskr.auth.identity.local as local_module

    calls: list[str] = []
    real = local_module._verify

    def spy(stored: str, password: str) -> bool:
        calls.append(stored)
        return real(stored, password)

    monkeypatch.setattr(local_module, "_verify", spy)
    await provider(password_hash).verify_password("nobody", "x")
    assert len(calls) == 1 and calls[0].startswith("$argon2id$")


@pytest.mark.parametrize(
    "stored", ["plaintext-password", "x", "$argon2id$garbage", PasswordHasher(type=Type.I).hash("pw"), ""]
)
def test_non_argon2id_hash_is_rejected_without_echoing_it(stored: str) -> None:
    with pytest.raises(ValueError, match="argon2id") as info:
        provider(stored)
    assert "kerem" in str(info.value)
    if stored:
        assert stored not in str(info.value)


def test_lookup_reflects_configuration(password_hash: str) -> None:
    local = provider(password_hash)
    found = local.lookup("kerem")
    assert found is not None and found.groups == frozenset({"admins", "devops"})
    assert local.lookup("removed-user") is None


# ── hardening beyond the plan's tests ──


@pytest.mark.parametrize(
    "stored",
    [
        "$argon2id$v=19$m=65536,t=3,p=4$!!!$!!!",  # parameters parse, salt and hash are not base64
        "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$",  # no hash part
        "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaA$extra",
        PasswordHasher(type=Type.D).hash("pw"),
    ],
)
def test_malformed_or_wrong_type_phc_strings_are_rejected(stored: str) -> None:
    with pytest.raises(ValueError, match="argon2id") as info:
        provider(stored)
    assert stored not in str(info.value)


async def test_password_with_lone_surrogate_is_verified_not_raised(password_hash: str) -> None:
    """Form input can carry lone surrogates; argon2 would raise UnicodeEncodeError on them."""
    assert await provider(password_hash).verify_password("kerem", "bad\udc80") is None
    surrogate_hash = hash_password("pw\udc80")
    assert await provider(surrogate_hash).verify_password("kerem", "pw\udc80") is not None


def test_username_normalisation_rule() -> None:
    """The rule the login route also uses for its rate-limit key (``login:user:<normalized>``)."""
    assert normalize_username("  Kerem ") == "kerem"
    assert normalize_username("STRASSE") == normalize_username("straße")
    assert normalize_username("ｋｅｒｅｍ") == "kerem"  # fullwidth
    assert normalize_username("Ayşe") == normalize_username("Ayşe")  # NFD vs NFC


async def test_fullwidth_and_decomposed_spellings_sign_in_as_the_configured_user(password_hash: str) -> None:
    local = LocalIdentityProvider([LocalUser(username="Ayşe", password_hash=SecretStr(password_hash))])
    for typed in ("ayşe", "ＡＹŞＥ"):
        principal = await local.verify_password(typed, PASSWORD)
        assert principal is not None and principal.subject == "Ayşe"


def test_usernames_that_collide_after_nfkc_are_rejected(password_hash: str) -> None:
    users = [
        LocalUser(username="kerem", password_hash=SecretStr(password_hash)),
        LocalUser(username="ｋｅｒｅｍ", password_hash=SecretStr(password_hash)),
    ]
    with pytest.raises(ValueError, match="more than once"):
        LocalIdentityProvider(users)


async def test_username_matching_is_case_insensitive_but_subject_is_configured_name(password_hash: str) -> None:
    local = LocalIdentityProvider([LocalUser(username="Kerem", password_hash=SecretStr(password_hash))])
    principal = await local.verify_password(" KEREM ", PASSWORD)
    assert principal is not None and principal.subject == "Kerem"
    found = local.lookup("Kerem")
    assert found is not None and found.subject == "Kerem"


def test_usernames_that_collide_after_normalisation_are_rejected(password_hash: str) -> None:
    users = [
        LocalUser(username="kerem", password_hash=SecretStr(password_hash)),
        LocalUser(username="Kerem", password_hash=SecretStr(password_hash)),
    ]
    with pytest.raises(ValueError, match="more than once") as info:
        LocalIdentityProvider(users)
    assert password_hash not in str(info.value)


async def test_unknown_user_dummy_hash_uses_the_configured_cost(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unknown users must cost the same as known ones even when the operator chose non-default parameters."""
    import ratatoskr.auth.identity.local as local_module

    cheap = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash("pw")
    calls: list[str] = []
    real = local_module._verify

    def spy(stored: str, password: str) -> bool:
        calls.append(stored)
        return real(stored, password)

    monkeypatch.setattr(local_module, "_verify", spy)
    await provider(cheap).verify_password("nobody", "x")
    dummy = extract_parameters(calls[0])
    configured = extract_parameters(cheap)
    assert (dummy.time_cost, dummy.memory_cost, dummy.parallelism) == (1, 8192, 1)
    assert dummy.type is configured.type is Type.ID


async def test_failed_verification_does_not_leak_password_into_logs(
    password_hash: str, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("DEBUG")
    await provider(password_hash).verify_password("kerem", "hunter2-secret")
    await provider(password_hash).verify_password("nobody", "hunter2-secret")
    assert "hunter2-secret" not in caplog.text


def _with_parameters(password_hash: str, parameters: str) -> str:
    """Same salt and hash, other ``m=…,t=…,p=…`` (format checks only; nothing is hashed with them)."""
    return re.sub(r"m=\d+,t=\d+,p=\d+", parameters, password_hash, count=1)


@pytest.mark.parametrize(
    "parameters",
    [
        "m=65536,t=0,p=4",
        "m=65536,t=11,p=4",
        "m=65536,t=3,p=0",
        "m=65536,t=3,p=17",
        "m=31,t=3,p=4",  # below 8 * p
        "m=262145,t=3,p=1",
    ],
)
def test_out_of_bounds_argon2_parameters_are_rejected(password_hash: str, parameters: str) -> None:
    stored = _with_parameters(password_hash, parameters)
    with pytest.raises(ValueError, match="argon2id") as info:
        provider(stored)
    assert stored not in str(info.value) and parameters not in str(info.value)
    user = LocalUser(username="kerem", password_hash=SecretStr(stored))
    assert password_hash_problem(user) is not None


def test_upper_bounds_are_inclusive(password_hash: str) -> None:
    user = LocalUser(username="kerem", password_hash=SecretStr(_with_parameters(password_hash, "m=262144,t=10,p=16")))
    assert password_hash_problem(user) is None


def test_weak_but_valid_parameters_are_reported_not_refused(caplog: pytest.LogCaptureFixture) -> None:
    weak = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash("pw")
    user = LocalUser(username="kerem", password_hash=SecretStr(weak))
    assert password_hash_problem(user) is None
    weakness = password_hash_weakness(user)
    assert weakness is not None and "kerem" in weakness and "OWASP" in weakness and weak not in weakness
    caplog.set_level("WARNING")
    provider(weak)
    # The provider does not log it: the preconditions collect it and serve / check-config report it once.
    assert caplog.text == ""


def test_default_parameters_are_not_weak(password_hash: str) -> None:
    assert password_hash_weakness(LocalUser(username="kerem", password_hash=SecretStr(password_hash))) is None


@pytest.mark.parametrize(
    "parameters",
    [
        # The OWASP password storage cheat sheet's equivalent argon2id settings (all p=1) ...
        "m=47104,t=1,p=1",
        "m=19456,t=2,p=1",
        "m=12288,t=3,p=1",
        "m=9216,t=4,p=1",
        "m=7168,t=5,p=1",
        # ... and anything at least as expensive in both memory and iterations.
        "m=65536,t=1,p=4",
        "m=12288,t=4,p=2",
    ],
)
def test_owasp_equivalent_parameters_are_not_weak(password_hash: str, parameters: str) -> None:
    user = LocalUser(username="kerem", password_hash=SecretStr(_with_parameters(password_hash, parameters)))
    assert password_hash_weakness(user) is None


@pytest.mark.parametrize("parameters", ["m=46080,t=1,p=1", "m=19456,t=1,p=1", "m=9216,t=3,p=1", "m=7168,t=4,p=1"])
def test_parameters_below_every_owasp_option_are_weak(password_hash: str, parameters: str) -> None:
    stored = _with_parameters(password_hash, parameters)
    message = password_hash_weakness(LocalUser(username="kerem", password_hash=SecretStr(stored)))
    assert message is not None and "OWASP" in message and "kerem" in message
    assert stored not in message


def test_users_with_different_argon2_parameters_are_refused(password_hash: str) -> None:
    """Different costs would let response time tell configured usernames apart from unknown ones."""
    cheap = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1).hash("pw")
    users = [
        LocalUser(username="kerem", password_hash=SecretStr(password_hash)),
        LocalUser(username="ayse", password_hash=SecretStr(cheap)),
    ]
    with pytest.raises(ValueError, match="same argon2 parameters") as info:
        LocalIdentityProvider(users)
    assert "kerem" in str(info.value) and "ayse" in str(info.value)
    assert password_hash not in str(info.value) and cheap not in str(info.value)


def test_dummy_hash_failure_becomes_the_config_error(password_hash: str, monkeypatch: pytest.MonkeyPatch) -> None:
    import ratatoskr.auth.identity.local as local_module

    def broken(*args: object, **kwargs: object) -> str:
        raise HashingError("boom")

    monkeypatch.setattr(local_module.PasswordHasher, "hash", broken)
    with pytest.raises(ValueError, match="argon2id") as info:
        provider(password_hash)
    assert "kerem" in str(info.value)


async def test_concurrent_verifications_are_bounded(password_hash: str, monkeypatch: pytest.MonkeyPatch) -> None:
    import ratatoskr.auth.identity.local as local_module

    lock = threading.Lock()
    running = 0
    peak = 0

    def slow(stored: str, password: str) -> bool:
        nonlocal running, peak
        with lock:
            running += 1
            peak = max(peak, running)
        time.sleep(0.05)
        with lock:
            running -= 1
        return False

    monkeypatch.setattr(local_module, "_verify", slow)
    local = provider(password_hash)
    await asyncio.gather(*(local.verify_password("kerem", "x") for _ in range(12)))
    assert 1 <= peak <= local_module.MAX_CONCURRENT_VERIFICATIONS


# ── hash-password command ──


class FakeTty(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_hash_password_command_reads_stdin() -> None:
    out, err = io.StringIO(), io.StringIO()
    assert run_hash_password(io.StringIO("s3cret-long-enough\n"), out, err) == 0
    printed = out.getvalue().strip()
    assert printed.startswith("$argon2id$") and "s3cret-long-enough" not in printed
    assert err.getvalue() == ""


def test_hash_password_command_prompts_twice_on_tty() -> None:
    answers = iter(["pw-one", "pw-one"])
    out, err = io.StringIO(), io.StringIO()
    assert run_hash_password(FakeTty(), out, err, prompt=lambda _: next(answers)) == 0
    assert out.getvalue().startswith("$argon2id$")


def test_hash_password_command_rejects_mismatch_and_empty() -> None:
    answers = iter(["a", "b"])
    err = io.StringIO()
    assert run_hash_password(FakeTty(), io.StringIO(), err, prompt=lambda _: next(answers)) == 1
    assert "do not match" in err.getvalue()
    err = io.StringIO()
    assert run_hash_password(io.StringIO("\n"), io.StringIO(), err) == 1
    assert "empty" in err.getvalue()


def test_hash_password_command_reads_piped_bytes_as_utf8_without_bom() -> None:
    """A pipe on Windows has a legacy text encoding; the bytes are UTF-8 (possibly with a BOM) all the same."""
    piped = io.TextIOWrapper(io.BytesIO("\ufeffpässwörd\r\n".encode()), encoding="cp1252")
    out = io.StringIO()
    assert run_hash_password(piped, out, io.StringIO()) == 0
    assert PasswordHasher().verify(out.getvalue().strip(), "pässwörd")


def test_hash_password_help_points_powershell_users_to_the_prompt() -> None:
    from ratatoskr.auth.password_cli import DESCRIPTION

    assert "PowerShell 5.1" in DESCRIPTION and "prompt" in DESCRIPTION


def test_hash_password_command_rejects_undecodable_input() -> None:
    piped = io.TextIOWrapper(io.BytesIO(b"\xff\xfe\xfa\n"), encoding="cp1252")
    err = io.StringIO()
    assert run_hash_password(piped, io.StringIO(), err) == 1
    assert "UTF-8" in err.getvalue()


def test_hash_password_command_output_verifies() -> None:
    out = io.StringIO()
    assert run_hash_password(io.StringIO("s3cret\r\n"), out, io.StringIO()) == 0
    assert PasswordHasher().verify(out.getvalue().strip(), "s3cret")
