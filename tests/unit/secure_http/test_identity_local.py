from __future__ import annotations

import io

import pytest
from argon2 import PasswordHasher, extract_parameters
from argon2.low_level import Type
from pydantic import SecretStr

from ratatoskr.auth.identity.local import LocalIdentityProvider, hash_password, normalize_username
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


# ── hash-password command ──


class FakeTty(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_hash_password_command_reads_stdin() -> None:
    out, err = io.StringIO(), io.StringIO()
    assert run_hash_password(io.StringIO("s3cret\n"), out, err) == 0
    printed = out.getvalue().strip()
    assert printed.startswith("$argon2id$") and "s3cret" not in printed
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


def test_hash_password_command_output_verifies() -> None:
    out = io.StringIO()
    assert run_hash_password(io.StringIO("s3cret\r\n"), out, io.StringIO()) == 0
    assert PasswordHasher().verify(out.getvalue().strip(), "s3cret")
