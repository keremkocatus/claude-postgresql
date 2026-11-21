from __future__ import annotations

import base64
import hashlib

import pytest

from ratatoskr.auth.crypto import (
    DecryptionError,
    Keyring,
    Sealer,
    Signer,
    derive_key,
    hash_token,
    new_token,
    pkce_challenge,
)


def test_new_token_is_32_random_bytes() -> None:
    tokens = {new_token() for _ in range(50)}
    assert len(tokens) == 50
    assert all(len(base64.urlsafe_b64decode(t + "=")) == 32 for t in tokens)


def test_hash_token_is_sha256_hex() -> None:
    assert hash_token("abc") == hashlib.sha256(b"abc").hexdigest()


def test_pkce_challenge_matches_rfc7636_example() -> None:
    assert (
        pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    )


def test_derived_keys_differ_per_purpose_and_secret() -> None:
    assert derive_key("s" * 32, "a") != derive_key("s" * 32, "b")
    assert derive_key("s" * 32, "a") != derive_key("t" * 32, "a")
    assert len(derive_key("s" * 32, "a")) == 32


def test_sealer_roundtrip_uses_fresh_nonce() -> None:
    sealer = Sealer(derive_key("s" * 32, "x"))
    one, two = sealer.seal("upstream-refresh", aad="alice"), sealer.seal("upstream-refresh", aad="alice")
    assert one != two
    assert b"upstream-refresh" not in one
    assert sealer.open(one, aad="alice") == "upstream-refresh"


def test_sealer_rejects_wrong_aad_wrong_key_and_tampering() -> None:
    sealer = Sealer(derive_key("s" * 32, "x"))
    blob = sealer.seal("secret", aad="alice")
    with pytest.raises(DecryptionError):
        sealer.open(blob, aad="bob")
    with pytest.raises(DecryptionError):
        Sealer(derive_key("other-secret" * 3, "x")).open(blob, aad="alice")
    tampered = blob[:-1] + bytes([blob[-1] ^ 1])
    with pytest.raises(DecryptionError):
        sealer.open(tampered, aad="alice")
    with pytest.raises(DecryptionError):
        sealer.open(b"short", aad="alice")


def test_signer_verifies_only_its_own_signatures() -> None:
    signer = Signer(derive_key("s" * 32, "csrf"))
    sig = signer.sign("message")
    assert signer.verify("message", sig)
    assert not signer.verify("other", sig)
    assert not Signer(derive_key("s" * 32, "flow")).verify("message", sig)


@pytest.mark.parametrize(
    "signature",
    ["", "é" * 43, "\udcff", "x", "A" * 10_000, "not base64!!", "\x00" * 43],
    ids=["empty", "non-ascii", "lone-surrogate", "short", "long", "garbage", "nul"],
)
def test_signer_verify_returns_false_for_attacker_supplied_signatures(signature: str) -> None:
    assert Signer(derive_key("s" * 32, "csrf")).verify("message", signature) is False


@pytest.mark.parametrize("signature", [None, b"bytes", 123], ids=["none", "bytes", "int"])
def test_signer_verify_returns_false_for_non_string_signatures(signature: object) -> None:
    assert Signer(derive_key("s" * 32, "csrf")).verify("message", signature) is False  # type: ignore[arg-type]


def test_signer_handles_messages_with_lone_surrogates() -> None:
    signer = Signer(derive_key("s" * 32, "csrf"))
    sig = signer.sign("req-\udcff")
    assert signer.verify("req-\udcff", sig)
    assert not signer.verify("req-\udcfe", sig)


@pytest.mark.parametrize("blob", [b"", b"\x00" * 12, b"\xff" * 13, b"\x00" * 28], ids=["empty", "nonce", "13", "28"])
def test_sealer_open_rejects_malformed_bytes(blob: bytes) -> None:
    with pytest.raises(DecryptionError):
        Sealer(derive_key("s" * 32, "x")).open(blob, aad="alice")


@pytest.mark.parametrize("blob", [None, "a" * 40, 123, bytearray(b"\x00" * 40)], ids=["none", "str", "int", "ba"])
def test_sealer_open_rejects_non_bytes_with_decryption_error(blob: object) -> None:
    with pytest.raises(DecryptionError):
        Sealer(derive_key("s" * 32, "x")).open(blob, aad="alice")  # type: ignore[arg-type]


def test_sealer_open_with_unencodable_aad_raises_decryption_error() -> None:
    sealer = Sealer(derive_key("s" * 32, "x"))
    blob = sealer.seal("secret", aad="alice")
    with pytest.raises(DecryptionError):
        sealer.open(blob, aad="\udcff")


def test_decryption_error_messages_carry_no_data() -> None:
    sealer = Sealer(derive_key("s" * 32, "x"))
    blob = sealer.seal("secret", aad="alice")
    for bad in (blob[:5], blob[:-1] + b"\x00", "secret-as-str"):
        with pytest.raises(DecryptionError) as info:
            sealer.open(bad, aad="alice")  # type: ignore[arg-type]
        assert "secret" not in str(info.value)
        assert "alice" not in str(info.value)


def test_hash_token_never_raises_on_lone_surrogates() -> None:
    assert len(hash_token("\udcff")) == 64
    assert hash_token("\udcff") != hash_token("\udcfe")


def test_keyring_keys_are_independent() -> None:
    ring = Keyring("s" * 32)
    blob = ring.upstream.seal("x", aad="a")
    with pytest.raises(DecryptionError):
        ring.client_secrets.open(blob, aad="a")
    assert not ring.oidc_flow.verify("m", ring.csrf.sign("m"))
