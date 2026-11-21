from __future__ import annotations

import base64
import hashlib
import hmac

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
    secret_key_problem,
)
from tests.unit.secure_http.conftest import SECRET_KEY

KAT_SECRET = "0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff"
# HKDF-SHA256(ikm=KAT_SECRET, salt=None, info="ratatoskr/<purpose>/v1", L=32), cross-checked against an independent
# RFC 5869 implementation built on hmac (see test_derive_key_matches_rfc5869).
KAT_KEYS = {
    "upstream-refresh-token": "194c0507b8584e85544f3a058e37b24987366991a2672c66e630f6044051a72b",
    "client-secret": "30bc8c7dae1301b265e6c44ce5360b75454df13916dfd194ec5d80cd6c5b31b2",
    "csrf": "c8dce30903c7050dc7ab049477828cffac9507088b6f8f2086d7f22527b52165",
    "oidc-flow": "0308be7d10e894512af819300201d57878efb41b615d6a2fedf388d9eaf43ff0",
}
PUBLIC_MESSAGE = "ciphertext could not be opened"


def _rfc5869(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


@pytest.mark.parametrize("purpose", sorted(KAT_KEYS))
def test_derive_key_known_answers(purpose: str) -> None:
    assert derive_key(KAT_SECRET, purpose).hex() == KAT_KEYS[purpose]


@pytest.mark.parametrize("purpose", sorted(KAT_KEYS))
def test_derive_key_matches_rfc5869(purpose: str) -> None:
    assert derive_key(KAT_SECRET, purpose) == _rfc5869(KAT_SECRET.encode(), f"ratatoskr/{purpose}/v1".encode())


def test_keyring_uses_the_pinned_purpose_labels() -> None:
    ring = Keyring(KAT_SECRET)
    assert Sealer(bytes.fromhex(KAT_KEYS["upstream-refresh-token"])).open(ring.upstream.seal("u", aad="a"), "a") == "u"
    assert Sealer(bytes.fromhex(KAT_KEYS["client-secret"])).open(ring.client_secrets.seal("c", aad="a"), "a") == "c"
    assert Signer(bytes.fromhex(KAT_KEYS["csrf"])).verify("m", ring.csrf.sign("m"))
    assert Signer(bytes.fromhex(KAT_KEYS["oidc-flow"])).verify("m", ring.oidc_flow.sign("m"))


def test_sealed_blob_layout() -> None:
    key = bytes.fromhex(KAT_KEYS["client-secret"])
    blob = Sealer(key).seal("hello", aad="alice")
    kid = hmac.new(key, b"kid", hashlib.sha256).digest()[:4]
    assert blob[0] == 1  # format version
    assert blob[1:5] == kid  # key id
    assert len(blob) == 1 + 4 + 12 + len(b"hello") + 16  # version, key id, nonce, ciphertext, GCM tag


def test_open_rejects_unknown_version() -> None:
    sealer = Sealer(derive_key("s" * 32, "x"))
    blob = sealer.seal("secret", aad="alice")
    with pytest.raises(DecryptionError) as info:
        sealer.open(b"\x02" + blob[1:], aad="alice")
    assert info.value.reason == "unknown-version"
    assert str(info.value) == PUBLIC_MESSAGE


def test_open_tells_key_mismatch_from_tampering() -> None:
    sealer = Sealer(derive_key("s" * 32, "x"))
    blob = sealer.seal("secret", aad="alice")
    with pytest.raises(DecryptionError) as mismatch:
        Sealer(derive_key("t" * 32, "x")).open(blob, aad="alice")
    assert mismatch.value.reason == "key-mismatch"
    for bad_blob, aad in (
        (blob[:-1] + bytes([blob[-1] ^ 1]), "alice"),  # tag
        (blob[:6] + bytes([blob[6] ^ 1]) + blob[7:], "alice"),  # nonce
        (blob, "bob"),  # aad
    ):
        with pytest.raises(DecryptionError) as tampered:
            sealer.open(bad_blob, aad=aad)
        assert tampered.value.reason == "tampered"
        assert str(tampered.value) == PUBLIC_MESSAGE
    assert str(mismatch.value) == PUBLIC_MESSAGE


def test_open_reasons_for_malformed_input() -> None:
    sealer = Sealer(derive_key("s" * 32, "x"))
    with pytest.raises(DecryptionError) as short:
        sealer.open(b"\x01" + b"\x00" * 31, aad="a")
    assert short.value.reason == "too-short"
    with pytest.raises(DecryptionError) as wrong_type:
        sealer.open("text", aad="a")  # type: ignore[arg-type]
    assert wrong_type.value.reason == "not-bytes"


def test_secret_key_problem_accepts_strong_keys() -> None:
    assert secret_key_problem(SECRET_KEY) is None
    assert secret_key_problem(new_token()) is None
    assert secret_key_problem("abcdefghij" + "a" * 22) is None  # 32 characters, 10 distinct


@pytest.mark.parametrize(
    ("value", "fragment"),
    [("", "at least 32"), ("x7Kq9-pL2" * 3, "at least 32"), ("k" * 48, "distinct"), ("abcdefghi" * 6, "distinct")],
    ids=["empty", "31-chars", "one-char", "nine-distinct"],
)
def test_secret_key_problem_reports_weak_keys_without_echoing_them(value: str, fragment: str) -> None:
    problem = secret_key_problem(value)
    assert problem is not None
    assert fragment in problem
    assert problem.startswith("server.secret_key")
    if value:
        assert value[:8] not in problem


def test_pkce_challenge_documents_server_generated_verifiers_only() -> None:
    assert pkce_challenge.__doc__ is not None
    assert "server-generated" in pkce_challenge.__doc__


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
