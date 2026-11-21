"""Token hashing, opaque token generation and keys derived from ``server.secret_key``."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_VERSION = b"\x01"
_KID_BYTES = 4
_NONCE_BYTES = 12
_TAG_BYTES = 16
_HEADER_BYTES = len(_VERSION) + _KID_BYTES
_MIN_BLOB_BYTES = _HEADER_BYTES + _NONCE_BYTES + _TAG_BYTES
MIN_SECRET_KEY_LENGTH = 32
MIN_SECRET_KEY_DISTINCT = 10


class DecryptionError(Exception):
    """A sealed blob could not be opened.

    ``str(exc)`` is always the same fixed text; ``reason`` (``not-bytes``, ``too-short``, ``unknown-version``,
    ``key-mismatch`` or ``tampered``) is for logs only and never contains key material, plaintext or aad.
    """

    def __init__(self, reason: str) -> None:
        super().__init__("ciphertext could not be opened")
        self.reason = reason


def _utf8(text: str) -> bytes:
    """UTF-8 that never raises: lone surrogates in attacker-supplied strings are encoded, not rejected."""
    return text.encode("utf-8", "surrogatepass")


def new_token() -> str:
    """Opaque 32-byte random token, URL-safe base64 (43 characters)."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """SHA-256 hex digest; the only form in which tokens and codes are stored."""
    return hashlib.sha256(_utf8(token)).hexdigest()


def pkce_challenge(verifier: str) -> str:
    """RFC 7636 S256 code challenge for ``verifier``.

    Only for server-generated ASCII verifiers (e.g. our own upstream OIDC flow); it raises on non-ASCII input. The
    SDK verifies client-supplied PKCE verifiers on ``/token``, so this is never called with attacker input.
    """
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def derive_key(secret_key: str, purpose: str) -> bytes:
    """32-byte key for ``purpose``, derived with HKDF-SHA256 so every use gets an independent key."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=f"ratatoskr/{purpose}/v1".encode())
    return hkdf.derive(secret_key.encode("utf-8"))


def secret_key_problem(secret_key: str) -> str | None:
    """Why ``secret_key`` is too weak to derive keys from, or ``None`` if it is acceptable.

    Not wired into startup here: the HTTP preconditions (``transport.preconditions``) call it and refuse to serve on
    a problem. The message never contains the key.
    """
    if len(secret_key) < MIN_SECRET_KEY_LENGTH:
        return f"server.secret_key must be at least {MIN_SECRET_KEY_LENGTH} characters long"
    if len(set(secret_key)) < MIN_SECRET_KEY_DISTINCT:
        return (
            f"server.secret_key must contain at least {MIN_SECRET_KEY_DISTINCT} distinct characters "
            '(generate one with: python -c "import secrets; print(secrets.token_urlsafe(48))")'
        )
    return None


class Sealer:
    """AES-256-GCM with a random 96-bit nonce.

    Blob layout: ``version (1 byte, 0x01) || key id (4) || nonce (12) || ciphertext || GCM tag (16)``. The key id is
    ``HMAC-SHA256(key, b"kid")[:4]``, so a blob sealed under another key is told apart from a tampered one. The
    version byte and key id are part of the authenticated data.
    """

    def __init__(self, key: bytes) -> None:
        self._aead = AESGCM(key)
        self._header = _VERSION + hmac.new(key, b"kid", hashlib.sha256).digest()[:_KID_BYTES]

    def seal(self, plaintext: str, aad: str) -> bytes:
        nonce = os.urandom(_NONCE_BYTES)
        return self._header + nonce + self._aead.encrypt(nonce, _utf8(plaintext), self._header + _utf8(aad))

    def open(self, blob: bytes, aad: str) -> str:
        """Plaintext, or ``DecryptionError`` for anything that is not an intact blob sealed under this key and aad."""
        if not isinstance(blob, bytes | bytearray | memoryview):
            raise DecryptionError("not-bytes")
        data = bytes(blob)
        if len(data) < _MIN_BLOB_BYTES:
            raise DecryptionError("too-short")
        header, nonce, sealed = (
            data[:_HEADER_BYTES],
            data[_HEADER_BYTES : _HEADER_BYTES + _NONCE_BYTES],
            data[_HEADER_BYTES + _NONCE_BYTES :],
        )
        if header[:1] != _VERSION:
            raise DecryptionError("unknown-version")
        if not hmac.compare_digest(header, self._header):
            raise DecryptionError("key-mismatch")
        try:
            plain = self._aead.decrypt(nonce, sealed, header + _utf8(aad))
            return plain.decode("utf-8", "surrogatepass")
        except (InvalidTag, UnicodeDecodeError):
            raise DecryptionError("tampered") from None


class Signer:
    """HMAC-SHA256 signatures, URL-safe base64 without padding."""

    def __init__(self, key: bytes) -> None:
        self._key = key

    def sign(self, message: str) -> str:
        mac = hmac.new(self._key, _utf8(message), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(mac).decode("ascii").rstrip("=")

    def verify(self, message: str, signature: str) -> bool:
        """Constant-time check; ``False`` (never an exception) for any malformed or non-string signature."""
        if not isinstance(signature, str) or not signature.isascii():
            return False
        return hmac.compare_digest(self.sign(message).encode("ascii"), signature.encode("ascii"))


class Keyring:
    """All keys the server derives from ``server.secret_key``."""

    def __init__(self, secret_key: str) -> None:
        self.upstream = Sealer(derive_key(secret_key, "upstream-refresh-token"))
        self.client_secrets = Sealer(derive_key(secret_key, "client-secret"))
        self.csrf = Signer(derive_key(secret_key, "csrf"))
        self.oidc_flow = Signer(derive_key(secret_key, "oidc-flow"))
        self.password_fingerprint = Signer(derive_key(secret_key, "password-fingerprint"))
