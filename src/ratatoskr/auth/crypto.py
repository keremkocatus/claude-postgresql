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

_NONCE_BYTES = 12


class DecryptionError(Exception):
    """Ciphertext was tampered with or sealed under a different key."""


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
    """RFC 7636 S256 code challenge for ``verifier``."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def derive_key(secret_key: str, purpose: str) -> bytes:
    """32-byte key for ``purpose``, derived with HKDF-SHA256 so every use gets an independent key."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=f"ratatoskr/{purpose}/v1".encode())
    return hkdf.derive(secret_key.encode("utf-8"))


class Sealer:
    """AES-256-GCM with a random 96-bit nonce; output is ``nonce || ciphertext+tag``."""

    def __init__(self, key: bytes) -> None:
        self._aead = AESGCM(key)

    def seal(self, plaintext: str, aad: str) -> bytes:
        nonce = os.urandom(_NONCE_BYTES)
        return nonce + self._aead.encrypt(nonce, _utf8(plaintext), _utf8(aad))

    def open(self, blob: bytes, aad: str) -> str:
        """Plaintext, or ``DecryptionError`` for anything that is not an intact blob sealed under this key and aad."""
        if not isinstance(blob, bytes | bytearray | memoryview):
            raise DecryptionError("ciphertext is not bytes")
        if len(blob) <= _NONCE_BYTES:
            raise DecryptionError("ciphertext too short")
        data = bytes(blob)
        try:
            plain = self._aead.decrypt(data[:_NONCE_BYTES], data[_NONCE_BYTES:], _utf8(aad))
            return plain.decode("utf-8", "surrogatepass")
        except (InvalidTag, UnicodeDecodeError) as exc:
            raise DecryptionError("ciphertext failed authentication") from exc


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
