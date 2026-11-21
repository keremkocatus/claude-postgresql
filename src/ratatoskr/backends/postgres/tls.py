"""Translate ``tls:`` settings into the ``ssl`` argument of asyncpg."""

from __future__ import annotations

import ssl

from ratatoskr.config.models import PgTlsSettings


def build_ssl(tls: PgTlsSettings | None) -> ssl.SSLContext | str | None:
    """None keeps asyncpg's default (the DSN's sslmode, else 'prefer'); 'disable' turns TLS off."""
    if tls is None:
        return None
    if tls.mode == "disable":
        return "disable"
    context = ssl.create_default_context(cafile=str(tls.ca_file) if tls.ca_file else None)
    if tls.mode == "require":
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    elif tls.mode == "verify-ca":
        context.check_hostname = False
    if tls.cert_file is not None and tls.key_file is not None:
        context.load_cert_chain(certfile=str(tls.cert_file), keyfile=str(tls.key_file))
    return context
