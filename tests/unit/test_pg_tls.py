import ssl

from ratatoskr.backends.postgres.tls import build_ssl
from ratatoskr.config.models import PgTlsSettings


def test_no_tls_section_keeps_asyncpg_default() -> None:
    assert build_ssl(None) is None


def test_disable() -> None:
    assert build_ssl(PgTlsSettings(mode="disable")) == "disable"


def test_require_does_not_verify() -> None:
    context = build_ssl(PgTlsSettings(mode="require"))
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_NONE
    assert context.check_hostname is False


def test_verify_ca_checks_chain_not_hostname() -> None:
    context = build_ssl(PgTlsSettings(mode="verify-ca"))
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is False


def test_verify_full_checks_everything() -> None:
    context = build_ssl(PgTlsSettings(mode="verify-full"))
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
