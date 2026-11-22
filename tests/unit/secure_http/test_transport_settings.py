from __future__ import annotations

import pytest
from argon2 import PasswordHasher
from pydantic import AnyHttpUrl, SecretStr

from ratatoskr.config.loader import ConfigError
from ratatoskr.config.models import LocalAuthSettings, LocalUser
from ratatoskr.transport.client_ip import client_ip, parse_trusted_proxies, rate_limit_address
from ratatoskr.transport.preconditions import check_http_preconditions
from ratatoskr.transport.security import mcp_auth_settings, transport_security
from tests.unit.secure_http.conftest import PASSWORD, SECRET_KEY


def scope(peer: str | None, *xff: str) -> dict[str, object]:
    headers = [(b"x-forwarded-for", value.encode()) for value in xff]
    result: dict[str, object] = {"type": "http", "headers": headers}
    if peer is not None:
        result["client"] = (peer, 5000)
    return result


# ── client IP ───────────────────────────────────────────────────────────────


def test_untrusted_peer_ignores_forwarded_for() -> None:
    assert client_ip(scope("203.0.113.9", "1.1.1.1"), ()) == "203.0.113.9"
    trusted = parse_trusted_proxies(["10.0.0.0/8"])
    assert client_ip(scope("203.0.113.9", "1.1.1.1"), trusted) == "203.0.113.9"


def test_trusted_proxy_uses_rightmost_untrusted_hop() -> None:
    trusted = parse_trusted_proxies(["10.0.0.0/8", "172.16.0.5"])
    assert client_ip(scope("10.1.2.3", "6.6.6.6, 198.51.100.7, 172.16.0.5"), trusted) == "198.51.100.7"
    assert client_ip(scope("10.1.2.3", "10.0.0.9"), trusted) == "10.0.0.9"
    assert client_ip(scope("10.1.2.3"), trusted) == "10.1.2.3"


def test_malformed_forwarded_for_falls_back_to_peer() -> None:
    trusted = parse_trusted_proxies(["10.0.0.0/8"])
    assert client_ip(scope("10.1.2.3", "not-an-ip"), trusted) == "10.1.2.3"
    assert client_ip(scope("10.1.2.3", "  ,  "), trusted) == "10.1.2.3"


def test_forwarded_for_hops_with_a_port_are_accepted() -> None:
    trusted = parse_trusted_proxies(["10.0.0.0/8"])
    assert client_ip(scope("10.1.2.3", "198.51.100.7:4444"), trusted) == "198.51.100.7"
    assert client_ip(scope("10.1.2.3", "[2001:db8::1]:443"), trusted) == "2001:db8::1"
    assert client_ip(scope("10.1.2.3", "[2001:db8::1]"), trusted) == "2001:db8::1"
    assert client_ip(scope("10.1.2.3", "198.51.100.7, 10.0.0.4:80"), trusted) == "198.51.100.7"


@pytest.mark.parametrize(
    "hop",
    [
        "198.51.100.7:",
        "198.51.100.7:abc",
        "198.51.100.7:99999",
        "198.51.100.7:+80",
        "198.51.100.7:٨٠",
        "2001:db8::1]:443",
        "[2001:db8::1]x",
        "[198.51.100.7]:80",
        "[2001:db8::1]:",
        "host.example:80",
        "1.2.3.4:5:6",
    ],
)
def test_malformed_ports_fall_back_to_peer(hop: str) -> None:
    trusted = parse_trusted_proxies(["10.0.0.0/8"])
    assert client_ip(scope("10.1.2.3", hop), trusted) == "10.1.2.3"


def test_client_garbage_left_of_the_real_hop_is_never_read() -> None:
    # Otherwise a client could push itself into the proxy's shared rate-limit bucket.
    trusted = parse_trusted_proxies(["10.0.0.0/8"])
    assert client_ip(scope("10.1.2.3", "garbage, 198.51.100.7"), trusted) == "198.51.100.7"
    assert client_ip(scope("10.1.2.3", "garbage, 198.51.100.7, 10.0.0.4"), trusted) == "198.51.100.7"


def test_missing_client_is_unknown() -> None:
    assert client_ip({"type": "http", "headers": []}, ()) == "unknown"
    assert client_ip(scope(None), parse_trusted_proxies(["10.0.0.0/8"])) == "unknown"


def test_every_forwarded_for_header_line_is_considered() -> None:
    # A proxy that adds its own header line instead of appending must not let the client's line win.
    trusted = parse_trusted_proxies(["10.0.0.0/8"])
    assert client_ip(scope("10.1.2.3", "6.6.6.6", "198.51.100.7"), trusted) == "198.51.100.7"


def test_addresses_are_canonical() -> None:
    trusted = parse_trusted_proxies(["10.0.0.0/8"])
    assert client_ip(scope("2001:DB8:0:0::1"), ()) == "2001:db8::1"
    assert client_ip(scope("10.1.2.3", "2001:0db8::0001"), trusted) == "2001:db8::1"


def test_ipv4_mapped_addresses_are_unwrapped() -> None:
    trusted = parse_trusted_proxies(["10.0.0.0/8"])
    assert client_ip(scope("::ffff:203.0.113.9"), ()) == "203.0.113.9"
    assert client_ip(scope("::ffff:10.0.0.1", "::ffff:198.51.100.7"), trusted) == "198.51.100.7"
    assert client_ip(scope("::ffff:10.0.0.1", "::ffff:10.0.0.2"), trusted) == "10.0.0.2"
    mapped_entry = parse_trusted_proxies(["::ffff:10.0.0.0/104"])
    assert client_ip(scope("10.0.0.1", "198.51.100.7"), mapped_entry) == "198.51.100.7"


def test_non_ip_peer_is_used_verbatim() -> None:
    assert client_ip(scope("testclient", "1.1.1.1"), parse_trusted_proxies(["0.0.0.0/0"])) == "testclient"


def test_rate_limit_address_groups_ipv6_by_64() -> None:
    assert rate_limit_address("2001:db8:1:2:aaaa::1") == "2001:db8:1:2::"
    assert rate_limit_address("2001:db8:1:2:bbbb:cccc:dddd:eeee") == "2001:db8:1:2::"
    assert rate_limit_address("2001:db8:1:3::1") == "2001:db8:1:3::"
    assert rate_limit_address("203.0.113.9") == "203.0.113.9"
    assert rate_limit_address("::ffff:203.0.113.9") == "203.0.113.9"
    assert rate_limit_address("fe80::1%eth0") == "fe80::"
    assert rate_limit_address("unknown") == "unknown"


# ── preconditions ───────────────────────────────────────────────────────────


def with_server(config, **updates):
    """Copy without validation, so 1a's model validators cannot pre-empt the check under test."""
    if "public_url" in updates and isinstance(updates["public_url"], str):
        updates["public_url"] = AnyHttpUrl(updates["public_url"])
    if "secret_key" in updates and isinstance(updates["secret_key"], str):
        updates["secret_key"] = SecretStr(updates["secret_key"])
    return config.model_copy(update={"server": config.server.model_copy(update=updates)})


def with_users(config, *users: LocalUser):
    assert config.auth is not None
    local = LocalAuthSettings(users=list(users))
    return config.model_copy(update={"auth": config.auth.model_copy(update={"local": local})})


def with_auth(config, **updates):
    assert config.auth is not None
    return config.model_copy(update={"auth": config.auth.model_copy(update=updates)})


def test_https_config_passes(make_config) -> None:
    settings = check_http_preconditions(make_config(), insecure_dev=False)
    assert settings.public_url == "https://mcp.example.com"
    assert settings.secret_key == SECRET_KEY
    assert settings.warnings == ()


def test_secret_key_is_not_in_the_repr(make_config) -> None:
    settings = check_http_preconditions(make_config(), insecure_dev=False)
    assert SECRET_KEY not in repr(settings)
    assert "local_provider" not in repr(settings)


async def test_local_mode_carries_the_checked_identity_provider(make_config) -> None:
    from ratatoskr.auth.identity.local import LocalIdentityProvider

    provider = check_http_preconditions(make_config(), insecure_dev=False).local_provider
    assert isinstance(provider, LocalIdentityProvider)
    principal = await provider.verify_password("kerem", PASSWORD)
    assert principal is not None and principal.subject == "kerem"


def test_oidc_mode_has_no_local_provider(make_config) -> None:
    assert check_http_preconditions(make_config(mode="oidc"), insecure_dev=False).local_provider is None


def test_auth_is_mandatory(make_config) -> None:
    config = make_config().model_copy(update={"auth": None})
    with pytest.raises(ConfigError, match="auth"):
        check_http_preconditions(config, insecure_dev=False)


def test_secret_key_is_mandatory_and_long(make_config) -> None:
    with pytest.raises(ConfigError, match="secret_key"):
        check_http_preconditions(with_server(make_config(), secret_key=None), insecure_dev=False)
    with pytest.raises(ConfigError, match="32") as info:
        check_http_preconditions(with_server(make_config(), secret_key="short"), insecure_dev=False)
    assert "short" not in str(info.value)


def test_low_entropy_secret_key_is_refused(make_config) -> None:
    weak = "ab" * 24
    with pytest.raises(ConfigError, match="distinct characters") as info:
        check_http_preconditions(with_server(make_config(), secret_key=weak), insecure_dev=False)
    assert weak not in str(info.value)


def test_public_url_is_mandatory_https_origin(make_config) -> None:
    with pytest.raises(ConfigError, match="public_url is required"):
        check_http_preconditions(with_server(make_config(), public_url=None), insecure_dev=False)
    with pytest.raises(ConfigError, match="https"):
        check_http_preconditions(with_server(make_config(), public_url="http://mcp.example.com"), insecure_dev=False)
    with pytest.raises(ConfigError, match="no path"):
        check_http_preconditions(
            with_server(make_config(), public_url="https://mcp.example.com/mcp"), insecure_dev=False
        )
    with pytest.raises(ConfigError, match="no path"):
        check_http_preconditions(
            with_server(make_config(), public_url="https://mcp.example.com/?x=1"), insecure_dev=False
        )


def test_public_url_must_not_carry_credentials(make_config) -> None:
    config = with_server(make_config(), public_url="https://admin:hunter2@mcp.example.com")
    with pytest.raises(ConfigError, match="credentials") as info:
        check_http_preconditions(config, insecure_dev=False)
    assert "hunter2" not in str(info.value)


def test_insecure_dev_allows_plain_http_only_on_loopback(make_config) -> None:
    config = with_server(make_config(), public_url="http://127.0.0.1:8000", host="127.0.0.1")
    settings = check_http_preconditions(config, insecure_dev=True)
    assert settings.public_url == "http://127.0.0.1:8000"
    assert settings.warnings and "INSECURE" in settings.warnings[0]
    with pytest.raises(ConfigError, match="server.host"):
        check_http_preconditions(with_server(config, host="0.0.0.0"), insecure_dev=True)
    with pytest.raises(ConfigError, match="public_url"):
        check_http_preconditions(with_server(config, public_url="http://mcp.example.com"), insecure_dev=True)


def test_insecure_dev_accepts_ipv6_loopback(make_config) -> None:
    config = with_server(make_config(), public_url="http://[::1]:8000", host="::1")
    assert check_http_preconditions(config, insecure_dev=True).public_url == "http://[::1]:8000"


def test_insecure_dev_warns_even_with_https(make_config) -> None:
    settings = check_http_preconditions(with_server(make_config(), host="127.0.0.1"), insecure_dev=True)
    assert settings.warnings


def test_local_password_hashes_must_be_argon2id(make_config) -> None:
    users = [LocalUser(username="kerem", password_hash=SecretStr("not-a-hash"))]
    with pytest.raises(ConfigError, match="user 'kerem': password_hash must be an argon2id hash") as info:
        check_http_preconditions(with_users(make_config(), *users), insecure_dev=False)
    assert "not-a-hash" not in str(info.value)


def test_argon2i_hashes_are_refused(make_config) -> None:
    from argon2 import Type

    argon2i = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1, type=Type.I).hash("pw")
    user = LocalUser(username="kerem", password_hash=SecretStr(argon2i))
    with pytest.raises(ConfigError, match="argon2id") as info:
        check_http_preconditions(with_users(make_config(), user), insecure_dev=False)
    assert argon2i not in str(info.value)


def test_local_usernames_must_be_unique_after_normalisation(make_config, password_hash: str) -> None:
    users = [
        LocalUser(username="Kerem", password_hash=SecretStr(password_hash)),
        LocalUser(username=" kerem ", password_hash=SecretStr(password_hash)),
    ]
    with pytest.raises(ConfigError, match="more than once"):
        check_http_preconditions(with_users(make_config(), *users), insecure_dev=False)


def test_local_usernames_must_not_be_empty(make_config, password_hash: str) -> None:
    user = LocalUser(username="  ", password_hash=SecretStr(password_hash))
    with pytest.raises(ConfigError, match="must not be empty"):
        check_http_preconditions(with_users(make_config(), user), insecure_dev=False)


def test_local_users_must_share_argon2_parameters(make_config, password_hash: str) -> None:
    other = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=2).hash("pw")
    users = [
        LocalUser(username="kerem", password_hash=SecretStr(password_hash)),
        LocalUser(username="ayse", password_hash=SecretStr(other)),
    ]
    with pytest.raises(ConfigError, match="same argon2 parameters") as info:
        check_http_preconditions(with_users(make_config(), *users), insecure_dev=False)
    assert other not in str(info.value) and password_hash not in str(info.value)


def test_local_mode_without_users_is_refused(make_config) -> None:
    with pytest.raises(ConfigError, match="auth.local.users"):
        check_http_preconditions(with_auth(make_config(), local=None), insecure_dev=False)


def test_oidc_issuer_must_be_https(make_config) -> None:
    config = make_config(mode="oidc")
    assert check_http_preconditions(config, insecure_dev=False).warnings == ()
    assert config.auth is not None and config.auth.oidc is not None
    plain = config.auth.oidc.model_copy(update={"issuer": AnyHttpUrl("http://idp.example.com/app/")})
    with pytest.raises(ConfigError, match="auth.oidc.issuer must use https"):
        check_http_preconditions(with_auth(config, oidc=plain), insecure_dev=False)
    dev = with_server(with_auth(config, oidc=plain), host="127.0.0.1")
    assert check_http_preconditions(dev, insecure_dev=True).warnings


def test_oidc_mode_without_section_is_refused(make_config) -> None:
    with pytest.raises(ConfigError, match="auth.oidc"):
        check_http_preconditions(with_auth(make_config(mode="oidc"), oidc=None), insecure_dev=False)


@pytest.mark.parametrize(
    ("entry", "shown"),
    [("0.0.0.0/0", "0.0.0.0/0"), ("::/0", "::/0"), ("::ffff:0:0/96", "::ffff:0.0.0.0/96")],
)
def test_catch_all_trusted_proxies_warn(make_config, entry: str, shown: str) -> None:
    config = make_config(server_extra={"trusted_proxies": ["10.0.0.0/8", "::ffff:10.0.0.0/104", entry]})
    warnings = check_http_preconditions(config, insecure_dev=False).warnings
    assert len(warnings) == 1 and shown in warnings[0] and "X-Forwarded-For" in warnings[0]


def test_loopback_hosts_come_from_the_config_models() -> None:
    from ratatoskr.config import models
    from ratatoskr.transport import preconditions

    assert preconditions.LOOPBACK_HOSTS is models.LOOPBACK_HOSTS


def test_wrong_transport_is_refused(make_config) -> None:
    with pytest.raises(ConfigError, match="streamable-http"):
        check_http_preconditions(with_server(make_config(), transport="stdio"), insecure_dev=False)


# ── SDK settings ────────────────────────────────────────────────────────────


def test_auth_settings_bind_tokens_to_the_mcp_endpoint() -> None:
    settings = mcp_auth_settings("https://mcp.example.com")
    assert str(settings.issuer_url) == "https://mcp.example.com/"
    assert str(settings.resource_server_url) == "https://mcp.example.com/mcp"
    assert settings.validate_token_resource is True
    assert settings.client_registration_options is not None and settings.client_registration_options.enabled
    assert settings.client_registration_options.default_scopes == ["mcp"]
    # scopes_supported in both metadata documents
    assert settings.client_registration_options.valid_scopes == ["mcp"] and settings.required_scopes == ["mcp"]
    assert settings.revocation_options is not None and settings.revocation_options.enabled


def test_transport_security_allows_only_the_public_host() -> None:
    sec = transport_security("https://mcp.example.com")
    assert sec.enable_dns_rebinding_protection
    assert sec.allowed_hosts == ["mcp.example.com", "mcp.example.com:*"]
    assert sec.allowed_origins == ["https://mcp.example.com", "https://mcp.example.com:*"]
    assert transport_security("http://[::1]:8000").allowed_hosts == ["[::1]", "[::1]:*"]


def test_preconditions_report_exactly_what_the_identity_provider_refuses(make_config, password_hash: str) -> None:
    from ratatoskr.auth.identity.local import LocalIdentityProvider

    other = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=2).hash("pw")
    users = [
        LocalUser(username="kerem", password_hash=SecretStr(password_hash)),
        LocalUser(username="ayse", password_hash=SecretStr(other)),
    ]
    with pytest.raises(ValueError) as provider_error:
        LocalIdentityProvider(users)
    with pytest.raises(ConfigError) as precondition_error:
        check_http_preconditions(with_users(make_config(), *users), insecure_dev=False)
    assert str(precondition_error.value) == str(provider_error.value)


def test_weak_password_hashes_are_warnings(make_config) -> None:
    weak = PasswordHasher(time_cost=1, memory_cost=1024, parallelism=1)
    users = [
        LocalUser(username="kerem", password_hash=SecretStr(weak.hash("a"))),
        LocalUser(username="ayse", password_hash=SecretStr(weak.hash("b"))),
    ]
    settings = check_http_preconditions(with_users(make_config(), *users), insecure_dev=False)
    assert len(settings.warnings) == 2
    assert all("OWASP" in warning for warning in settings.warnings)
    assert "'kerem'" in settings.warnings[0] and "'ayse'" in settings.warnings[1]
    assert all(user.password_hash.get_secret_value() not in " ".join(settings.warnings) for user in users)


def test_strong_password_hashes_give_no_warning(make_config) -> None:
    assert check_http_preconditions(make_config(), insecure_dev=False).warnings == ()


# ── state_path and settings that are not implemented ────────────────────────


def test_state_directory_may_be_missing_if_it_can_be_created(make_config, tmp_path) -> None:
    config = with_server(make_config(), state_path=tmp_path / "new" / "deeper" / "state.db")
    check_http_preconditions(config, insecure_dev=False)
    assert not (tmp_path / "new").exists(), "checking must not create anything"


def test_state_directory_that_cannot_be_created_is_a_config_error(make_config, tmp_path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    config = with_server(make_config(), state_path=blocker / "sub" / "state.db")
    with pytest.raises(ConfigError, match=r"server\.state_path") as info:
        check_http_preconditions(config, insecure_dev=False)
    assert "cannot be created" in str(info.value)


def test_state_path_that_is_a_directory_is_a_config_error(make_config, tmp_path) -> None:
    (tmp_path / "state.db").mkdir()
    with pytest.raises(ConfigError, match=r"server\.state_path .* is a directory"):
        check_http_preconditions(with_server(make_config(), state_path=tmp_path / "state.db"), insecure_dev=False)


def test_unwritable_state_directory_is_a_config_error_naming_the_fix(make_config, tmp_path, monkeypatch) -> None:
    import ratatoskr.transport.preconditions as preconditions

    monkeypatch.setattr(preconditions.os, "access", lambda path, mode: False)
    with pytest.raises(ConfigError, match=r"server\.state_path") as info:
        check_http_preconditions(make_config(), insecure_dev=False)
    assert "not writable" in str(info.value) and "chown" in str(info.value)


def test_missing_state_dir_under_unwritable_parent_says_where_to_check(make_config, tmp_path, monkeypatch) -> None:
    """A container config checked on a host (/data absent, / not writable): no chown advice for the wrong place."""
    import ratatoskr.transport.preconditions as preconditions

    monkeypatch.setattr(preconditions.os, "access", lambda path, mode: False)
    config = with_server(make_config(), state_path=tmp_path / "data" / "state.db")
    with pytest.raises(ConfigError, match=r"server\.state_path") as info:
        check_http_preconditions(config, insecure_dev=False)
    message = str(info.value)
    assert "does not exist" in message and "where `serve` runs" in message and "chown" not in message


def test_metrics_port_adds_no_warning(make_config) -> None:
    settings = check_http_preconditions(with_server(make_config(), metrics_port=9100), insecure_dev=False)
    assert not any("metrics" in w for w in settings.warnings)
