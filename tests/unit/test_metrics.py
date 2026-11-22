"""Metrics: four Ratatoskr series with bounded labels, rendered in the Prometheus text format."""

from prometheus_client.parser import text_string_to_metric_families

from ratatoskr.auth.events import AuthEventName
from ratatoskr.observability.metrics import GLOBAL_CONNECTION, UNRESOLVED_CONNECTION, Metrics


def _samples(metrics: Metrics) -> dict[tuple[str, tuple[tuple[str, str], ...]], float]:
    out: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
    for family in text_string_to_metric_families(metrics.render().decode("utf-8")):
        for sample in family.samples:
            out[(sample.name, tuple(sorted(sample.labels.items())))] = sample.value
    return out


def test_tool_calls_are_counted_per_tool_connection_and_result() -> None:
    metrics = Metrics(["prod", "dev"])
    metrics.observe_tool("pg_query", "prod", "ok", 0.2)
    metrics.observe_tool("pg_query", "prod", "ok", 0.3)
    metrics.observe_tool("pg_query", "prod", "denied", 0.0)
    samples = _samples(metrics)
    key = ("connection", "prod"), ("result", "ok"), ("tool", "pg_query")
    assert samples[("ratatoskr_tool_calls_total", key)] == 2
    assert samples[("ratatoskr_tool_duration_seconds_count", (("connection", "prod"), ("tool", "pg_query")))] == 3
    assert samples[("ratatoskr_tool_duration_seconds_sum", (("connection", "prod"), ("tool", "pg_query")))] == 0.5


def test_auth_events_start_at_zero_for_every_known_event() -> None:
    metrics = Metrics([])
    metrics.count_auth_event("login_failed")
    samples = _samples(metrics)
    for event in AuthEventName.__args__:
        expected = 1 if event == "login_failed" else 0
        assert samples[("ratatoskr_auth_events_total", (("event", event),))] == expected


def test_backend_up_is_a_gauge_per_configured_connection() -> None:
    metrics = Metrics(["prod", "dev"])
    metrics.set_backend_up("prod", True)
    metrics.set_backend_up("dev", False)
    samples = _samples(metrics)
    assert samples[("ratatoskr_backend_up", (("connection", "prod"),))] == 1
    assert samples[("ratatoskr_backend_up", (("connection", "dev"),))] == 0


def test_unconfigured_names_never_become_label_values() -> None:
    metrics = Metrics(["prod"])
    assert metrics.connection_label("prod", None, "ok") == "prod"
    assert metrics.connection_label("ghost", "ConnectionNotFoundError", "denied") == UNRESOLVED_CONNECTION
    assert metrics.connection_label("../../etc/passwd", None, "ok") == UNRESOLVED_CONNECTION
    assert metrics.connection_label(None, None, "ok") == GLOBAL_CONNECTION
    metrics.set_backend_up("ghost", True)  # ignored: not a configured connection
    assert "ghost" not in metrics.render().decode("utf-8")


def test_forbidden_and_unauthenticated_calls_hide_the_name() -> None:
    metrics = Metrics(["prod"])
    assert metrics.connection_label("prod", "ConnectionNotFoundError", "denied") == UNRESOLVED_CONNECTION
    assert metrics.connection_label("prod", "PermissionError", "denied") == UNRESOLVED_CONNECTION  # no identity
    assert metrics.connection_label("prod", "InsufficientAccessError", "denied") == "prod"


def test_an_os_permission_error_on_a_permitted_connection_keeps_the_name() -> None:
    metrics = Metrics(["prod"])
    assert metrics.connection_label("prod", "PermissionError", "error") == "prod"


def test_fixed_labels_cannot_collide_with_connection_names() -> None:
    from ratatoskr.config.models import CONNECTION_NAME_RE

    assert CONNECTION_NAME_RE.fullmatch(GLOBAL_CONNECTION) is None
    assert CONNECTION_NAME_RE.fullmatch(UNRESOLVED_CONNECTION) is None


def test_no_created_series_are_exported() -> None:
    metrics = Metrics(["prod"])
    metrics.observe_tool("pg_query", "prod", "ok", 0.1)
    assert "_created" not in metrics.render().decode("utf-8")


def test_two_instances_do_not_share_state() -> None:
    first, second = Metrics(["prod"]), Metrics(["prod"])
    first.observe_tool("pg_query", "prod", "ok", 0.1)
    assert ("ratatoskr_tool_calls_total", (("connection", "prod"), ("result", "ok"), ("tool", "pg_query"))) not in (
        _samples(second)
    )
