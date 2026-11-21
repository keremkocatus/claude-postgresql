from typing import Any

import respx

from ratatoskr.backends.output import NOTE_RESERVE_BYTES
from ratatoskr.backends.prometheus import alerts
from ratatoskr.backends.prometheus.backend import PrometheusBackend
from tests.unit.prom_helpers import api_error, make_backend, success

ALERTS = {
    "alerts": [
        {
            "labels": {"alertname": "DiskFilling", "severity": "warning", "instance": "db-1"},
            "annotations": {"description": "Disk is 85% full"},
            "state": "pending",
            "activeAt": "2026-11-22T09:50:00.5Z",
        },
        {
            "labels": {"alertname": "HighErrorRate", "severity": "critical", "job": "api"},
            "annotations": {"summary": "5xx above 5% | for 10m"},
            "state": "firing",
            "activeAt": "2026-11-22T09:12:00.123456789Z",
        },
    ]
}
RULES: dict[str, Any] = {
    "groups": [
        {
            "name": "api",
            "file": "/etc/prometheus/rules/api.yml",
            "interval": 30,
            "lastEvaluation": "2026-11-22T09:59:45.1Z",
            "evaluationTime": 0.0042,
            "rules": [
                {"type": "alerting", "name": "HighErrorRate", "state": "firing", "health": "ok"},
                {"type": "alerting", "name": "Latency", "state": "inactive", "health": "ok"},
                {
                    "type": "recording",
                    "name": "job:errors:rate5m",
                    "health": "err",
                    "lastError": "query timed out fetching from 10.0.0.9:9090",
                },
            ],
        }
    ]
}


async def test_alerts_and_rule_groups(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    prom_api.get("/api/v1/alerts").mock(return_value=success(ALERTS))
    prom_api.get("/api/v1/rules").mock(return_value=success(RULES))
    output = await alerts.alerts_overview(prom_backend)
    assert output.text.splitlines() == [
        "Alerts: 1 firing, 1 pending.",
        "| state | alert | since | severity | labels | summary |",
        "| --- | --- | --- | --- | --- | --- |",
        '| firing | HighErrorRate | 2026-11-22T09:12:00Z | critical | job="api" | 5xx above 5% \\| for 10m |',
        '| pending | DiskFilling | 2026-11-22T09:50:00Z | warning | instance="db-1" | Disk is 85% full |',
        "",
        "Rule groups: 1 groups, 3 rules, 1 unhealthy.",
        "| group | file | interval | alerting | recording | firing | pending | unhealthy | last evaluation | took |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        "| api | api.yml | 30s | 2 | 1 | 1 | 0 | 1 | 2026-11-22T09:59:45Z | 4.2 ms |",
        "",
        "Unhealthy rules:",
        "- api / job:errors:rate5m: query timed out fetching from <address>",
    ]
    assert output.rows == 2


async def test_no_alerts_and_no_rules(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    prom_api.get("/api/v1/alerts").mock(return_value=success({"alerts": []}))
    prom_api.get("/api/v1/rules").mock(return_value=success({"groups": []}))
    output = await alerts.alerts_overview(prom_backend)
    assert output.text == "Alerts: none firing or pending.\n\nRule groups: none loaded."
    assert output.rows == 0


async def test_rules_endpoint_failure_keeps_the_alerts(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    prom_api.get("/api/v1/alerts").mock(return_value=success(ALERTS))
    prom_api.get("/api/v1/rules").mock(return_value=api_error(400, "bad_data", "vmalert.proxyURL is not set"))
    output = await alerts.alerts_overview(prom_backend)
    assert "Alerts: 1 firing, 1 pending." in output.text
    assert output.text.endswith("Rule groups are unavailable: Prometheus error (bad_data): vmalert.proxyURL is not set")


def test_alerts_are_capped() -> None:
    many = [{"labels": {"alertname": f"A{i:02}"}, "state": "firing"} for i in range(5)]
    text, shown = alerts.format_alerts(many, max_items=2, budget=10_000)
    assert shown == 2
    assert text.count("| firing |") == 2
    assert text.endswith(
        '[Showing 2 of 5 alerts: the limit is 2. Query ALERTS{alertstate="firing"} with prom_query to filter them.]'
    )


async def test_rule_errors_shown_in_the_output_are_redacted(
    prom_api: respx.Router, prom_backend: PrometheusBackend
) -> None:
    prom_api.get("/api/v1/alerts").mock(return_value=success(ALERTS))
    prom_api.get("/api/v1/rules").mock(
        return_value=api_error(400, "bad_data", "proxy at 10.0.0.9:8880 refused token=s3cr3t-VALUE")
    )
    output = await alerts.alerts_overview(prom_backend)
    assert output.text.endswith(
        "Rule groups are unavailable: Prometheus error (bad_data): proxy at <address> refused token=***"
    )


async def test_last_errors_of_unhealthy_rules_are_redacted(
    prom_api: respx.Router, prom_backend: PrometheusBackend
) -> None:
    rules = {"groups": [{"name": "g", "rules": [{"name": "r", "health": "err", "lastError": "password=hunter2 bad"}]}]}
    prom_api.get("/api/v1/alerts").mock(return_value=success({"alerts": []}))
    prom_api.get("/api/v1/rules").mock(return_value=success(rules))
    output = await alerts.alerts_overview(prom_backend)
    assert "hunter2" not in output.text
    assert output.text.endswith("- g / r: password=*** bad")


async def test_audit_rows_count_the_alerts_shown(prom_api: respx.Router) -> None:
    backend = make_backend(limits={"max_series": 1})
    await backend.open()
    prom_api.get("/api/v1/alerts").mock(return_value=success(ALERTS))
    prom_api.get("/api/v1/rules").mock(return_value=success(RULES))
    output = await alerts.alerts_overview(backend)
    await backend.close()
    assert "[Showing 1 of 2 alerts: the limit is 1." in output.text
    assert output.rows == 1


async def test_many_unhealthy_rules_stay_within_the_response_budget(prom_api: respx.Router) -> None:
    backend = make_backend(limits={"max_response_bytes": 4096})
    await backend.open()
    rules = [{"name": f"r{i}", "health": "err", "lastError": "é" * 300} for i in range(40)]
    prom_api.get("/api/v1/alerts").mock(return_value=success({"alerts": []}))
    prom_api.get("/api/v1/rules").mock(return_value=success({"groups": [{"name": "g", "rules": rules}]}))
    output = await alerts.alerts_overview(backend)
    await backend.close()
    assert len(output.text.encode()) <= 4096 - NOTE_RESERVE_BYTES
    assert output.text.endswith("more")
