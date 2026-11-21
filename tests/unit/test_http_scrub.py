import pytest

from ratatoskr.backends.http.scrub import MAX_UPSTREAM_TEXT, scrub_upstream_text


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            'Get "http://10.0.0.7:10902/api/v1/query": dial tcp: i/o timeout',
            'Get "<url>": dial tcp: i/o timeout',
        ),
        ("receive series from 10.0.0.7:10901: rpc error", "receive series from <address>: rpc error"),
        ("store [fd00::7]:10901 failed", "store <address> failed"),
        ("addr thanos-store.monitoring.svc.cluster.local failed", "addr <host> failed"),
        ("ingester-3.ingesters.prod.example.com:9095 refused", "<address> refused"),
        ("db.internal is slow", "<host> is slow"),
    ],
)
def test_addresses_are_replaced(text: str, expected: str) -> None:
    assert scrub_upstream_text(text) == expected


def test_promql_errors_stay_readable() -> None:
    text = '1:14: parse error: unexpected "}" in label matching, expected string; rate(x[5m:1m]) job:up:sum'
    assert scrub_upstream_text(text) == text


def test_configured_single_label_host_is_replaced_only_with_a_port() -> None:
    text = "prometheus:9090 is down; prometheus_http_requests_total exists"
    assert scrub_upstream_text(text, hosts=["prometheus"]) == "<host> is down; prometheus_http_requests_total exists"


def test_configured_dotted_host_is_replaced_everywhere() -> None:
    text = "query failed at prom.example.com (prom.example.com:443)"
    assert scrub_upstream_text(text, hosts=["prom.example.com"]) == "query failed at <host> (<host>)"


def test_long_text_is_cut() -> None:
    assert len(scrub_upstream_text("a" * 5000)) == MAX_UPSTREAM_TEXT + 2
