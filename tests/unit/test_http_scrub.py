import time
from collections.abc import Callable

import pytest

from ratatoskr.backends.http.scrub import MAX_UPSTREAM_TEXT, replace_addresses, scrub_upstream_text


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


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("store prometheus-0:10901 unavailable", "store <address> unavailable"),
        ("addr=thanos-store-0:10901", "addr=<address>"),
        ("dial tcp prometheus-0:10901: connect: connection refused", "dial tcp <address>: connect: connection refused"),
        ("dial tcp 2001:db8::1:9090: connect refused", "dial tcp <address>: connect refused"),
        ("dial tcp fe80::1%eth0 refused", "dial tcp <address> refused"),
        ("peer 0a00:0001:: gone", "peer <address> gone"),
        ("mapped ::ffff:10.0.0.1 gone", "mapped <address> gone"),
        ("pod/ingester-7.ingester.mimir unreachable", "pod/<host> unreachable"),
        ("host prom.example.com unreachable.", "host <host> unreachable."),
        ("store [fe80::1%eth0]:10901 failed", "store <address> failed"),
        ("db.internal.", "<host>."),
    ],
)
def test_more_address_forms_are_replaced(text: str, expected: str) -> None:
    assert scrub_upstream_text(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "1:14: parse error: unexpected character",
        "subquery rate(x[5m:1m]) and x[1h:30s] offset 5m",
        "recording rule job:http_5xx:rate5m and instance:node_cpu:ratio",
        'invalid parameter "start": cannot parse "2026-11-22T10:00:00Z" to a valid timestamp',
        "time 10:00:00 and version v3.16.0, value 1.5e10",
        'strconv.ParseFloat: parsing "abc": invalid syntax',
        'name does not end in _total: "http.server.request.duration"',
        "std::chrono and a :: b",
    ],
)
def test_ordinary_server_text_is_not_mistaken_for_addresses(text: str) -> None:
    assert scrub_upstream_text(text) == text


ADVERSARIAL = 32 * 1024


@pytest.mark.parametrize(
    "unit",
    [
        "a-",
        "a.",
        "a:",
        "1:",
        "a.a:",
        "0:",
        "0::",
        "1.",
        "a.-+",
        "a:/",
        "[0:",
        "a-a.",
        "x.svc.",
        "a.1:1.",
        "a1:",
        "[::aaaaaaaaaa",
        '"a.b.c',
    ],
    ids=repr,
)
def test_address_patterns_are_linear(unit: str) -> None:
    """32 KB built to make backtracking patterns quadratic (seconds to minutes) is scrubbed in milliseconds."""
    text = unit * (ADVERSARIAL // len(unit)) + "("
    hosts = ["prom.example.com", "prom.example.com:9090", "prometheus", "a-a"]
    assert _fastest(lambda: replace_addresses(text, hosts=hosts)) < 0.1


def test_long_server_text_is_cut_before_it_is_scrubbed() -> None:
    message = "1:1: parse error: error parsing regexp: missing closing ): `" + "a-" * 10_000 + "(`"
    assert _fastest(lambda: scrub_upstream_text(message, hosts=["prom.example.com"])) < 0.1
    assert len(scrub_upstream_text(message)) == MAX_UPSTREAM_TEXT + 2


@pytest.mark.parametrize(("filler", "address"), [(96, "prom-1.store.mimir:10901"), (93, "10.0.0.7:10901")])
def test_a_cut_never_leaves_part_of_an_address(filler: int, address: str) -> None:
    """The input is cut before scrubbing; a token cut in half there is dropped, not shown half-scrubbed."""
    urls = ("http://" + "h" * 92 + " ") * 39  # 3900 characters that shrink to 234
    text = urls + "x" * filler + " " + address + " and more"
    assert address[:3] not in scrub_upstream_text(text)


def _fastest(run: Callable[[], object]) -> float:
    best = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        run()
        best = min(best, time.perf_counter() - started)
    return best
