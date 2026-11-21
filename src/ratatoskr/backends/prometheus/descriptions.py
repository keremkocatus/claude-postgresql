"""Tool and argument descriptions for the Prometheus tools. They are the product UX for the LLM: keep them short,
say what the tool returns, when to use it, and what the limits are."""

from __future__ import annotations

CONNECTION = (
    "Name of a Prometheus connection (kind prometheus) exactly as returned by list_connections. "
    "Call list_connections first if you do not know the names."
)
PROMQL = 'PromQL expression, e.g. up{job="api"} or sum by (instance) (rate(http_requests_total[5m])).'
TIME = "Evaluation time: RFC3339 (2026-11-22T10:00:00Z), unix seconds, or relative (now, now-15m, now-2h). Default now."
START = "Window start: RFC3339, unix seconds or relative (now-6h). Default: one hour before end."
END = "Window end: RFC3339, unix seconds or relative (now-1h). Default: now."
STEP = "Resolution such as 15s, 1m, 5m or 1h. Omit it to get up to about 120 points over the range."
MATCH = 'Optional series selector that limits the result, e.g. {job="api"} or http_requests_total{code=~"5.."}.'
NAME_CONTAINS = "Optional case-insensitive text the metric name must contain, e.g. http or memory."
LABEL = "Label name, e.g. job, instance, namespace, or __name__ for metric names."
TRUNCATION_HINT = (
    "Narrow the request: add label matchers, aggregate (sum by, topk), shorten the range or raise the step."
)

PROM_QUERY = (
    "Evaluate a PromQL expression at one instant (default now) and get each series' labels and value, or a scalar. "
    "Use it for the current state: up, error ratios, top consumers with topk. Shows at most the connection's series "
    "limit (default 100) and says how many matched; aggregate (sum by, topk) to stay under it. Find metric and label "
    "names with prom_list_metrics and prom_label_values first."
)
PROM_QUERY_RANGE = (
    "Evaluate a PromQL expression over a time window (default the last hour) and get per series: number of points, "
    "min, max, average, last value and up to 60 evenly spaced samples (fewer when there are many series). Use it for "
    "trends and incident windows. Without step it picks one that gives up to about 120 points; the connection caps "
    "points per series and the window length. At most the series limit (default 100) is shown."
)
PROM_LIST_METRICS = (
    "List metric names that have data in a time window (default the last hour), with type and help text when the "
    "server keeps metadata. Narrow with name_contains (e.g. 'http') or a match selector (e.g. {job=\"api\"}). Use it "
    "to find the right metric before prom_query. Shows at most the connection's list limit (default 500)."
)
PROM_LABEL_VALUES = (
    "List the values of one label (e.g. job, instance, namespace) on series with data in a time window (default the "
    "last hour), optionally only on series matching a selector. Use it to write exact label matchers for prom_query. "
    "Shows at most the connection's list limit (default 500)."
)
PROM_ALERTS = (
    "Show the alerts that are firing or pending now (name, state, since when, severity, labels, summary) and the "
    "state of every rule group (rule counts, firing and pending rules, unhealthy rules with their last error, last "
    "evaluation). Start here when investigating an incident."
)
