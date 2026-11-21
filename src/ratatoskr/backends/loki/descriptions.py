"""Tool and argument descriptions for the Loki tools. They are the product UX for the LLM: keep them short, say what
the tool returns, when to use it, and what the limits are."""

from __future__ import annotations

CONNECTION = (
    "Name of a Loki connection (kind loki) exactly as returned by list_connections. "
    "Call list_connections first if you do not know the names."
)
LOGQL = (
    'LogQL. A log query: a stream selector plus filters, e.g. {app="api"} |= "error" or '
    '{namespace="prod"} | json | status >= 500. A metric query: e.g. sum by (level) (count_over_time({app="api"}[5m])).'
)
START = "Window start: RFC3339, unix seconds or relative (now-6h). Default: one hour before end."
END = "Window end: RFC3339, unix seconds or relative (now-1h). Default: now."
LIMIT = "Log queries: most lines to return (default 100, at most the connection's line limit, default 500)."
DIRECTION = "Log queries: backward (default) returns the newest lines first, forward the oldest first."
STEP = "Metric queries: resolution such as 15s, 1m or 5m. Omit it to get up to about 120 points over the window."
SELECTOR = 'Optional stream selector: only streams that match it count, e.g. {app="api"} or {namespace=~"prod-.*"}.'
LABEL = "Label name, e.g. app, namespace, pod or level; loki_labels lists them."
TRUNCATION_HINT = (
    'Narrow the request: a shorter time range, more label matchers, a |= "text" line filter, a lower limit, or '
    "aggregate a metric query (sum by, topk)."
)

LOKI_QUERY = (
    "Run a LogQL query over a time window (default the last hour; the connection caps the window, default 24h). "
    "A log query returns the matching lines, newest first: each stream's labels once, then every line with its UTC "
    "time; long lines are cut (default 2 KB) and marked. A metric query (count_over_time, rate, sum by) returns per "
    "series points, min, max, average, last value and sampled points. Returns at most limit lines (default 100) and "
    "says when more exist. Find labels with loki_labels and loki_label_values first; narrow with label matchers and "
    '|= "text" filters.'
)
LOKI_LABELS = (
    "List the label names on log streams with data in a time window (default the last hour), optionally only on "
    'streams matching a selector such as {app="api"}. Use it to build the stream selector for loki_query. Shows at '
    "most the connection's list limit (default 500)."
)
LOKI_LABEL_VALUES = (
    "List the values of one label (e.g. app, namespace, pod, level) on log streams with data in a time window "
    "(default the last hour), optionally only on streams matching a selector. Use it to write exact label matchers "
    "for loki_query. Shows at most the connection's list limit (default 500)."
)
