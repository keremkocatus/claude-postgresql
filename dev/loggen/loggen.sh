#!/bin/sh
# Pushes made-up log lines of two apps to the dev Loki every 2 seconds (compose.dev.yml). busybox sh and wget only.
set -u
url="${LOKI_URL:-http://loki:3100}/loki/api/v1/push"
i=0
while true; do
  i=$((i + 1))
  now="$(date +%s)000000000"
  case $((i % 10)) in
    0) app=shop-api level=error line="GET /orders/$i 500 upstream timeout after 3000ms" ;;
    3 | 7) app=shop-api level=warn line="slow query on orders took $((i % 900 + 100))ms" ;;
    5) app=worker level=info line="sent invoice for order $i" ;;
    *) app=shop-api level=info line="GET /orders/$i 200 $((i % 40 + 5))ms" ;;
  esac
  body=$(printf '{"streams":[{"stream":{"app":"%s","env":"dev","level":"%s"},"values":[["%s","%s"]]}]}' \
    "$app" "$level" "$now" "$line")
  wget -q -O /dev/null --header 'Content-Type: application/json' --post-data "$body" "$url" \
    || echo "loggen: push to $url failed" >&2
  sleep 2
done
