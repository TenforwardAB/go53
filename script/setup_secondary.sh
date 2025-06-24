#!/usr/bin/env bash

set -euo pipefail

BASE_URL="http://localhost:8054"
JSON_HEADER="Content-Type: application/json"

echo "Updating config for secondary..."

curl -s -X PATCH "$BASE_URL/api/config" -H "$JSON_HEADER" -d '{
  "log_level": "debug",
  "dnssec_enabled": true,
  "mode": "secondary",
  "allow_transfer": "",
  "allow_recursion": false,
  "default_ttl": 3600,
  "version": "go53 1.0.0",
  "max_udp_size": 1232,
  "enable_edns": true,
  "rate_limit_qps": 0,
  "allow_axfr": false,
  "default_ns": "ns1.go53.test.",
  "primary": {
    "notify_debounce_ms": 2000,
    "ip": "172.99.53.10"
  },
  "secondary": {
    "fetch_debounce_ms": 3000,
    "min_fetch_interval_sec": 10,
    "max_parallel_fetches": 5
  }
}'

echo "Secondary configuration complete."
