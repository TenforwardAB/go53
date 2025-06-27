#!/usr/bin/env bash

set -euo pipefail

BASE_URL="http://localhost:8053"
ZONE="go53.test"
JSON_HEADER="Content-Type: application/json"

echo "Updating config..."
curl -s -X PATCH "$BASE_URL/api/config" -H "$JSON_HEADER" -d '{
  "log_level": "debug",
  "dnssec_enabled": true,
  "mode": "primary",
  "allow_transfer": "172.99.53.11",
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

echo "Creating records in zone: $ZONE"

post_record() {
  local type=$1
  local payload=$2
  echo " Adding  $type"
  curl -s -X POST "$BASE_URL/api/zones/${ZONE}/records/${type}" -H "$JSON_HEADER" -d "$payload"
}

post_record "soa" '{
  "Ns": "ns2.go53.eu.",
  "Mbox": "hostmaster3.go53.eu."
}'

post_record "a" '{
  "name": "www",
  "ip": "1.2.3.8",
  "ttl": 3600
}'

post_record "a" '{
  "name": "www",
  "ip": "1.2.3.9",
  "ttl": 3600
}'

post_record "a" '{
  "name": "mail",
  "ip": "1.2.3.8",
  "ttl": 3600
}'

post_record "cname" '{
  "name": "mail1",
  "target": "mail.go53.test",
  "ttl": 3600
}'

post_record "a" '{
  "name": "api",
  "ip": "1.2.3.8",
  "ttl": 3600
}'

post_record "mx" '{
  "name": "@",
  "host": "mail1.go53.test.",
  "priority": 10,
  "ttl": 3600
}'

post_record "txt" '{
  "name": "test3",
  "text": "v=spf1 include:mailtrix.eu ~all",
  "ttl": 3600
}'

post_record "ns" '{
  "name": "@",
  "ns": "ns2.go53.test.",
  "ttl": 3600
}'

post_record "spf" '{
   "name": "@",
   "text": "v=spf1 include:mailtrix.eu ~all",
   "ttl": 3600
}'

echo "Setup complete."
