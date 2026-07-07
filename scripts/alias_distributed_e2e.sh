#!/usr/bin/env bash
set -euo pipefail

# End-to-end correctness test for ALIAS flattening in a two-node distributed
# cluster. Verifies:
#   1. an ALIAS at the apex is flattened to real A/AAAA and served
#   2. the flattened records replicate and converge on the second node
#   3. ALIAS itself is never served on the wire
#   4. multi-master writes (write to EITHER node, read on both) still work
#   5. the per-node vector clocks converge (no anti-entropy divergence)
#   6. deleting the ALIAS removes the flattened records cluster-wide
#
# The ALIAS target defaults to "localhost." (offline, deterministic → 127.0.0.1
# and ::1). The expected addresses are computed with the same net.DefaultResolver
# the flattener uses, so the assertions are self-calibrating for any target.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ID="${RUN_ID:-$(date +%Y%m%d%H%M%S)}"
WORK_DIR="${WORK_DIR:-/tmp/go53-alias-e2e-${RUN_ID}}"
KEEP_TMP="${KEEP_TMP:-0}"

ALIAS_TARGET="${ALIAS_TARGET:-localhost.}"
ZONE="${ZONE:-alias.go53.test.}"
SETTLE_SECONDS="${SETTLE_SECONDS:-8}"
FLATTEN_TIMEOUT="${FLATTEN_TIMEOUT:-120}"
CLEANUP_TIMEOUT="${CLEANUP_TIMEOUT:-160}"
REPLICATE_TIMEOUT="${REPLICATE_TIMEOUT:-30}"

LOCAL_HOST="127.0.0.1"
SERVER_BIN="${WORK_DIR}/go53-server"
CTL_BIN="${WORK_DIR}/go53ctl"
RESOLVE_SRC="${WORK_DIR}/resolve.go"
BUILD_GOCACHE="${GOCACHE:-/tmp/go53-gocache}"
BUILD_GOTMPDIR="${GOTMPDIR:-/tmp/go53-gotmp}"

NODE_A_DB="${WORK_DIR}/node-a-db"
NODE_B_DB="${WORK_DIR}/node-b-db"
NODE_A_SOCK="${WORK_DIR}/node-a-admin.sock"
NODE_B_SOCK="${WORK_DIR}/node-b-admin.sock"
NODE_A_API="http://${LOCAL_HOST}:18160"
NODE_B_API="http://${LOCAL_HOST}:18161"
NODE_A_DNS_PORT="15460"
NODE_B_DNS_PORT="15461"
NODE_A_SYNC_PORT="53560"
NODE_B_SYNC_PORT="53561"
NODE_B_SYNC="tls://${LOCAL_HOST}:${NODE_B_SYNC_PORT}"

PIDS=()
FAILURES=0

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
fail() { printf '  ✗ FAIL: %s\n' "$*"; FAILURES=$((FAILURES + 1)); }
pass() { printf '  ✓ %s\n' "$*"; }

need_cmd() {
	command -v "$1" >/dev/null 2>&1 || { printf 'missing required command: %s\n' "$1" >&2; exit 1; }
}

cleanup() {
	stop_all_nodes
	if [[ "$KEEP_TMP" != "1" ]]; then
		rm -rf "$WORK_DIR"
	else
		log "kept work dir: $WORK_DIR"
	fi
}
trap cleanup EXIT INT TERM

stop_all_nodes() {
	local pid
	for pid in "${PIDS[@]:-}"; do
		kill -0 "$pid" >/dev/null 2>&1 && kill "$pid" >/dev/null 2>&1 || true
	done
	# Give processes a moment to exit, then force-kill any stragglers so a slow
	# or stuck shutdown can never hang the run.
	for pid in "${PIDS[@]:-}"; do
		local waited=0
		while kill -0 "$pid" >/dev/null 2>&1 && (( waited < 30 )); do
			sleep 0.2
			waited=$((waited + 1))
		done
		kill -0 "$pid" >/dev/null 2>&1 && kill -9 "$pid" >/dev/null 2>&1 || true
	done
	wait "${PIDS[@]:-}" 2>/dev/null || true
	PIDS=()
}

api() {
	local method="$1" url="$2" body="${3:-}"
	if [[ -n "$body" ]]; then
		curl -fsS -m 15 -X "$method" -H 'Content-Type: application/json' -d "$body" "$url"
	else
		curl -fsS -m 15 -X "$method" "$url"
	fi
}

sock_api() {
	local sock="$1" method="$2" path="$3" body="${4:-}"
	if [[ -n "$body" ]]; then
		curl -fsS -m 15 --unix-socket "$sock" -X "$method" -H 'Content-Type: application/json' -d "$body" "http://localhost${path}"
	else
		curl -fsS -m 15 --unix-socket "$sock" -X "$method" "http://localhost${path}"
	fi
}

record_url() { printf '%s/api/zones/%s/records/%s' "$1" "$ZONE" "$2"; }
post_record() { api POST "$(record_url "$1" "$2")" "$3" >/dev/null; }

dig_short() {
	local port="$1" name="$2" rtype="$3"
	dig @"$LOCAL_HOST" -p "$port" "$name" "$rtype" +time=1 +tries=1 +short 2>/dev/null | sort
}

resolve_expected() {
	local network="$1"
	GOCACHE="$BUILD_GOCACHE" GOTMPDIR="$BUILD_GOTMPDIR" go run "$RESOLVE_SRC" "$network" "$ALIAS_TARGET" 2>/dev/null | sort
}

wait_sock() {
	local sock="$1"
	local timeout="${2:-20}"
	local deadline=$((SECONDS + timeout))
	# Probe an actual request, not just the file: a restart leaves the previous
	# instance's socket file behind until the new process removes and rebinds it,
	# so file existence alone can point at a dead listener.
	until curl -fsS -m 2 --unix-socket "$sock" http://localhost/api/config >/dev/null 2>&1; do
		(( SECONDS >= deadline )) && { printf 'timeout waiting for admin socket %s\n' "$sock" >&2; return 1; }
		sleep 0.2
	done
}

wait_http() {
	local url="$1"
	local timeout="${2:-20}"
	local deadline=$((SECONDS + timeout))
	until curl -fsS -m 3 "$url" >/dev/null 2>&1; do
		(( SECONDS >= deadline )) && { printf 'timeout waiting for %s\n' "$url" >&2; return 1; }
		sleep 0.2
	done
}

wait_dns_soa() {
	local port="$1"
	local timeout="${2:-20}"
	local deadline=$((SECONDS + timeout))
	until [[ -n "$(dig_short "$port" "$ZONE" SOA)" ]]; do
		(( SECONDS >= deadline )) && { printf 'timeout waiting for DNS SOA on port %s\n' "$port" >&2; return 1; }
		sleep 0.2
	done
}

start_node() {
	local name="$1" db="$2" dns_port="$3" api_port="$4" sock="$5"
	local log_file="${WORK_DIR}/${name}.log"
	# Clear any socket file left by a prior instance so wait_sock only succeeds
	# once THIS process has bound its listener.
	rm -f "$sock"
	BADGER_DIR="$db" BIND_HOST="$LOCAL_HOST" DNS_PORT=":${dns_port}" \
		API_PORT=":${api_port}" STORAGE_BACKEND="badger" ADMIN_SOCKET="$sock" \
		"$SERVER_BIN" >"$log_file" 2>&1 &
	PIDS+=("$!")
	# The default auth mode ("disabled") closes the TCP API; open it to "none"
	# through the trusted admin socket so the rest of the run can use HTTP.
	wait_sock "$sock"
	sock_api "$sock" PATCH /api/config '{"auth":{"mode":"none"}}' >/dev/null
	wait_http "http://${LOCAL_HOST}:${api_port}/api/config"
}

start_node_a() { start_node node-a "$NODE_A_DB" "$NODE_A_DNS_PORT" 18160 "$NODE_A_SOCK"; }
start_node_b() { start_node node-b "$NODE_B_DB" "$NODE_B_DNS_PORT" 18161 "$NODE_B_SOCK"; }
restart_node_a() { stop_all_nodes; start_node_a; }
restart_cluster_nodes() { stop_all_nodes; start_node_a; start_node_b; }

json_field() {
	printf '%s' "$2" | sed -n "s/.*\"${1}\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p"
}

configure_distributed_node() {
	local api_base="$1" node_id="$2" sync_port="$3" private_key="$4"
	api PATCH "${api_base}/api/config" "{
  \"mode\": \"distributed\",
  \"auth\": { \"mode\": \"none\" },
  \"distributed\": {
    \"node_id\": \"${node_id}\",
    \"transport\": \"tls\",
    \"sync_bind_host\": \"${LOCAL_HOST}\",
    \"sync_port\": \":${sync_port}\",
    \"peers\": \"\",
    \"private_key\": \"${private_key}\",
    \"peer_public_keys\": {},
    \"push_timeout_ms\": 2000,
    \"resync_interval_s\": 5
  },
  \"allow_recursion\": false,
  \"allow_axfr\": true,
  \"default_ttl\": 60,
  \"max_udp_size\": 1232,
  \"enable_edns\": true
}" >/dev/null
}

seed_zone() {
	local api_base="$1"
	post_record "$api_base" SOA \
		"{\"ttl\":60,\"ns\":\"ns1.${ZONE}\",\"mbox\":\"hostmaster.${ZONE}\",\"refresh\":3600,\"retry\":600,\"expire\":1209600,\"minimum\":60}"
	post_record "$api_base" NS "{\"name\":\"${ZONE}\",\"ttl\":60,\"ns\":\"ns1.${ZONE}\"}"
	post_record "$api_base" A "{\"name\":\"ns1.${ZONE}\",\"ttl\":60,\"ip\":\"192.0.2.53\"}"
}

# Poll until `dig` on the given node returns exactly the expected sorted set.
poll_dns_equals() {
	local port="$1" name="$2" rtype="$3" expected="$4" timeout="$5"
	local deadline=$((SECONDS + timeout)) got
	while :; do
		got="$(dig_short "$port" "$name" "$rtype")"
		[[ "$got" == "$expected" ]] && { printf '%s' "$got"; return 0; }
		(( SECONDS >= deadline )) && { printf '%s' "$got"; return 1; }
		sleep 1
	done
}

poll_dns_empty() {
	local port="$1" name="$2" rtype="$3" timeout="$4"
	local deadline=$((SECONDS + timeout)) got
	while :; do
		got="$(dig_short "$port" "$name" "$rtype")"
		[[ -z "$got" ]] && return 0
		(( SECONDS >= deadline )) && { printf '%s' "$got"; return 1; }
		sleep 1
	done
}

need_cmd go
need_cmd curl
need_cmd dig
need_cmd sed

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR" "$BUILD_GOCACHE" "$BUILD_GOTMPDIR"

cat > "$RESOLVE_SRC" <<'EOF'
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"time"
)

func main() {
	network, host := os.Args[1], os.Args[2]
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, network, host)
	if err != nil {
		return
	}
	out := []string{}
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	sort.Strings(out)
	for _, s := range out {
		fmt.Println(s)
	}
}
EOF

log "building server and go53ctl"
GOCACHE="$BUILD_GOCACHE" GOTMPDIR="$BUILD_GOTMPDIR" go build -o "$SERVER_BIN" "$ROOT_DIR/cmd/server"
GOCACHE="$BUILD_GOCACHE" GOTMPDIR="$BUILD_GOTMPDIR" go build -o "$CTL_BIN" "$ROOT_DIR/cmd/go53ctl"

EXPECT_A="$(resolve_expected ip4)"
EXPECT_AAAA="$(resolve_expected ip6)"
log "ALIAS target ${ALIAS_TARGET} resolves to A=[$(echo "$EXPECT_A" | tr '\n' ' ')] AAAA=[$(echo "$EXPECT_AAAA" | tr '\n' ' ')]"
if [[ -z "$EXPECT_A" && -z "$EXPECT_AAAA" ]]; then
	printf 'ALIAS target %s does not resolve to any address; set ALIAS_TARGET to a resolvable name\n' "$ALIAS_TARGET" >&2
	exit 1
fi

log "starting node-a and forming distributed cluster"
start_node_a
node_a_key_json="$(api POST "${NODE_A_API}/api/distributed/keypair")"
node_a_private_key="$(json_field private_key "$node_a_key_json")"
configure_distributed_node "$NODE_A_API" "node-a" "$NODE_A_SYNC_PORT" "$node_a_private_key"
restart_node_a
wait_http "${NODE_A_API}/.well-known/go53-node.json"

start_node_b
# --join-node-id pins node-b's id (otherwise it defaults to the hostname);
# --auto-accept skips the manual approve step so a fresh join replicates at once.
invite_token="$("$CTL_BIN" cluster invite --api "$NODE_A_API" --usage-count 1 --ttl 15m --join-node-id node-b --sync-bind-host "$LOCAL_HOST" --resync-interval-s 5 --auto-accept)"
"$CTL_BIN" cluster join --token "$invite_token" --api "$NODE_B_API" --sync-endpoint "$NODE_B_SYNC"
restart_cluster_nodes
wait_http "${NODE_A_API}/.well-known/go53-node.json"
wait_http "${NODE_B_API}/.well-known/go53-node.json"
log "waiting ${SETTLE_SECONDS}s for initial resync"
sleep "$SETTLE_SECONDS"

log "seeding zone ${ZONE} on node-a"
seed_zone "$NODE_A_API"
sleep "$SETTLE_SECONDS"
wait_dns_soa "$NODE_A_DNS_PORT"
wait_dns_soa "$NODE_B_DNS_PORT"

printf '\n=== T1: apex ALIAS is flattened and served on the origin node ===\n'
post_record "$NODE_A_API" ALIAS "{\"name\":\"@\",\"ttl\":60,\"target\":\"${ALIAS_TARGET}\"}"
if [[ -n "$EXPECT_A" ]]; then
	got_a="$(poll_dns_equals "$NODE_A_DNS_PORT" "$ZONE" A "$EXPECT_A" "$FLATTEN_TIMEOUT")" \
		&& pass "node-a serves flattened A: $(echo "$got_a" | tr '\n' ' ')" \
		|| fail "node-a A mismatch: want [$(echo "$EXPECT_A" | tr '\n' ' ')] got [$(echo "$got_a" | tr '\n' ' ')]"
fi
if [[ -n "$EXPECT_AAAA" ]]; then
	got_aaaa="$(poll_dns_equals "$NODE_A_DNS_PORT" "$ZONE" AAAA "$EXPECT_AAAA" "$FLATTEN_TIMEOUT")" \
		&& pass "node-a serves flattened AAAA: $(echo "$got_aaaa" | tr '\n' ' ')" \
		|| fail "node-a AAAA mismatch: want [$(echo "$EXPECT_AAAA" | tr '\n' ' ')] got [$(echo "$got_aaaa" | tr '\n' ' ')]"
fi

if [[ "${DEBUG_ALIAS:-0}" == "1" ]]; then
	printf '  [dbg] node-a dig AAAA=[%s]  API AAAA=%s\n' \
		"$(dig_short "$NODE_A_DNS_PORT" "$ZONE" AAAA | tr '\n' ' ')" \
		"$(api GET "$(record_url "$NODE_A_API" AAAA)" 2>/dev/null | head -c 200)"
	printf '  [dbg] node-b dig AAAA=[%s]  API AAAA=%s\n' \
		"$(dig_short "$NODE_B_DNS_PORT" "$ZONE" AAAA | tr '\n' ' ')" \
		"$(api GET "$(record_url "$NODE_B_API" AAAA)" 2>/dev/null | head -c 200)"
fi

printf '\n=== T2: flattened records replicate and converge on node-b ===\n'
if [[ -n "$EXPECT_A" ]]; then
	got_b="$(poll_dns_equals "$NODE_B_DNS_PORT" "$ZONE" A "$EXPECT_A" "$REPLICATE_TIMEOUT")" \
		&& pass "node-b serves the same flattened A" \
		|| fail "node-b A mismatch: want [$(echo "$EXPECT_A" | tr '\n' ' ')] got [$(echo "$got_b" | tr '\n' ' ')]"
fi
if [[ -n "$EXPECT_AAAA" ]]; then
	got_b6="$(poll_dns_equals "$NODE_B_DNS_PORT" "$ZONE" AAAA "$EXPECT_AAAA" "$REPLICATE_TIMEOUT")" \
		&& pass "node-b serves the same flattened AAAA" \
		|| fail "node-b AAAA mismatch: want [$(echo "$EXPECT_AAAA" | tr '\n' ' ')] got [$(echo "$got_b6" | tr '\n' ' ')]"
fi

printf '\n=== T3: ALIAS is stored but never served on the wire ===\n'
if api GET "$(record_url "$NODE_A_API" ALIAS)" | grep -q "$ALIAS_TARGET"; then
	pass "ALIAS row is present via the API (target ${ALIAS_TARGET})"
else
	fail "ALIAS row not found via the API"
fi
raw_a="$(dig_short "$NODE_A_DNS_PORT" "$ZONE" TYPE65280)"
raw_b="$(dig_short "$NODE_B_DNS_PORT" "$ZONE" TYPE65280)"
if [[ -z "$raw_a" && -z "$raw_b" ]]; then
	pass "querying ALIAS (TYPE65280) returns no wire records on either node"
else
	fail "ALIAS leaked on the wire: node-a=[$raw_a] node-b=[$raw_b]"
fi

printf '\n=== T4: multi-master writes converge (write to either node) ===\n'
post_record "$NODE_B_API" A "{\"name\":\"mm-b.${ZONE}\",\"ttl\":60,\"ip\":\"203.0.113.11\"}"
got="$(poll_dns_equals "$NODE_A_DNS_PORT" "mm-b.${ZONE}" A "203.0.113.11" "$REPLICATE_TIMEOUT")" \
	&& pass "write to node-b is served by node-a (B→A replication)" \
	|| fail "node-a never saw node-b's write (got [$got])"
post_record "$NODE_A_API" A "{\"name\":\"mm-a.${ZONE}\",\"ttl\":60,\"ip\":\"203.0.113.12\"}"
got="$(poll_dns_equals "$NODE_B_DNS_PORT" "mm-a.${ZONE}" A "203.0.113.12" "$REPLICATE_TIMEOUT")" \
	&& pass "write to node-a is served by node-b (A→B replication)" \
	|| fail "node-b never saw node-a's write (got [$got])"

printf '\n=== T5: per-node vector clocks converge (no divergence) ===\n'
vec_a=""; vec_b=""
deadline=$((SECONDS + REPLICATE_TIMEOUT))
while :; do
	vec_a="$(api GET "${NODE_A_API}/api/distributed/status" | tr ',' '\n' | grep -oE '"node-[ab]":[0-9]+' | sort | tr '\n' ' ')"
	vec_b="$(api GET "${NODE_B_API}/api/distributed/status" | tr ',' '\n' | grep -oE '"node-[ab]":[0-9]+' | sort | tr '\n' ' ')"
	[[ -n "$vec_a" && "$vec_a" == "$vec_b" ]] && break
	(( SECONDS >= deadline )) && break
	sleep 1
done
if [[ -n "$vec_a" && "$vec_a" == "$vec_b" ]]; then
	pass "vectors converged: ${vec_a}"
else
	fail "vectors diverged: node-a=[${vec_a}] node-b=[${vec_b}]"
fi

printf '\n=== T6: deleting the ALIAS removes flattened records cluster-wide ===\n'
# The apex record is stored under "@"; the delete handler resolves the {name}
# path segment through SplitName, so the zone FQDN addresses the apex record.
curl -fsS -m 15 -X DELETE "$(record_url "$NODE_B_API" ALIAS)/${ZONE}" >/dev/null
del_a=1; del_b=1
if [[ -n "$EXPECT_A" ]]; then
	poll_dns_empty "$NODE_A_DNS_PORT" "$ZONE" A "$CLEANUP_TIMEOUT" >/dev/null && del_a=0 || del_a=1
	poll_dns_empty "$NODE_B_DNS_PORT" "$ZONE" A "$CLEANUP_TIMEOUT" >/dev/null && del_b=0 || del_b=1
	if (( del_a == 0 && del_b == 0 )); then
		pass "flattened A records removed on both nodes after ALIAS delete"
	else
		fail "flattened A survived delete: node-a_cleared=$((1 - del_a)) node-b_cleared=$((1 - del_b))"
	fi
fi

printf '\n=== Summary ===\n'
if (( FAILURES == 0 )); then
	printf 'ALL CHECKS PASSED\n'
	exit 0
else
	printf '%d CHECK(S) FAILED\n' "$FAILURES"
	exit 1
fi
