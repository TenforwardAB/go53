#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ID="${RUN_ID:-$(date +%Y%m%d%H%M%S)}"
WORK_DIR="${WORK_DIR:-/tmp/go53-cluster-onboarding-${RUN_ID}}"
KEEP_TMP="${KEEP_TMP:-0}"
LOCAL_HOST="${LOCAL_HOST:-127.0.0.1}"
BUILD_GOCACHE="${GOCACHE:-/tmp/go53-gocache}"

SERVER_BIN="${WORK_DIR}/go53-server"
CTL_BIN="${WORK_DIR}/go53ctl"

NODE_A_DNS_PORT="${NODE_A_DNS_PORT:-15530}"
NODE_B_DNS_PORT="${NODE_B_DNS_PORT:-15531}"
NODE_C_DNS_PORT="${NODE_C_DNS_PORT:-15532}"
NODE_A_API_PORT="${NODE_A_API_PORT:-18530}"
NODE_B_API_PORT="${NODE_B_API_PORT:-18531}"
NODE_C_API_PORT="${NODE_C_API_PORT:-18532}"
NODE_A_SYNC_PORT="${NODE_A_SYNC_PORT:-53530}"
NODE_B_SYNC_PORT="${NODE_B_SYNC_PORT:-53531}"
NODE_C_SYNC_PORT="${NODE_C_SYNC_PORT:-53532}"

NODE_A_SYNC="tls://${LOCAL_HOST}:${NODE_A_SYNC_PORT}"
NODE_B_SYNC="tls://${LOCAL_HOST}:${NODE_B_SYNC_PORT}"
NODE_C_SYNC="tls://${LOCAL_HOST}:${NODE_C_SYNC_PORT}"

NODE_A_SOCKET="${WORK_DIR}/node-a/admin.sock"
NODE_B_SOCKET="${WORK_DIR}/node-b/admin.sock"
NODE_C_SOCKET="${WORK_DIR}/node-c/admin.sock"

NODE_A_PID=""
NODE_B_PID=""
NODE_C_PID=""

log() {
	printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"
}

fail() {
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
}

need_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		fail "missing required command: $1"
	fi
}

cleanup() {
	for pid in "${NODE_A_PID:-}" "${NODE_B_PID:-}" "${NODE_C_PID:-}"; do
		if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
			kill "$pid" >/dev/null 2>&1 || true
		fi
	done
	wait "${NODE_A_PID:-}" "${NODE_B_PID:-}" "${NODE_C_PID:-}" 2>/dev/null || true
	if [[ "$KEEP_TMP" != "1" ]]; then
		rm -rf "$WORK_DIR"
	else
		log "kept work dir: $WORK_DIR"
	fi
}
trap cleanup EXIT INT TERM

ctl() {
	local socket="$1"
	shift
	GO53_ADMIN_SOCKET="$socket" "$CTL_BIN" "$@"
}

wait_for_socket() {
	local socket="$1"
	local deadline=$((SECONDS + 25))
	while ((SECONDS < deadline)); do
		if [[ -S "$socket" ]] && ctl "$socket" config get >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.2
	done
	fail "server did not expose admin socket: $socket"
}

wait_for_dns() {
	local port="$1"
	local deadline=$((SECONDS + 25))
	while ((SECONDS < deadline)); do
		if dig @"$LOCAL_HOST" -p "$port" version.bind TXT CH +time=1 +tries=1 +short >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.2
	done
	fail "server did not answer DNS on ${LOCAL_HOST}:${port}"
}

start_node() {
	local node="$1"
	local dns_port="$2"
	local api_port="$3"
	local socket="$4"
	local db="${WORK_DIR}/${node}/badger"
	local log_file="${WORK_DIR}/${node}/server.log"
	mkdir -p "$(dirname "$socket")" "$db"
	(
		cd "$ROOT_DIR"
		exec env BIND_HOST="$LOCAL_HOST" \
			DNS_PORT=":${dns_port}" \
			API_PORT=":${api_port}" \
			BADGER_DIR="$db" \
			ADMIN_SOCKET="$socket" \
			ADMIN_SOCKET_GROUP="" \
			"$SERVER_BIN"
	) >"$log_file" 2>&1 &
	case "$node" in
	node-a) NODE_A_PID=$! ;;
	node-b) NODE_B_PID=$! ;;
	node-c) NODE_C_PID=$! ;;
	esac
	wait_for_socket "$socket"
	wait_for_dns "$dns_port"
}

stop_node() {
	local node="$1"
	local pid_var=""
	case "$node" in
	node-a) pid_var="NODE_A_PID" ;;
	node-b) pid_var="NODE_B_PID" ;;
	node-c) pid_var="NODE_C_PID" ;;
	esac
	local pid="${!pid_var:-}"
	if [[ -n "$pid" ]] && kill -0 "$pid" >/dev/null 2>&1; then
		kill "$pid" >/dev/null 2>&1 || true
		wait "$pid" 2>/dev/null || true
	fi
	printf -v "$pid_var" ''
}

restart_node() {
	local node="$1"
	case "$node" in
	node-a)
		stop_node node-a
		start_node node-a "$NODE_A_DNS_PORT" "$NODE_A_API_PORT" "$NODE_A_SOCKET"
		;;
	node-b)
		stop_node node-b
		start_node node-b "$NODE_B_DNS_PORT" "$NODE_B_API_PORT" "$NODE_B_SOCKET"
		;;
	node-c)
		stop_node node-c
		start_node node-c "$NODE_C_DNS_PORT" "$NODE_C_API_PORT" "$NODE_C_SOCKET"
		;;
	esac
}

private_key() {
	local socket="$1"
	ctl "$socket" distributed keypair | jq -r '.private_key'
}

configure_issuer() {
	local key
	key="$(private_key "$NODE_A_SOCKET")"
	[[ -n "$key" && "$key" != "null" ]] || fail "could not generate node-a private key"
	ctl "$NODE_A_SOCKET" config patch "$(jq -nc \
		--arg private_key "$key" \
		--arg sync_port ":${NODE_A_SYNC_PORT}" \
		'{mode:"distributed", allow_axfr:true, dnssec_enabled:false,
		  distributed:{node_id:"node-a", transport:"tls", sync_bind_host:"127.0.0.1",
		  sync_port:$sync_port, peers:"", private_key:$private_key,
		  peer_public_keys:{}, push_timeout_ms:750, resync_interval_s:2}}')" >/dev/null
	restart_node node-a
	assert_node_id "$NODE_A_SOCKET" "node-a"
}

assert_node_id() {
	local socket="$1"
	local expected="$2"
	local got
	got="$(ctl "$socket" distributed well-known | jq -r '.node_id')"
	[[ "$got" == "$expected" ]] || fail "node_id on $socket = $got, want $expected"
}

assert_peer() {
	local socket="$1"
	local node_id="$2"
	local endpoint="$3"
	if ! has_peer "$socket" "$node_id" "$endpoint"; then
		fail "$socket does not include pinned peer $node_id at $endpoint"
	fi
}

has_peer() {
	local socket="$1"
	local node_id="$2"
	local endpoint="$3"
	local cfg
	cfg="$(ctl "$socket" config get)"
	jq -e --arg node "$node_id" '.distributed.peer_public_keys[$node] | strings | length > 0' <<<"$cfg" >/dev/null \
		|| return 1
	jq -e --arg endpoint "$endpoint" '(.distributed.peers // "" | split(",") | index($endpoint)) != null' <<<"$cfg" >/dev/null \
		|| return 1
}

assert_pending_count() {
	local expected="$1"
	local got
	got="$(ctl "$NODE_A_SOCKET" cluster pending | jq 'length')"
	[[ "$got" == "$expected" ]] || fail "pending count = $got, want $expected"
}

join_with_retry() {
	local socket="$1"
	local token="$2"
	local endpoint="$3"
	shift 3
	local deadline=$((SECONDS + 25))
	local out=""
	while ((SECONDS < deadline)); do
		if out="$("$CTL_BIN" cluster join --token "$token" --sync-endpoint "$endpoint" --socket "$socket" "$@" 2>&1)"; then
			printf '%s\n' "$out"
			return 0
		fi
		sleep 0.5
	done
	printf '%s\n' "$out" >&2
	return 1
}

main() {
	need_cmd jq
	need_cmd dig

	mkdir -p "$WORK_DIR"
	log "building go53 server and go53ctl"
	(
		cd "$ROOT_DIR"
		GOCACHE="$BUILD_GOCACHE" go build -o "$SERVER_BIN" ./cmd/server
		GOCACHE="$BUILD_GOCACHE" go build -o "$CTL_BIN" ./cmd/go53ctl
	)

	log "starting node-a issuer"
	start_node node-a "$NODE_A_DNS_PORT" "$NODE_A_API_PORT" "$NODE_A_SOCKET"
	configure_issuer

	log "starting node-b and testing pending join"
	start_node node-b "$NODE_B_DNS_PORT" "$NODE_B_API_PORT" "$NODE_B_SOCKET"
	token_b="$(ctl "$NODE_A_SOCKET" cluster invite --usage-count 1 --ttl 15m --join-node-id node-b --sync-bind-host "$LOCAL_HOST" --resync-interval-s 2)"
	join_with_retry "$NODE_B_SOCKET" "$token_b" "$NODE_B_SYNC" >"${WORK_DIR}/node-b-join.out"
	assert_node_id "$NODE_B_SOCKET" "node-b"
	assert_peer "$NODE_B_SOCKET" "node-a" "$NODE_A_SYNC"
	assert_pending_count 1
	ctl "$NODE_A_SOCKET" cluster approve node-b >/dev/null
	assert_pending_count 0
	assert_peer "$NODE_A_SOCKET" "node-b" "$NODE_B_SYNC"

	log "restarting node-b after pending approval"
	restart_node node-b
	assert_node_id "$NODE_B_SOCKET" "node-b"
	assert_peer "$NODE_B_SOCKET" "node-a" "$NODE_A_SYNC"

	log "starting node-c and testing auto-accept join into existing cluster"
	start_node node-c "$NODE_C_DNS_PORT" "$NODE_C_API_PORT" "$NODE_C_SOCKET"
	token_c="$(ctl "$NODE_A_SOCKET" cluster invite --usage-count 1 --ttl 15m --join-node-id node-c --sync-bind-host "$LOCAL_HOST" --resync-interval-s 2)"
	join_with_retry "$NODE_C_SOCKET" "$token_c" "$NODE_C_SYNC" --auto-accept >"${WORK_DIR}/node-c-join.out"
	assert_node_id "$NODE_C_SOCKET" "node-c"
	assert_peer "$NODE_C_SOCKET" "node-a" "$NODE_A_SYNC"
	assert_pending_count 0
	assert_peer "$NODE_A_SOCKET" "node-c" "$NODE_C_SYNC"

	log "waiting for auto-accepted node-c membership to replicate"
	local deadline=$((SECONDS + 60))
	while ((SECONDS < deadline)); do
		if has_peer "$NODE_B_SOCKET" "node-c" "$NODE_C_SYNC" &&
			has_peer "$NODE_C_SOCKET" "node-b" "$NODE_B_SYNC"; then
			break
		fi
		sleep 0.5
	done
	assert_peer "$NODE_B_SOCKET" "node-c" "$NODE_C_SYNC"
	assert_peer "$NODE_C_SOCKET" "node-b" "$NODE_B_SYNC"

	log "cluster onboarding integration passed"
}

main "$@"
