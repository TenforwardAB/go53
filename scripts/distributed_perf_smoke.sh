#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ID="${RUN_ID:-$(date +%Y%m%d%H%M%S)}"
WORK_DIR="${WORK_DIR:-/tmp/go53-dist-perf-${RUN_ID}}"
PROFILE="${PROFILE:-distributed}"
DURATION_SECONDS="${DURATION_SECONDS:-300}"
READ_WORKERS="${READ_WORKERS:-18}"
WRITE_WORKERS="${WRITE_WORKERS:-2}"
SETTLE_SECONDS="${SETTLE_SECONDS:-8}"
READ_TOOL="${READ_TOOL:-dig}"
DNSPERF_CLIENTS="${DNSPERF_CLIENTS:-50}"
DNSPERF_THREADS="${DNSPERF_THREADS:-4}"
DNSPERF_OUTSTANDING="${DNSPERF_OUTSTANDING:-500}"
DNSPERF_MAX_QPS="${DNSPERF_MAX_QPS:-0}"
DNSPERF_STATS_INTERVAL="${DNSPERF_STATS_INTERVAL:-10}"
ZONE="${ZONE:-perf.go53.test.}"
KEEP_TMP="${KEEP_TMP:-0}"

SERVER_BIN="${WORK_DIR}/go53-server"
CTL_BIN="${WORK_DIR}/go53ctl"
BUILD_GOCACHE="${GOCACHE:-/tmp/go53-gocache}"
BUILD_GOTMPDIR="${GOTMPDIR:-/tmp/go53-gotmp}"

NODE_A_DB="${WORK_DIR}/node-a-db"
NODE_B_DB="${WORK_DIR}/node-b-db"
NODE_A_API="http://127.0.0.1:18140"
NODE_B_API="http://127.0.0.1:18141"
NODE_A_DNS_PORT="15440"
NODE_B_DNS_PORT="15441"
NODE_A_SYNC_PORT="53540"
NODE_B_SYNC_PORT="53541"
NODE_A_SYNC="tls://127.0.0.1:${NODE_A_SYNC_PORT}"
NODE_B_SYNC="tls://127.0.0.1:${NODE_B_SYNC_PORT}"

PIDS=()

log() {
	printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"
}

need_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		printf 'missing required command: %s\n' "$1" >&2
		exit 1
	fi
}

cleanup() {
	for pid in "${PIDS[@]:-}"; do
		if kill -0 "$pid" >/dev/null 2>&1; then
			kill "$pid" >/dev/null 2>&1 || true
		fi
	done
	wait "${PIDS[@]:-}" 2>/dev/null || true
	if [[ "$KEEP_TMP" != "1" ]]; then
		rm -rf "$WORK_DIR"
	else
		log "kept work dir: $WORK_DIR"
	fi
}
trap cleanup EXIT INT TERM

api() {
	local method="$1"
	local url="$2"
	local body="${3:-}"
	if [[ -n "$body" ]]; then
		curl -fsS -X "$method" -H 'Content-Type: application/json' -d "$body" "$url"
	else
		curl -fsS -X "$method" "$url"
	fi
}

api_status_ok() {
	local method="$1"
	local url="$2"
	local body="${3:-}"
	local status
	status="$(curl -s -o /dev/null -w '%{http_code}' -X "$method" -H 'Content-Type: application/json' -d "$body" "$url" || true)"
	[[ "$status" == 2* ]]
}

wait_http() {
	local url="$1"
	local timeout="${2:-20}"
	local deadline=$((SECONDS + timeout))
	until curl -fsS "$url" >/dev/null 2>&1; do
		if (( SECONDS >= deadline )); then
			printf 'timeout waiting for %s\n' "$url" >&2
			return 1
		fi
		sleep 0.2
	done
}

wait_dns() {
	local port="$1"
	local timeout="${2:-20}"
	local deadline=$((SECONDS + timeout))
	until dig @"127.0.0.1" -p "$port" "$ZONE" SOA +time=1 +tries=1 +short >/dev/null 2>&1; do
		if (( SECONDS >= deadline )); then
			printf 'timeout waiting for DNS port %s\n' "$port" >&2
			return 1
		fi
		sleep 0.2
	done
}

start_node() {
	local name="$1"
	local db="$2"
	local dns_port="$3"
	local api_port="$4"
	local log_file="${WORK_DIR}/${name}.log"

	BADGER_DIR="$db" \
	BIND_HOST="127.0.0.1" \
	DNS_PORT=":${dns_port}" \
	API_PORT=":${api_port}" \
	STORAGE_BACKEND="badger" \
	"$SERVER_BIN" >"$log_file" 2>&1 &
	PIDS+=("$!")
	wait_http "http://127.0.0.1:${api_port}/api/config"
}

stop_all_nodes() {
	for pid in "${PIDS[@]:-}"; do
		if kill -0 "$pid" >/dev/null 2>&1; then
			kill "$pid" >/dev/null 2>&1 || true
		fi
	done
	wait "${PIDS[@]:-}" 2>/dev/null || true
	PIDS=()
}

json_field() {
	local field="$1"
	local json="$2"
	printf '%s' "$json" | sed -n "s/.*\"${field}\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p"
}

configure_distributed_node() {
	local api_base="$1"
	local node_id="$2"
	local sync_port="$3"
	local private_key="$4"

	api PATCH "${api_base}/api/config" "{
  \"mode\": \"distributed\",
  \"distributed\": {
    \"node_id\": \"${node_id}\",
    \"transport\": \"tls\",
    \"sync_bind_host\": \"127.0.0.1\",
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

configure_primary_readonly_node() {
	local api_base="$1"

	api PATCH "${api_base}/api/config" "{
  \"mode\": \"primary\",
  \"dnssec_enabled\": false,
  \"allow_recursion\": false,
  \"allow_axfr\": true,
  \"default_ttl\": 60,
  \"max_udp_size\": 1232,
  \"enable_edns\": true,
  \"primary\": {
    \"notify_debounce_ms\": 1000,
    \"ip\": \"127.0.0.1\",
    \"port\": 53
  }
}" >/dev/null
}

seed_zone() {
	local api_base="$1"
	api POST "${api_base}/api/zones/${ZONE}/records/SOA" \
		'{"ttl":60,"ns":"ns1.perf.go53.test.","mbox":"hostmaster.perf.go53.test.","refresh":3600,"retry":600,"expire":1209600,"minimum":60}' >/dev/null
	api POST "${api_base}/api/zones/${ZONE}/records/NS" \
		'{"name":"perf.go53.test.","ttl":60,"ns":"ns1.perf.go53.test."}' >/dev/null
	api POST "${api_base}/api/zones/${ZONE}/records/A" \
		'{"name":"ns1.perf.go53.test.","ttl":60,"ip":"192.0.2.53"}' >/dev/null
	for i in $(seq 1 100); do
		api POST "${api_base}/api/zones/${ZONE}/records/A" \
			"{\"name\":\"host-${i}.perf.go53.test.\",\"ttl\":60,\"ip\":\"192.0.2.$((i % 250 + 1))\"}" >/dev/null
	done
}

counter_file() {
	printf '%s/%s.count' "$WORK_DIR" "$1"
}

inc_counter() {
	local name="$1"
	printf '1\n' >>"$(counter_file "$name")"
}

read_worker() {
	local id="$1"
	local end_at="$2"
	local names=(perf.go53.test. ns1.perf.go53.test.)
	for i in $(seq 1 100); do
		names+=("host-${i}.perf.go53.test.")
	done
	while (( $(date +%s) < end_at )); do
		local name="${names[$((RANDOM % ${#names[@]}))]}"
		local rtype="A"
		(( RANDOM % 20 == 0 )) && rtype="SOA"
		local port="$NODE_A_DNS_PORT"
		(( RANDOM % 2 == 0 )) && port="$NODE_B_DNS_PORT"
		if dig @"127.0.0.1" -p "$port" "$name" "$rtype" +time=1 +tries=1 +short >/dev/null 2>&1; then
			inc_counter "read_ok_${id}"
		else
			inc_counter "read_fail_${id}"
		fi
	done
}

write_worker() {
	local id="$1"
	local end_at="$2"
	local seq=0
	while (( $(date +%s) < end_at )); do
		seq=$((seq + 1))
		local api_base="$NODE_A_API"
		(( RANDOM % 2 == 0 )) && api_base="$NODE_B_API"
		local suffix="w${id}-${seq}-${RANDOM}"
		local op=$((RANDOM % 5))
		local ok=0
		case "$op" in
			0)
				api_status_ok POST "${api_base}/api/zones/${ZONE}/records/A" \
					"{\"name\":\"${suffix}.perf.go53.test.\",\"ttl\":60,\"ip\":\"198.51.100.$((RANDOM % 250 + 1))\"}" >/dev/null && ok=1
				;;
			1)
				local hextet
				hextet="$(printf '%x' "$((RANDOM % 65535 + 1))")"
				api_status_ok POST "${api_base}/api/zones/${ZONE}/records/AAAA" \
					"{\"name\":\"${suffix}.perf.go53.test.\",\"ttl\":60,\"ip\":\"2001:db8::${hextet}\"}" >/dev/null && ok=1
				;;
			2)
				api_status_ok POST "${api_base}/api/zones/${ZONE}/records/TXT" \
					"{\"name\":\"txt-${suffix}.perf.go53.test.\",\"ttl\":60,\"text\":\"load-${suffix}\"}" >/dev/null && ok=1
				;;
			3)
				api_status_ok POST "${api_base}/api/zones/${ZONE}/records/MX" \
					"{\"name\":\"mx-${suffix}.perf.go53.test.\",\"ttl\":60,\"host\":\"mail-${suffix}.perf.go53.test.\",\"priority\":10}" >/dev/null && ok=1
				;;
			*)
				api_status_ok POST "${api_base}/api/zones/${ZONE}/records/CNAME" \
					"{\"name\":\"alias-${suffix}.perf.go53.test.\",\"ttl\":60,\"target\":\"host-$((RANDOM % 100 + 1)).perf.go53.test.\"}" >/dev/null && ok=1
				;;
		esac
		if (( ok == 1 )); then
			inc_counter "write_ok_${id}"
		else
			inc_counter "write_fail_${id}"
		fi
	done
}

write_queries_file() {
	local file="${WORK_DIR}/dnsperf-queries.txt"
	{
		printf '%s SOA\n' "$ZONE"
		printf '%s NS\n' "$ZONE"
		printf 'ns1.%s A\n' "$ZONE"
		for i in $(seq 1 100); do
			printf 'host-%s.%s A\n' "$i" "$ZONE"
		done
	} >"$file"
	printf '%s' "$file"
}

run_dnsperf_read_worker() {
	local id="$1"
	local port="$2"
	local queries_file="$3"
	local log_file="${WORK_DIR}/dnsperf-${id}.log"
	local args=(
		-s 127.0.0.1
		-p "$port"
		-d "$queries_file"
		-l "$DURATION_SECONDS"
		-c "$DNSPERF_CLIENTS"
		-T "$DNSPERF_THREADS"
		-q "$DNSPERF_OUTSTANDING"
		-S "$DNSPERF_STATS_INTERVAL"
		-t 2
	)
	if (( DNSPERF_MAX_QPS > 0 )); then
		args+=(-Q "$DNSPERF_MAX_QPS")
	fi
	dnsperf "${args[@]}" >"$log_file" 2>&1
}

dnsperf_metric() {
	local metric="$1"
	local total=0
	local value file
	for file in "$WORK_DIR"/dnsperf-*.log; do
		[[ -e "$file" ]] || continue
		value="$(sed -n "s/.*${metric}:[[:space:]]*\\([0-9][0-9]*\\).*/\\1/p" "$file" | tail -n 1)"
		[[ -n "$value" ]] || continue
		total=$((total + value))
	done
	printf '%s' "$total"
}

dnsperf_qps_total() {
	local total="0"
	local value file
	for file in "$WORK_DIR"/dnsperf-*.log; do
		[[ -e "$file" ]] || continue
		value="$(sed -n 's/.*Queries per second:[[:space:]]*\([0-9.][0-9.]*\).*/\1/p' "$file" | tail -n 1)"
		[[ -n "$value" ]] || continue
		total="$(awk -v a="$total" -v b="$value" 'BEGIN { printf "%.2f", a + b }')"
	done
	printf '%s' "$total"
}

sum_counters() {
	local pattern="$1"
	local total=0
	local file
	for file in "$WORK_DIR"/${pattern}.count; do
		[[ -e "$file" ]] || continue
		total=$((total + $(wc -l <"$file")))
	done
	printf '%s' "$total"
}

print_summary() {
	local elapsed="$1"
	local read_ok read_fail write_ok write_fail total_ok
	if [[ "$READ_TOOL" == "dnsperf" ]]; then
		read_ok="$(dnsperf_metric "Queries completed")"
		read_fail="$(dnsperf_metric "Queries lost")"
	else
		read_ok="$(sum_counters 'read_ok_*')"
		read_fail="$(sum_counters 'read_fail_*')"
	fi
	write_ok="$(sum_counters 'write_ok_*')"
	write_fail="$(sum_counters 'write_fail_*')"
	total_ok=$((read_ok + write_ok))

	printf '\nSummary\n'
	printf '  work dir:      %s\n' "$WORK_DIR"
	printf '  duration:      %ss\n' "$elapsed"
	printf '  reads ok/fail: %s/%s\n' "$read_ok" "$read_fail"
	printf '  writes ok/fail:%s/%s\n' "$write_ok" "$write_fail"
	if (( elapsed > 0 )); then
		printf '  ok ops/sec:    %s\n' "$((total_ok / elapsed))"
	fi
	if [[ "$READ_TOOL" == "dnsperf" ]]; then
		printf '  dnsperf qps:   %s\n' "$(dnsperf_qps_total)"
		printf '  dnsperf logs:  %s/dnsperf-*.log\n' "$WORK_DIR"
	fi
	if [[ "$PROFILE" == "distributed" ]]; then
		printf '\nDistributed status\n'
		curl -fsS "${NODE_A_API}/api/distributed/status" || true
		printf '\n'
		curl -fsS "${NODE_B_API}/api/distributed/status" || true
		printf '\n'
	fi
}

need_cmd go
need_cmd curl
need_cmd dig
need_cmd sed
if [[ "$READ_TOOL" == "dnsperf" ]]; then
	need_cmd dnsperf
fi
case "$PROFILE" in
distributed | udp-readonly) ;;
*)
	printf 'unknown PROFILE=%s; expected distributed or udp-readonly\n' "$PROFILE" >&2
	exit 1
	;;
esac
if [[ "$PROFILE" == "udp-readonly" ]]; then
	READ_TOOL="dnsperf"
	WRITE_WORKERS=0
	need_cmd dnsperf
fi

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR" "$BUILD_GOCACHE" "$BUILD_GOTMPDIR"

log "building server and go53ctl into $WORK_DIR"
GOCACHE="$BUILD_GOCACHE" GOTMPDIR="$BUILD_GOTMPDIR" go build -o "$SERVER_BIN" "$ROOT_DIR/cmd/server"
GOCACHE="$BUILD_GOCACHE" GOTMPDIR="$BUILD_GOTMPDIR" go build -o "$CTL_BIN" "$ROOT_DIR/tools/go53ctl.go"

if [[ "$PROFILE" == "udp-readonly" ]]; then
	log "starting node-a bootstrap for UDP read-only profile"
	start_node node-a "$NODE_A_DB" "$NODE_A_DNS_PORT" 18140
	configure_primary_readonly_node "$NODE_A_API"

	log "restarting node-a with primary DNSSEC-off config"
	stop_all_nodes
	start_node node-a "$NODE_A_DB" "$NODE_A_DNS_PORT" 18140
else
	log "starting node-a bootstrap"
	start_node node-a "$NODE_A_DB" "$NODE_A_DNS_PORT" 18140
	node_a_key_json="$(api POST "${NODE_A_API}/api/distributed/keypair")"
	node_a_private_key="$(json_field private_key "$node_a_key_json")"
	configure_distributed_node "$NODE_A_API" "node-a" "$NODE_A_SYNC_PORT" "$node_a_private_key"

	log "restarting node-a with distributed listener"
	stop_all_nodes
	start_node node-a "$NODE_A_DB" "$NODE_A_DNS_PORT" 18140
	wait_http "${NODE_A_API}/.well-known/go53-node.json"

	log "starting node-b bootstrap"
	start_node node-b "$NODE_B_DB" "$NODE_B_DNS_PORT" 18141

	log "creating one-use invite and joining node-b"
	invite_token="$("$CTL_BIN" cluster invite --api "$NODE_A_API" --usage-count 1 --ttl 15m --sync-bind-host 127.0.0.1 --resync-interval-s 5)"
	"$CTL_BIN" cluster join --token "$invite_token" --api "$NODE_B_API" --sync-endpoint "$NODE_B_SYNC"

	log "restarting both nodes after join config"
	stop_all_nodes
	start_node node-a "$NODE_A_DB" "$NODE_A_DNS_PORT" 18140
	start_node node-b "$NODE_B_DB" "$NODE_B_DNS_PORT" 18141
	wait_http "${NODE_A_API}/.well-known/go53-node.json"
	wait_http "${NODE_B_API}/.well-known/go53-node.json"
	log "waiting ${SETTLE_SECONDS}s for initial distributed resync"
	sleep "$SETTLE_SECONDS"
fi

log "seeding zone on node-a"
seed_zone "$NODE_A_API"
if [[ "$PROFILE" == "distributed" ]]; then
	log "waiting ${SETTLE_SECONDS}s for seeded zone replication"
	sleep "$SETTLE_SECONDS"
fi
wait_dns "$NODE_A_DNS_PORT"
if [[ "$PROFILE" == "distributed" ]]; then
	wait_dns "$NODE_B_DNS_PORT"
fi

log "running ${PROFILE} load for ${DURATION_SECONDS}s with read_tool=${READ_TOOL}, read_workers=${READ_WORKERS}, write_workers=${WRITE_WORKERS}"
started_at="$(date +%s)"
end_at=$((started_at + DURATION_SECONDS))
LOAD_PIDS=()
if [[ "$READ_TOOL" == "dnsperf" ]]; then
	queries_file="$(write_queries_file)"
	run_dnsperf_read_worker node-a "$NODE_A_DNS_PORT" "$queries_file" &
	LOAD_PIDS+=("$!")
	if [[ "$PROFILE" == "distributed" ]]; then
		run_dnsperf_read_worker node-b "$NODE_B_DNS_PORT" "$queries_file" &
		LOAD_PIDS+=("$!")
	fi
else
	for id in $(seq 1 "$READ_WORKERS"); do
		read_worker "$id" "$end_at" &
		LOAD_PIDS+=("$!")
	done
fi
for id in $(seq 1 "$WRITE_WORKERS"); do
	write_worker "$id" "$end_at" &
	LOAD_PIDS+=("$!")
done
wait "${LOAD_PIDS[@]}"
elapsed=$(($(date +%s) - started_at))

print_summary "$elapsed"
