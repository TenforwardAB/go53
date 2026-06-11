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
BOOTSTRAP_ZONE="bootstrap-onboarding.test."

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
		'{mode:"distributed", allow_axfr:true, dnssec_enabled:true,
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

add_record() {
	local socket="$1"
	local zone="$2"
	local rrtype="$3"
	local body="$4"
	ctl "$socket" records add "$zone" "$rrtype" "$body" >/dev/null
}

record_exists() {
	local socket="$1"
	local zone="$2"
	local rrtype="$3"
	local name="$4"
	ctl "$socket" records get "$zone" "$rrtype" "$name" >/dev/null 2>&1
}

wait_for_record() {
	local socket="$1"
	local zone="$2"
	local rrtype="$3"
	local name="$4"
	local deadline=$((SECONDS + 60))
	while ((SECONDS < deadline)); do
		if record_exists "$socket" "$zone" "$rrtype" "$name"; then
			return 0
		fi
		sleep 0.5
	done
	fail "$socket did not receive $rrtype $name in $zone"
}

wait_for_dns_answer() {
	local port="$1"
	local name="$2"
	local rrtype="$3"
	local pattern="$4"
	local deadline=$((SECONDS + 60))
	local out=""
	while ((SECONDS < deadline)); do
		out="$(dig @"$LOCAL_HOST" -p "$port" "$name" "$rrtype" +time=1 +tries=1 +short 2>/dev/null || true)"
		if grep -Eq "$pattern" <<<"$out"; then
			return 0
		fi
		sleep 0.5
	done
	fail "DNS ${LOCAL_HOST}:${port} did not answer $rrtype $name with $pattern; output: $out"
}

wait_for_dns_rrsig() {
	local port="$1"
	local name="$2"
	local rrtype="$3"
	local deadline=$((SECONDS + 60))
	local out=""
	while ((SECONDS < deadline)); do
		out="$(dig @"$LOCAL_HOST" -p "$port" "$name" "$rrtype" +dnssec +time=1 +tries=1 +noall +answer 2>/dev/null || true)"
		if grep -Eq "[[:space:]]RRSIG[[:space:]]+$rrtype[[:space:]]" <<<"$out"; then
			return 0
		fi
		sleep 0.5
	done
	fail "DNS ${LOCAL_HOST}:${port} did not return RRSIG($rrtype) for $name; output: $out"
}

assert_dnssec_keys() {
	local socket="$1"
	local zone="$2"
	local zone_nodot="${zone%.}"
	local keys
	keys="$(ctl "$socket" dnskeys list)"
	jq -e --arg zone "$zone" --arg zone_nodot "$zone_nodot" '[.[] | select((.zone == $zone or .zone == $zone_nodot) and .flags == 257)] | length >= 1' <<<"$keys" >/dev/null \
		|| fail "$socket does not have KSK for $zone"
	jq -e --arg zone "$zone" --arg zone_nodot "$zone_nodot" '[.[] | select((.zone == $zone or .zone == $zone_nodot) and .flags == 256)] | length >= 1' <<<"$keys" >/dev/null \
		|| fail "$socket does not have ZSK for $zone"
	jq -e --arg zone "$zone" --arg zone_nodot "$zone_nodot" '[.[] | select((.zone == $zone or .zone == $zone_nodot) and (.private_pem // "") != "")] | length >= 2' <<<"$keys" >/dev/null \
		|| fail "$socket does not have private DNSSEC key material for $zone"
}

create_bootstrap_zone() {
	local zone="$BOOTSTRAP_ZONE"
	local ksk_key zsk_key
	log "creating pre-existing signed bootstrap zone on node-a"
	add_record "$NODE_A_SOCKET" "$zone" SOA '{"ttl":300,"ns":"ns1.bootstrap-onboarding.test.","mbox":"hostmaster.bootstrap-onboarding.test.","refresh":3600,"retry":600,"expire":86400,"minimum":300}'
	ksk_key="$(ctl "$NODE_A_SOCKET" dnskeys rollover "$zone" ksk ED25519 | jq -r '.keyid')"
	zsk_key="$(ctl "$NODE_A_SOCKET" dnskeys rollover "$zone" zsk ED25519 | jq -r '.keyid')"
	[[ -n "$ksk_key" && "$ksk_key" != "null" ]] || fail "could not create bootstrap KSK"
	[[ -n "$zsk_key" && "$zsk_key" != "null" ]] || fail "could not create bootstrap ZSK"
	add_record "$NODE_A_SOCKET" "$zone" DNSKEY "{\"keyid\":\"$ksk_key\",\"ttl\":300}"
	add_record "$NODE_A_SOCKET" "$zone" DNSKEY "{\"keyid\":\"$zsk_key\",\"ttl\":300}"
	add_record "$NODE_A_SOCKET" "$zone" NS '{"name":"@","ttl":300,"ns":"ns1.bootstrap-onboarding.test."}'
	add_record "$NODE_A_SOCKET" "$zone" A '{"name":"ns1","ttl":300,"ip":"192.0.2.10"}'
	add_record "$NODE_A_SOCKET" "$zone" A '{"name":"www","ttl":300,"ip":"192.0.2.20"}'
	add_record "$NODE_A_SOCKET" "$zone" AAAA '{"name":"www","ttl":300,"ip":"2001:db8::20"}'
	add_record "$NODE_A_SOCKET" "$zone" CNAME '{"name":"alias","ttl":300,"target":"www.bootstrap-onboarding.test."}'
	add_record "$NODE_A_SOCKET" "$zone" MX '{"name":"@","ttl":300,"host":"mail.bootstrap-onboarding.test.","priority":10}'
	add_record "$NODE_A_SOCKET" "$zone" TXT '{"name":"txt","ttl":300,"text":"cluster onboarding txt"}'
	add_record "$NODE_A_SOCKET" "$zone" SPF '{"name":"spf","ttl":300,"text":"v=spf1 -all"}'
	add_record "$NODE_A_SOCKET" "$zone" SRV '{"name":"_sip._tcp","ttl":300,"priority":10,"weight":5,"port":5060,"target":"sip.bootstrap-onboarding.test."}'
	add_record "$NODE_A_SOCKET" "$zone" PTR '{"name":"ptr","ttl":300,"ptr":"www.bootstrap-onboarding.test."}'
	assert_bootstrap_zone "$NODE_A_SOCKET" "$NODE_A_DNS_PORT"
}

assert_bootstrap_zone() {
	local socket="$1"
	local port="$2"
	local zone="$BOOTSTRAP_ZONE"
	wait_for_record "$socket" "$zone" SOA "$zone"
	wait_for_record "$socket" "$zone" NS "$zone"
	wait_for_record "$socket" "$zone" DNSKEY "$zone"
	wait_for_record "$socket" "$zone" A "www.$zone"
	wait_for_record "$socket" "$zone" AAAA "www.$zone"
	wait_for_record "$socket" "$zone" CNAME "alias.$zone"
	wait_for_record "$socket" "$zone" MX "$zone"
	wait_for_record "$socket" "$zone" TXT "txt.$zone"
	wait_for_record "$socket" "$zone" SPF "spf.$zone"
	wait_for_record "$socket" "$zone" SRV "_sip._tcp.$zone"
	wait_for_record "$socket" "$zone" PTR "ptr.$zone"
	assert_dnssec_keys "$socket" "$zone"
	wait_for_dns_answer "$port" "$zone" SOA "ns1\\.bootstrap-onboarding\\.test\\."
	wait_for_dns_answer "$port" "www.$zone" A "192\\.0\\.2\\.20"
	wait_for_dns_answer "$port" "alias.$zone" CNAME "www\\.bootstrap-onboarding\\.test\\."
	wait_for_dns_answer "$port" "_sip._tcp.$zone" SRV "5060[[:space:]]+sip\\.bootstrap-onboarding\\.test\\."
	wait_for_dns_answer "$port" "$zone" DNSKEY "257|256"
	wait_for_dns_rrsig "$port" "www.$zone" A
}

add_live_cluster_record() {
	local zone="$BOOTSTRAP_ZONE"
	log "adding post-join record on node-a"
	add_record "$NODE_A_SOCKET" "$zone" A '{"name":"after-join","ttl":300,"ip":"192.0.2.55"}'
	wait_for_record "$NODE_A_SOCKET" "$zone" A "after-join.$zone"
	wait_for_record "$NODE_B_SOCKET" "$zone" A "after-join.$zone"
	wait_for_record "$NODE_C_SOCKET" "$zone" A "after-join.$zone"
	wait_for_dns_answer "$NODE_B_DNS_PORT" "after-join.$zone" A "192\\.0\\.2\\.55"
	wait_for_dns_answer "$NODE_C_DNS_PORT" "after-join.$zone" A "192\\.0\\.2\\.55"
}

assert_pending_count() {
	local expected="$1"
	local got
	got="$(ctl "$NODE_A_SOCKET" cluster pending | jq 'length')"
	[[ "$got" == "$expected" ]] || fail "pending count = $got, want $expected"
}

get_xauth_key() {
	local socket="$1"
	ctl "$socket" config get xauth_key | jq -r '.x_auth_key // ""'
}

generate_xauth_key() {
	# Prints the freshly generated key on stdout.
	local socket="$1"
	ctl "$socket" config set xauth_key --generate
}

set_auth_sync() {
	local socket="$1"
	local value="$2" # true|false
	ctl "$socket" config patch "{\"distributed\":{\"auth_sync\":$value}}" >/dev/null
}

wait_for_xauth_key() {
	local socket="$1"
	local expected="$2"
	local deadline=$((SECONDS + 30))
	while ((SECONDS < deadline)); do
		[[ "$(get_xauth_key "$socket")" == "$expected" ]] && return 0
		sleep 0.5
	done
	fail "$socket did not receive x-auth-key $expected (have: $(get_xauth_key "$socket"))"
}

assert_xauth_key() {
	local socket="$1"
	local expected="$2"
	local got
	got="$(get_xauth_key "$socket")"
	[[ "$got" == "$expected" ]] || fail "x-auth-key on $socket = $got, want $expected"
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
	create_bootstrap_zone

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
	assert_bootstrap_zone "$NODE_B_SOCKET" "$NODE_B_DNS_PORT"

	log "starting node-c and testing auto-accept join into existing cluster"
	start_node node-c "$NODE_C_DNS_PORT" "$NODE_C_API_PORT" "$NODE_C_SOCKET"
	token_c="$(ctl "$NODE_A_SOCKET" cluster invite --usage-count 1 --ttl 15m --join-node-id node-c --sync-bind-host "$LOCAL_HOST" --resync-interval-s 2 --auto-accept)"
	join_with_retry "$NODE_C_SOCKET" "$token_c" "$NODE_C_SYNC" >"${WORK_DIR}/node-c-join.out"
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
	assert_bootstrap_zone "$NODE_C_SOCKET" "$NODE_C_DNS_PORT"
	add_live_cluster_record

	local key1 key2 key3
	log "auth_sync default (true): x-auth-key replicates across the cluster"
	key1="$(generate_xauth_key "$NODE_A_SOCKET")"
	[[ -n "$key1" ]] || fail "could not generate x-auth-key on node-a"
	wait_for_xauth_key "$NODE_B_SOCKET" "$key1"
	wait_for_xauth_key "$NODE_C_SOCKET" "$key1"

	log "auth_sync=false: opted-out node-c keeps its local x-auth-key"
	set_auth_sync "$NODE_C_SOCKET" false
	key2="$(generate_xauth_key "$NODE_A_SOCKET")"
	[[ -n "$key2" && "$key2" != "$key1" ]] || fail "node-a did not rotate x-auth-key"
	wait_for_xauth_key "$NODE_B_SOCKET" "$key2"
	# node-c opted out: give replication time to (not) arrive, then confirm it still holds key1.
	sleep 3
	assert_xauth_key "$NODE_C_SOCKET" "$key1"

	log "auth_sync re-enabled (true): node-c resumes replication"
	set_auth_sync "$NODE_C_SOCKET" true
	key3="$(generate_xauth_key "$NODE_A_SOCKET")"
	[[ -n "$key3" && "$key3" != "$key2" ]] || fail "node-a did not rotate x-auth-key again"
	wait_for_xauth_key "$NODE_B_SOCKET" "$key3"
	wait_for_xauth_key "$NODE_C_SOCKET" "$key3"

	log "cluster onboarding integration passed"
}

main "$@"
