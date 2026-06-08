#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_ROOT="${TMPDIR:-/tmp}/go53-bind-catalog.$$"
BIN_DIR="$TMP_ROOT/bin"
SERVER_BIN="$BIN_DIR/go53-server"
CTL_BIN="$BIN_DIR/go53ctl"

BIND_IMAGE="${BIND_IMAGE:-docker.io/internetsystemsconsortium/bind9:9.18}"
PODMAN_BIN="${PODMAN_BIN:-podman}"
SERVER_ADDR="${SERVER_ADDR:-127.0.0.1}"
PULL_IMAGE="${PULL_IMAGE:-missing}"

BASE_PORT="${BASE_PORT:-$((20000 + ($$ % 20000)))}"
BIND_PRIMARY_PORT="${BIND_PRIMARY_PORT:-$BASE_PORT}"
GO53_SECONDARY_DNS_PORT="${GO53_SECONDARY_DNS_PORT:-$((BASE_PORT + 1))}"
GO53_SECONDARY_API_PORT="${GO53_SECONDARY_API_PORT:-$((BASE_PORT + 2))}"
GO53_PRIMARY_DNS_PORT="${GO53_PRIMARY_DNS_PORT:-$((BASE_PORT + 3))}"
GO53_PRIMARY_API_PORT="${GO53_PRIMARY_API_PORT:-$((BASE_PORT + 4))}"
BIND_SECONDARY_PORT="${BIND_SECONDARY_PORT:-$((BASE_PORT + 5))}"

CATALOG_ZONE="${CATALOG_ZONE:-catalog.go53.}"
MEMBER_A_ZONE="${MEMBER_A_ZONE:-catalog-member-a.test.}"
MEMBER_B_ZONE="${MEMBER_B_ZONE:-catalog-member-b.test.}"
BIND_PRIMARY_CONTAINER="${BIND_PRIMARY_CONTAINER:-go53-bind-catalog-primary-$$}"
BIND_SECONDARY_CONTAINER="${BIND_SECONDARY_CONTAINER:-go53-bind-catalog-secondary-$$}"

SERVER_PID=""
CURRENT_SOCKET="$TMP_ROOT/go53-secondary/admin.sock"
CURRENT_LOG="$TMP_ROOT/go53-secondary/go53.log"

cleanup() {
	if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	if command -v "$PODMAN_BIN" >/dev/null 2>&1; then
		"$PODMAN_BIN" rm -f "$BIND_PRIMARY_CONTAINER" "$BIND_SECONDARY_CONTAINER" >/dev/null 2>&1 || true
	fi
	if [[ -n "${KEEP_TMP:-}" ]]; then
		echo "KEEP_TMP set; preserving $TMP_ROOT" >&2
	else
		rm -rf "$TMP_ROOT"
	fi
}
trap cleanup EXIT

fail() {
	echo "ERROR: $*" >&2
	if [[ -f "$CURRENT_LOG" ]]; then
		echo "--- go53 log tail ($CURRENT_LOG) ---" >&2
		tail -100 "$CURRENT_LOG" >&2 || true
	fi
	for container in "$BIND_PRIMARY_CONTAINER" "$BIND_SECONDARY_CONTAINER"; do
		if "$PODMAN_BIN" ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "$container"; then
			echo "--- BIND log tail ($container) ---" >&2
			"$PODMAN_BIN" logs "$container" 2>&1 | tail -100 >&2 || true
		fi
	done
	exit 1
}

need_cmd() {
	command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

api() {
	"$CTL_BIN" api --socket "$CURRENT_SOCKET" "$@"
}

bind_exec() {
	local container="$1"
	shift
	"$PODMAN_BIN" exec "$container" "$@"
}

wait_for_socket() {
	local deadline=$((SECONDS + 20))
	while ((SECONDS < deadline)); do
		if [[ -S "$CURRENT_SOCKET" ]] && api GET /api/config >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.2
	done
	fail "go53 did not expose admin socket: $CURRENT_SOCKET"
}

wait_for_dns() {
	local port="$1"
	local container="${2:-$BIND_PRIMARY_CONTAINER}"
	local deadline=$((SECONDS + 30))
	while ((SECONDS < deadline)); do
		if bind_exec "$container" dig @"$SERVER_ADDR" -p "$port" version.bind TXT CH +time=1 +tries=1 +short >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.2
	done
	fail "DNS service did not answer on $SERVER_ADDR:$port"
}

wait_for_record() {
	local port="$1"
	local name="$2"
	local rrtype="$3"
	local want_pattern="$4"
	local container="${5:-$BIND_PRIMARY_CONTAINER}"
	local deadline=$((SECONDS + 45))
	local output
	while ((SECONDS < deadline)); do
		output="$(bind_exec "$container" dig @"$SERVER_ADDR" -p "$port" "$name" "$rrtype" +time=1 +tries=1 +noall +answer 2>/dev/null || true)"
		if grep -Eq "$want_pattern" <<<"$output"; then
			return 0
		fi
		sleep 0.5
	done
	fail "did not observe $rrtype $name on $SERVER_ADDR:$port; last output: $output"
}

wait_for_absent_record() {
	local port="$1"
	local name="$2"
	local rrtype="$3"
	local container="${4:-$BIND_PRIMARY_CONTAINER}"
	local deadline=$((SECONDS + 45))
	local output
	while ((SECONDS < deadline)); do
		output="$(bind_exec "$container" dig @"$SERVER_ADDR" -p "$port" "$name" "$rrtype" +time=1 +tries=1 +noall +answer 2>/dev/null || true)"
		if [[ -z "$output" ]]; then
			return 0
		fi
		sleep 0.5
	done
	fail "still observed $rrtype $name on $SERVER_ADDR:$port; last output: $output"
}

soa_serial() {
	local port="$1"
	local zone="$2"
	local container="${3:-$BIND_PRIMARY_CONTAINER}"
	bind_exec "$container" dig @"$SERVER_ADDR" -p "$port" "$zone" SOA +short +time=1 +tries=1 2>/dev/null | awk 'NR==1{print $3}'
}

build_go53() {
	mkdir -p "$BIN_DIR"
	echo "building local go53 server and go53ctl"
	(
		cd "$ROOT_DIR"
		GOCACHE="$TMP_ROOT/gocache" go build -o "$SERVER_BIN" ./cmd/server
		GOCACHE="$TMP_ROOT/gocache" go build -o "$CTL_BIN" ./cmd/go53ctl
	)
}

write_bind_config() {
	local dir="$TMP_ROOT/bind-primary"
	mkdir -p "$dir/cache" "$dir/zones"
	cat >"$dir/named.conf" <<EOF
options {
	directory "/work/bind-primary/cache";
	listen-on port $BIND_PRIMARY_PORT { 127.0.0.1; };
	listen-on-v6 { none; };
	recursion no;
	dnssec-validation no;
	notify yes;
};
zone "$CATALOG_ZONE" {
	type primary;
	file "/work/bind-primary/zones/db.catalog";
	allow-transfer { 127.0.0.1; };
	also-notify { 127.0.0.1 port $GO53_SECONDARY_DNS_PORT; };
};
zone "$MEMBER_A_ZONE" {
	type primary;
	file "/work/bind-primary/zones/db.member-a";
	allow-transfer { 127.0.0.1; };
	notify no;
};
zone "$MEMBER_B_ZONE" {
	type primary;
	file "/work/bind-primary/zones/db.member-b";
	allow-transfer { 127.0.0.1; };
	notify no;
};
EOF
	write_catalog_zone 1 "$MEMBER_A_ZONE"
	write_member_zone "$dir/zones/db.member-a" "$MEMBER_A_ZONE" 1 192.0.2.101
	write_member_zone "$dir/zones/db.member-b" "$MEMBER_B_ZONE" 1 192.0.2.102
}

write_catalog_zone() {
	local serial="$1"
	shift
	local dir="$TMP_ROOT/bind-primary"
	cat >"$dir/zones/db.catalog" <<EOF
\$TTL 300
@ IN SOA ns1.$CATALOG_ZONE hostmaster.$CATALOG_ZONE (
	$serial 3600 600 86400 300 )
@ IN NS invalid.
version IN TXT "2"
EOF
	local i=1
	local member
	for member in "$@"; do
		printf 'm%s.zones IN PTR %s\n' "$i" "$member" >>"$dir/zones/db.catalog"
		i=$((i + 1))
	done
}

write_member_zone() {
	local path="$1"
	local zone="$2"
	local serial="$3"
	local ip="$4"
	cat >"$path" <<EOF
\$TTL 300
@ IN SOA ns1.$zone hostmaster.$zone (
	$serial 3600 600 86400 300 )
@ IN NS ns1.$zone
ns1 IN A 192.0.2.53
www IN A $ip
txt IN TXT "BIND catalog member $zone"
EOF
}

start_bind() {
	"$PODMAN_BIN" rm -f "$BIND_PRIMARY_CONTAINER" >/dev/null 2>&1 || true
	"$PODMAN_BIN" run \
		--rm \
		--detach \
		--name "$BIND_PRIMARY_CONTAINER" \
		--network host \
		--pull "$PULL_IMAGE" \
		--volume "$TMP_ROOT:/work" \
		--entrypoint /bin/sh \
		"$BIND_IMAGE" \
		-lc "named -g -c '/work/bind-primary/named.conf'" >/dev/null
	bind_exec "$BIND_PRIMARY_CONTAINER" /bin/sh -lc 'command -v dig >/dev/null && command -v named-checkzone >/dev/null' \
		|| fail "BIND container does not provide dig and named-checkzone"
	wait_for_dns "$BIND_PRIMARY_PORT"
}

start_go53_secondary() {
	local badger="$TMP_ROOT/go53-secondary/badger"
	CURRENT_SOCKET="$TMP_ROOT/go53-secondary/admin.sock"
	CURRENT_LOG="$TMP_ROOT/go53-secondary/go53.log"
	mkdir -p "$(dirname "$CURRENT_SOCKET")" "$badger"
	(
		cd "$ROOT_DIR"
		exec env BIND_HOST="$SERVER_ADDR" \
			DNS_PORT=":$GO53_SECONDARY_DNS_PORT" \
			API_PORT=":$GO53_SECONDARY_API_PORT" \
			BADGER_DIR="$badger" \
			ADMIN_SOCKET="$CURRENT_SOCKET" \
			ADMIN_SOCKET_GROUP="" \
			"$SERVER_BIN" >"$CURRENT_LOG" 2>&1
	) &
	SERVER_PID=$!
	wait_for_socket
	wait_for_dns "$GO53_SECONDARY_DNS_PORT"
}

stop_go53() {
	if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	SERVER_PID=""
}

start_go53_primary() {
	local badger="$TMP_ROOT/go53-primary/badger"
	CURRENT_SOCKET="$TMP_ROOT/go53-primary/admin.sock"
	CURRENT_LOG="$TMP_ROOT/go53-primary/go53.log"
	mkdir -p "$(dirname "$CURRENT_SOCKET")" "$badger"
	(
		cd "$ROOT_DIR"
		exec env BIND_HOST="$SERVER_ADDR" \
			DNS_PORT=":$GO53_PRIMARY_DNS_PORT" \
			API_PORT=":$GO53_PRIMARY_API_PORT" \
			BADGER_DIR="$badger" \
			ADMIN_SOCKET="$CURRENT_SOCKET" \
			ADMIN_SOCKET_GROUP="" \
			"$SERVER_BIN" >"$CURRENT_LOG" 2>&1
	) &
	SERVER_PID=$!
	wait_for_socket
	wait_for_dns "$GO53_PRIMARY_DNS_PORT" "$BIND_PRIMARY_CONTAINER"
}

configure_go53_secondary() {
	api PATCH /api/config "$(jq -nc \
		--arg ip "$SERVER_ADDR" \
		--arg catalog "$CATALOG_ZONE" \
		--argjson port "$BIND_PRIMARY_PORT" \
		'{mode:"secondary",allow_axfr:true,dnssec_enabled:false,enforce_tsig:false,
		  primary:{ip:$ip,port:$port},
		  secondary:{catalog_enabled:true,catalog_zone:$catalog,zones:[],
		             min_fetch_interval_sec:0,max_parallel_fetches:2,
		             refresh_interval_sec:5,refresh_jitter_sec:0}}')" >/dev/null \
		|| fail "failed to configure go53 secondary"
}

assert_go53_secondary_config() {
	local cfg
	cfg="$(api GET /api/config)"
	jq -e \
		--arg catalog "$CATALOG_ZONE" \
		--argjson port "$BIND_PRIMARY_PORT" \
		'.mode == "secondary"
		 and .primary.port == $port
		 and .secondary.catalog_enabled == true
		 and .secondary.catalog_zone == $catalog' <<<"$cfg" >/dev/null \
		|| fail "go53 secondary did not reload persisted catalog config: $cfg"
}

reload_bind() {
	bind_exec "$BIND_PRIMARY_CONTAINER" /bin/sh -lc 'kill -HUP "$(pidof named)"' >/dev/null 2>&1 || true
}

api_add_record() {
	local zone="$1"
	local rrtype="$2"
	local payload="$3"
	local output
	output="$(api POST "/api/zones/$zone/records/$rrtype" "$payload" 2>&1)" \
		|| fail "failed to add $rrtype to $zone with $payload; output: $output"
}

create_go53_catalog_primary_zone() {
	api PATCH /api/config "$(jq -nc \
		--arg allow "127.0.0.1,$SERVER_ADDR:$BIND_SECONDARY_PORT" \
		--arg catalog "$CATALOG_ZONE" \
		'{mode:"primary",allow_axfr:true,allow_transfer:$allow,dnssec_enabled:false,
		  enforce_tsig:false,default_ttl:300,primary:{notify_debounce_ms:100},
		  secondary:{catalog_enabled:true,catalog_zone:$catalog}}')" >/dev/null \
		|| fail "failed to configure go53 catalog primary"
	api_add_record "$MEMBER_A_ZONE" SOA "$(jq -nc --arg zone "$MEMBER_A_ZONE" '{ttl:300,ns:("ns1."+$zone),mbox:("hostmaster."+$zone),serial:1,refresh:3600,retry:600,expire:86400,minimum:300}')"
	api_add_record "$MEMBER_A_ZONE" NS "$(jq -nc --arg zone "$MEMBER_A_ZONE" '{name:"@",ttl:300,ns:("ns1."+$zone)}')"
	api_add_record "$MEMBER_A_ZONE" A '{"name":"ns1","ttl":300,"ip":"192.0.2.53"}'
	api_add_record "$MEMBER_A_ZONE" A '{"name":"www","ttl":300,"ip":"192.0.2.111"}'
	api_add_record "$MEMBER_A_ZONE" TXT '{"name":"txt","ttl":300,"text":"go53 catalog primary member"}'
}

write_bind_catalog_secondary_config() {
	local dir="$TMP_ROOT/bind-secondary"
	mkdir -p "$dir/cache" "$dir/zones"
	cat >"$dir/named.conf" <<EOF
options {
	directory "/work/bind-secondary/cache";
	listen-on port $BIND_SECONDARY_PORT { 127.0.0.1; };
	listen-on-v6 { none; };
	recursion no;
	dnssec-validation no;
	notify no;
catalog-zones {
	zone "$CATALOG_ZONE" default-primaries { 127.0.0.1 port $GO53_PRIMARY_DNS_PORT; };
};
};
zone "$CATALOG_ZONE" {
	type secondary;
	file "/work/bind-secondary/zones/db.catalog";
	primaries { 127.0.0.1 port $GO53_PRIMARY_DNS_PORT; };
};
EOF
}

start_bind_secondary() {
	"$PODMAN_BIN" rm -f "$BIND_SECONDARY_CONTAINER" >/dev/null 2>&1 || true
	"$PODMAN_BIN" run \
		--detach \
		--name "$BIND_SECONDARY_CONTAINER" \
		--network host \
		--pull "$PULL_IMAGE" \
		--volume "$TMP_ROOT:/work" \
		--entrypoint /bin/sh \
		"$BIND_IMAGE" \
		-lc "named -g -c '/work/bind-secondary/named.conf'" >/dev/null
	bind_exec "$BIND_SECONDARY_CONTAINER" /bin/sh -lc 'command -v dig >/dev/null && command -v named-checkconf >/dev/null' \
		|| fail "BIND secondary container does not provide dig and named-checkconf"
	wait_for_dns "$BIND_SECONDARY_PORT" "$BIND_SECONDARY_CONTAINER"
}

main() {
	need_cmd go
	need_cmd jq
	need_cmd "$PODMAN_BIN"

	mkdir -p "$TMP_ROOT"
	build_go53
	write_bind_config
	start_bind
	wait_for_record "$BIND_PRIMARY_PORT" "www.$MEMBER_A_ZONE" A "192\\.0\\.2\\.101"

	echo "== BIND catalog primary -> go53 secondary =="
	start_go53_secondary
	configure_go53_secondary
	# Restart after persisted secondary config so startup sweep exercises the catalog bootstrap.
	kill "$SERVER_PID" 2>/dev/null || true
	wait "$SERVER_PID" 2>/dev/null || true
	SERVER_PID=""
	start_go53_secondary
	assert_go53_secondary_config

	CATALOG_SERIAL="$(soa_serial "$BIND_PRIMARY_PORT" "$CATALOG_ZONE")"
	MEMBER_A_SERIAL="$(soa_serial "$BIND_PRIMARY_PORT" "$MEMBER_A_ZONE")"
	wait_for_record "$GO53_SECONDARY_DNS_PORT" "$CATALOG_ZONE" SOA "$CATALOG_SERIAL"
	wait_for_record "$GO53_SECONDARY_DNS_PORT" "www.$MEMBER_A_ZONE" A "192\\.0\\.2\\.101"
	echo "[A] ok: go53 fetched catalog $CATALOG_ZONE and member $MEMBER_A_ZONE"

	write_catalog_zone 2 "$MEMBER_A_ZONE" "$MEMBER_B_ZONE"
	reload_bind
	wait_for_record "$BIND_PRIMARY_PORT" "www.$MEMBER_B_ZONE" A "192\\.0\\.2\\.102"
	wait_for_record "$GO53_SECONDARY_DNS_PORT" "www.$MEMBER_B_ZONE" A "192\\.0\\.2\\.102"
	wait_for_record "$GO53_SECONDARY_DNS_PORT" "$MEMBER_A_ZONE" SOA "$MEMBER_A_SERIAL"
	echo "[B] ok: go53 discovered new member $MEMBER_B_ZONE from refreshed BIND catalog"

	write_catalog_zone 3 "$MEMBER_B_ZONE"
	reload_bind
	wait_for_absent_record "$GO53_SECONDARY_DNS_PORT" "www.$MEMBER_A_ZONE" A
	wait_for_record "$GO53_SECONDARY_DNS_PORT" "www.$MEMBER_B_ZONE" A "192\\.0\\.2\\.102"
	echo "[C] ok: go53 deleted removed catalog member $MEMBER_A_ZONE"

	stop_go53

	echo "== go53 catalog primary -> BIND secondary =="
	start_go53_primary
	create_go53_catalog_primary_zone
	write_bind_catalog_secondary_config
	start_bind_secondary
	CATALOG_SERIAL="$(soa_serial "$GO53_PRIMARY_DNS_PORT" "$CATALOG_ZONE")"
	wait_for_record "$BIND_SECONDARY_PORT" "$CATALOG_ZONE" SOA "$CATALOG_SERIAL" "$BIND_SECONDARY_CONTAINER"
	wait_for_record "$BIND_SECONDARY_PORT" "www.$MEMBER_A_ZONE" A "192\\.0\\.2\\.111" "$BIND_SECONDARY_CONTAINER"
	wait_for_record "$BIND_SECONDARY_PORT" "txt.$MEMBER_A_ZONE" TXT "go53 catalog primary member" "$BIND_SECONDARY_CONTAINER"
	echo "[D] ok: BIND fetched go53 catalog $CATALOG_ZONE and member $MEMBER_A_ZONE"

	echo "BIND/go53 catalog interop checks passed"
}

main "$@"
