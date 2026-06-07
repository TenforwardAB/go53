#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_ROOT="${TMPDIR:-/tmp}/go53-bind-xfr.$$"
BIN_DIR="$TMP_ROOT/bin"
SERVER_BIN="$BIN_DIR/go53-server"
CTL_BIN="$BIN_DIR/go53ctl"

BIND_IMAGE="${BIND_IMAGE:-docker.io/internetsystemsconsortium/bind9:9.18}"
PODMAN_BIN="${PODMAN_BIN:-podman}"
SERVER_ADDR="${SERVER_ADDR:-127.0.0.1}"
PULL_IMAGE="${PULL_IMAGE:-missing}"

GO53_PRIMARY_DNS_PORT="${GO53_PRIMARY_DNS_PORT:-12253}"
GO53_PRIMARY_API_PORT="${GO53_PRIMARY_API_PORT:-18253}"
BIND_SECONDARY_PORT="${BIND_SECONDARY_PORT:-12254}"
BIND_PRIMARY_PORT="${BIND_PRIMARY_PORT:-12255}"
GO53_SECONDARY_DNS_PORT="${GO53_SECONDARY_DNS_PORT:-12256}"
GO53_SECONDARY_API_PORT="${GO53_SECONDARY_API_PORT:-18256}"

GO53_TO_BIND_ZONE="${GO53_TO_BIND_ZONE:-go53-to-bind.test.}"
BIND_TO_GO53_ZONE="${BIND_TO_GO53_ZONE:-bind-to-go53.test.}"
BIND_SECONDARY_CONTAINER="${BIND_SECONDARY_CONTAINER:-go53-bind-secondary-$$}"
BIND_PRIMARY_CONTAINER="${BIND_PRIMARY_CONTAINER:-go53-bind-primary-$$}"

SERVER_PID=""
CURRENT_SOCKET=""
CURRENT_LOG=""

cleanup() {
	if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	if command -v "$PODMAN_BIN" >/dev/null 2>&1; then
		"$PODMAN_BIN" rm -f "$BIND_SECONDARY_CONTAINER" "$BIND_PRIMARY_CONTAINER" >/dev/null 2>&1 || true
	fi
	rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

fail() {
	echo "ERROR: $*" >&2
	if [[ -n "${CURRENT_LOG:-}" && -f "$CURRENT_LOG" ]]; then
		echo "--- go53 log tail ($CURRENT_LOG) ---" >&2
		tail -100 "$CURRENT_LOG" >&2 || true
	fi
	for name in "$BIND_SECONDARY_CONTAINER" "$BIND_PRIMARY_CONTAINER"; do
		if "$PODMAN_BIN" ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "$name"; then
			echo "--- container log tail ($name) ---" >&2
			"$PODMAN_BIN" logs "$name" 2>&1 | tail -100 >&2 || true
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
	local container="${2:-}"
	local deadline=$((SECONDS + 30))
	while ((SECONDS < deadline)); do
		if [[ -n "$container" ]]; then
			if bind_exec "$container" dig @"$SERVER_ADDR" -p "$port" version.bind TXT CH +time=1 +tries=1 +short >/dev/null 2>&1; then
				return 0
			fi
		elif "$BIN_DIR/dnsnotify" --dig-check "$SERVER_ADDR:$port" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.2
	done
	fail "DNS service did not answer on $SERVER_ADDR:$port"
}

build_tools() {
	mkdir -p "$BIN_DIR"
	echo "building local go53 server, go53ctl, and notify helper"
	(
		cd "$ROOT_DIR"
		GOCACHE="$TMP_ROOT/gocache" go build -o "$SERVER_BIN" ./cmd/server
		GOCACHE="$TMP_ROOT/gocache" go build -o "$CTL_BIN" ./cmd/go53ctl
	)
	cat >"$TMP_ROOT/dnsnotify.go" <<'EOF'
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/miekg/dns"
)

func main() {
	digCheck := flag.String("dig-check", "", "send a CHAOS version.bind probe to host:port")
	server := flag.String("server", "", "target host:port")
	zone := flag.String("zone", "", "zone name for NOTIFY")
	flag.Parse()

	if *digCheck != "" {
		msg := new(dns.Msg)
		msg.SetQuestion("version.bind.", dns.TypeTXT)
		msg.Question[0].Qclass = dns.ClassCHAOS
		client := &dns.Client{Timeout: time.Second}
		if _, _, err := client.Exchange(msg, *digCheck); err != nil {
			os.Exit(1)
		}
		return
	}
	if *server == "" || *zone == "" {
		fmt.Fprintln(os.Stderr, "usage: dnsnotify --server host:port --zone zone.")
		os.Exit(2)
	}
	msg := new(dns.Msg)
	msg.SetNotify(dns.Fqdn(*zone))
	msg.RecursionDesired = false
	for _, netName := range []string{"udp", "tcp"} {
		client := &dns.Client{Net: netName, Timeout: 3 * time.Second}
		if _, _, err := client.Exchange(msg, *server); err == nil {
			return
		}
	}
	os.Exit(1)
}
EOF
	(cd "$ROOT_DIR" && GOCACHE="$TMP_ROOT/gocache" go build -o "$BIN_DIR/dnsnotify" "$TMP_ROOT/dnsnotify.go")
}

start_go53() {
	local label="$1"
	local dns_port="$2"
	local api_port="$3"
	local socket="$TMP_ROOT/$label/admin.sock"
	local badger="$TMP_ROOT/$label/badger"
	local log_file="$TMP_ROOT/$label/go53.log"

	if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	SERVER_PID=""
	CURRENT_SOCKET="$socket"
	CURRENT_LOG="$log_file"
	mkdir -p "$(dirname "$socket")" "$badger"

	(
		cd "$ROOT_DIR"
		BIND_HOST="$SERVER_ADDR" \
			DNS_PORT=":$dns_port" \
			API_PORT=":$api_port" \
			BADGER_DIR="$badger" \
			ADMIN_SOCKET="$socket" \
			ADMIN_SOCKET_GROUP="" \
			"$SERVER_BIN" >"$log_file" 2>&1
	) &
	SERVER_PID=$!

	wait_for_socket
	wait_for_dns "$dns_port"
}

stop_go53() {
	if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	SERVER_PID=""
	CURRENT_SOCKET=""
	CURRENT_LOG=""
}

api_add_record() {
	local zone="$1"
	local rrtype="$2"
	local payload="$3"
	local output
	output="$(api POST "/api/zones/$zone/records/$rrtype" "$payload" 2>&1)" \
		|| fail "failed to add $rrtype to $zone with $payload; output: $output"
}

create_go53_primary_zone() {
	local zone="$GO53_TO_BIND_ZONE"
	api PATCH /api/config "$(jq -nc --arg allow "127.0.0.1,$SERVER_ADDR:$BIND_SECONDARY_PORT" \
		'{mode:"primary",allow_axfr:true,allow_transfer:$allow,dnssec_enabled:true,default_ttl:300,primary:{notify_debounce_ms:250}}')" >/dev/null \
		|| fail "failed to configure go53 primary"
	api_add_record "$zone" SOA "$(jq -nc --arg zone "$zone" '{ttl:300,ns:("ns1."+$zone),mbox:("hostmaster."+$zone),serial:1,refresh:3600,retry:600,expire:86400,minimum:300}')"
	api_add_record "$zone" NS "$(jq -nc --arg zone "$zone" '{name:"@",ttl:300,ns:("ns1."+$zone)}')"
	api_add_record "$zone" A '{"name":"ns1","ttl":300,"ip":"192.0.2.53"}'
	api_add_record "$zone" A '{"name":"www","ttl":300,"ip":"192.0.2.80"}'
	api_add_record "$zone" TXT '{"name":"txt","ttl":300,"text":"go53 primary to bind secondary"}'
}

write_bind_secondary_config() {
	local dir="$TMP_ROOT/bind-secondary"
	mkdir -p "$dir/zones" "$dir/cache"
	cat >"$dir/named.conf" <<EOF
options {
	directory "/work/bind-secondary/cache";
	listen-on port $BIND_SECONDARY_PORT { 127.0.0.1; };
	listen-on-v6 { none; };
	recursion no;
	dnssec-validation no;
	notify no;
};
zone "$GO53_TO_BIND_ZONE" {
	type secondary;
	file "/work/bind-secondary/zones/db.go53-to-bind";
	primaries { 127.0.0.1 port $GO53_PRIMARY_DNS_PORT; };
};
EOF
}

start_bind_named() {
	local container="$1"
	local conf="$2"
	"$PODMAN_BIN" rm -f "$container" >/dev/null 2>&1 || true
	"$PODMAN_BIN" run \
		--rm \
		--detach \
		--name "$container" \
		--network host \
		--pull "$PULL_IMAGE" \
		--volume "$TMP_ROOT:/work" \
		--entrypoint /bin/sh \
		"$BIND_IMAGE" \
		-lc "named -g -c '$conf'" >/dev/null
}

wait_for_record() {
	local port="$1"
	local name="$2"
	local rrtype="$3"
	local container="$4"
	local want_pattern="$5"
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

verify_axfr_from() {
	local port="$1"
	local zone="$2"
	local container="$3"
	local output
	output="$(bind_exec "$container" dig @"$SERVER_ADDR" -p "$port" "$zone" AXFR +tcp +time=4 +tries=1)"
	grep -Eq "[[:space:]]SOA[[:space:]]" <<<"$output" || fail "AXFR from $port missing SOA; output: $output"
	grep -Eq "www\\.$zone[[:space:]].*[[:space:]]A[[:space:]]" <<<"$output" || fail "AXFR from $port missing www A; output: $output"
}

run_go53_primary_bind_secondary() {
	echo "== go53 primary -> BIND secondary =="
	start_go53 go53-primary "$GO53_PRIMARY_DNS_PORT" "$GO53_PRIMARY_API_PORT"
	create_go53_primary_zone

	write_bind_secondary_config
	start_bind_named "$BIND_SECONDARY_CONTAINER" "/work/bind-secondary/named.conf"
	wait_for_dns "$BIND_SECONDARY_PORT" "$BIND_SECONDARY_CONTAINER"
	verify_axfr_from "$GO53_PRIMARY_DNS_PORT" "$GO53_TO_BIND_ZONE" "$BIND_SECONDARY_CONTAINER"
	wait_for_record "$BIND_SECONDARY_PORT" "www.$GO53_TO_BIND_ZONE" A "$BIND_SECONDARY_CONTAINER" "192\\.0\\.2\\.80"
	wait_for_record "$BIND_SECONDARY_PORT" "txt.$GO53_TO_BIND_ZONE" TXT "$BIND_SECONDARY_CONTAINER" "go53 primary to bind secondary"
	verify_axfr_from "$BIND_SECONDARY_PORT" "$GO53_TO_BIND_ZONE" "$BIND_SECONDARY_CONTAINER"

	api_add_record "$GO53_TO_BIND_ZONE" A '{"name":"new","ttl":300,"ip":"192.0.2.81"}'
	"$BIN_DIR/dnsnotify" --server "$SERVER_ADDR:$BIND_SECONDARY_PORT" --zone "$GO53_TO_BIND_ZONE" \
		|| fail "manual NOTIFY from go53 primary side to BIND secondary failed"
	wait_for_record "$BIND_SECONDARY_PORT" "new.$GO53_TO_BIND_ZONE" A "$BIND_SECONDARY_CONTAINER" "192\\.0\\.2\\.81"
	stop_go53
	echo "[go53 primary -> BIND secondary] ok"
}

write_bind_primary_config() {
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
zone "$BIND_TO_GO53_ZONE" {
	type primary;
	file "/work/bind-primary/zones/db.bind-to-go53";
	allow-transfer { 127.0.0.1; };
	also-notify { 127.0.0.1 port $GO53_SECONDARY_DNS_PORT; };
};
EOF
	cat >"$dir/zones/db.bind-to-go53" <<EOF
\$TTL 300
@ IN SOA ns1.$BIND_TO_GO53_ZONE hostmaster.$BIND_TO_GO53_ZONE (
	1 3600 600 86400 300 )
@ IN NS ns1.$BIND_TO_GO53_ZONE
ns1 IN A 192.0.2.53
www IN A 192.0.2.90
txt IN TXT "bind primary to go53 secondary"
EOF
}

run_bind_primary_go53_secondary() {
	echo "== BIND primary -> go53 secondary =="
	write_bind_primary_config
	start_bind_named "$BIND_PRIMARY_CONTAINER" "/work/bind-primary/named.conf"
	wait_for_dns "$BIND_PRIMARY_PORT" "$BIND_PRIMARY_CONTAINER"
	wait_for_record "$BIND_PRIMARY_PORT" "www.$BIND_TO_GO53_ZONE" A "$BIND_PRIMARY_CONTAINER" "192\\.0\\.2\\.90"
	verify_axfr_from "$BIND_PRIMARY_PORT" "$BIND_TO_GO53_ZONE" "$BIND_PRIMARY_CONTAINER"

	start_go53 go53-secondary "$GO53_SECONDARY_DNS_PORT" "$GO53_SECONDARY_API_PORT"
	api PATCH /api/config "$(jq -nc --arg ip "$SERVER_ADDR" --argjson port "$BIND_PRIMARY_PORT" \
		'{mode:"secondary",dnssec_enabled:true,primary:{ip:$ip,port:$port},secondary:{fetch_debounce_ms:100,min_fetch_interval_sec:0,max_parallel_fetches:2}}')" >/dev/null \
		|| fail "failed to configure go53 secondary"
	"$BIN_DIR/dnsnotify" --server "$SERVER_ADDR:$GO53_SECONDARY_DNS_PORT" --zone "$BIND_TO_GO53_ZONE" \
		|| fail "NOTIFY to go53 secondary failed"
	wait_for_record "$GO53_SECONDARY_DNS_PORT" "www.$BIND_TO_GO53_ZONE" A "$BIND_PRIMARY_CONTAINER" "192\\.0\\.2\\.90"
	wait_for_record "$GO53_SECONDARY_DNS_PORT" "txt.$BIND_TO_GO53_ZONE" TXT "$BIND_PRIMARY_CONTAINER" "bind primary to go53 secondary"

	cat >"$TMP_ROOT/bind-primary/zones/db.bind-to-go53" <<EOF
\$TTL 300
@ IN SOA ns1.$BIND_TO_GO53_ZONE hostmaster.$BIND_TO_GO53_ZONE (
	2 3600 600 86400 300 )
@ IN NS ns1.$BIND_TO_GO53_ZONE
ns1 IN A 192.0.2.53
www IN A 192.0.2.90
new IN A 192.0.2.91
txt IN TXT "bind primary to go53 secondary"
EOF
	bind_exec "$BIND_PRIMARY_CONTAINER" /bin/sh -lc 'kill -HUP "$(pidof named)"' >/dev/null 2>&1 || true
	"$BIN_DIR/dnsnotify" --server "$SERVER_ADDR:$GO53_SECONDARY_DNS_PORT" --zone "$BIND_TO_GO53_ZONE" \
		|| fail "second NOTIFY to go53 secondary failed"
	wait_for_record "$GO53_SECONDARY_DNS_PORT" "new.$BIND_TO_GO53_ZONE" A "$BIND_PRIMARY_CONTAINER" "192\\.0\\.2\\.91"
	stop_go53
	echo "[BIND primary -> go53 secondary] ok"
}

main() {
	need_cmd go
	need_cmd jq
	need_cmd "$PODMAN_BIN"

	mkdir -p "$TMP_ROOT"
	build_tools
	run_go53_primary_bind_secondary
	run_bind_primary_go53_secondary
	echo "BIND primary/secondary interop checks passed"
}

main "$@"
