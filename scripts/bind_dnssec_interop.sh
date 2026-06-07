#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_ROOT="${TMPDIR:-/tmp}/go53-bind-dnssec.$$"
BIN_DIR="$TMP_ROOT/bin"
SERVER_BIN="$BIN_DIR/go53-server"
CTL_BIN="$BIN_DIR/go53ctl"

BIND_IMAGE="${BIND_IMAGE:-docker.io/internetsystemsconsortium/bind9:9.18}"
PODMAN_BIN="${PODMAN_BIN:-podman}"
SERVER_ADDR="${SERVER_ADDR:-127.0.0.1}"
DNS_PORT="${DNS_PORT:-12153}"
API_PORT="${API_PORT:-18153}"
ZONE="${ZONE:-bind-dnssec.test.}"
CONTAINER_NAME="${CONTAINER_NAME:-go53-bind-dnssec-$$}"
PULL_IMAGE="${PULL_IMAGE:-missing}"
STRICT_WILDCARD_DELV="${STRICT_WILDCARD_DELV:-1}"
STRICT_NEGATIVE_DELV="${STRICT_NEGATIVE_DELV:-1}"

SERVER_PID=""
CURRENT_BADGER_DIR="$TMP_ROOT/badger"
CURRENT_SOCKET="$TMP_ROOT/admin.sock"
CURRENT_LOG="$TMP_ROOT/server.log"

cleanup() {
	if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	if command -v "$PODMAN_BIN" >/dev/null 2>&1; then
		"$PODMAN_BIN" rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
	fi
	rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

fail() {
	echo "ERROR: $*" >&2
	if [[ -n "${CURRENT_LOG:-}" && -f "$CURRENT_LOG" ]]; then
		echo "--- server log tail ($CURRENT_LOG) ---" >&2
		tail -80 "$CURRENT_LOG" >&2 || true
	fi
	exit 1
}

need_cmd() {
	command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

api() {
	"$CTL_BIN" api --socket "$CURRENT_SOCKET" "$@"
}

bind_exec() {
	"$PODMAN_BIN" exec "$CONTAINER_NAME" "$@"
}

bind_sh() {
	bind_exec /bin/sh -lc "$1"
}

start_bind_tools_container() {
	echo "starting BIND tools container: $BIND_IMAGE"
	"$PODMAN_BIN" rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
	"$PODMAN_BIN" run \
		--rm \
		--detach \
		--name "$CONTAINER_NAME" \
		--network host \
		--pull "$PULL_IMAGE" \
		--volume "$TMP_ROOT:/work" \
		--entrypoint /bin/sh \
		"$BIND_IMAGE" \
		-lc 'trap "exit 0" TERM INT; while :; do sleep 3600; done' >/dev/null

	bind_sh 'command -v dig >/dev/null && command -v delv >/dev/null && command -v named-checkzone >/dev/null' \
		|| fail "BIND container does not provide dig, delv, and named-checkzone"
}

wait_for_socket() {
	local deadline=$((SECONDS + 20))
	while ((SECONDS < deadline)); do
		if [[ -S "$CURRENT_SOCKET" ]] && api GET /api/config >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.2
	done
	fail "server did not expose admin socket: $CURRENT_SOCKET"
}

wait_for_dns() {
	local deadline=$((SECONDS + 20))
	while ((SECONDS < deadline)); do
		if bind_exec dig @"$SERVER_ADDR" -p "$DNS_PORT" version.bind TXT CH +time=1 +tries=1 +short >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.2
	done
	fail "server did not answer DNS on $SERVER_ADDR:$DNS_PORT"
}

start_go53() {
	mkdir -p "$BIN_DIR" "$CURRENT_BADGER_DIR"
	echo "building local go53 server and go53ctl"
	(
		cd "$ROOT_DIR"
		GOCACHE="$TMP_ROOT/gocache" go build -o "$SERVER_BIN" ./cmd/server
		GOCACHE="$TMP_ROOT/gocache" go build -o "$CTL_BIN" ./cmd/go53ctl
	)

	echo "starting go53 on $SERVER_ADDR:$DNS_PORT"
	(
		cd "$ROOT_DIR"
		BIND_HOST="$SERVER_ADDR" \
			DNS_PORT=":$DNS_PORT" \
			API_PORT=":$API_PORT" \
			BADGER_DIR="$CURRENT_BADGER_DIR" \
			ADMIN_SOCKET="$CURRENT_SOCKET" \
			ADMIN_SOCKET_GROUP="" \
			"$SERVER_BIN" >"$CURRENT_LOG" 2>&1
	) &
	SERVER_PID=$!

	wait_for_socket
	api PATCH /api/config '{"mode":"primary","allow_axfr":true,"dnssec_enabled":true,"default_ttl":3600}' >/dev/null \
		|| fail "failed to configure go53 primary DNSSEC mode"
	wait_for_dns
}

add_record() {
	local rrtype="$1"
	local payload="$2"
	local output
	output="$(api POST "/api/zones/$ZONE/records/$rrtype" "$payload" 2>&1)" \
		|| fail "failed to add $rrtype with payload $payload; output: $output"
}

create_signed_zone() {
	local now active_at
	now="$(date +%s)"
	active_at=$((now - 60))

	echo "creating signed test zone: $ZONE"
	add_record SOA "$(jq -nc --arg zone "$ZONE" '{
		ttl:3600,
		ns:("ns1." + $zone),
		mbox:("hostmaster." + $zone),
		serial:1,
		refresh:3600,
		retry:600,
		expire:86400,
		minimum:300
	}')"
	add_record NS "$(jq -nc --arg zone "$ZONE" '{name:"@",ttl:3600,ns:("ns1." + $zone)}')"
	add_record A '{"name":"ns1","ttl":3600,"ip":"192.0.2.53"}'
	add_record A '{"name":"www","ttl":3600,"ip":"192.0.2.10"}'
	add_record AAAA '{"name":"www","ttl":3600,"ip":"2001:db8::10"}'
	add_record TXT '{"name":"txt","ttl":3600,"text":"go53 bind dnssec interop"}'
	add_record A '{"name":"*","ttl":3600,"ip":"192.0.2.42"}'
	add_record NSEC3PARAM '{"name":"@","ttl":3600,"hash_algorithm":1,"flags":0,"iterations":0,"salt":"-"}'

	api POST /api/dnskeys/rollover "$(jq -nc --arg zone "$ZONE" --argjson t "$active_at" \
		'{zone:$zone,role:"ksk",algorithm:"ED25519",publish_at:$t,activate_at:$t}')" >/dev/null \
		|| fail "failed to create KSK"
	api POST /api/dnskeys/rollover "$(jq -nc --arg zone "$ZONE" --argjson t "$active_at" \
		'{zone:$zone,role:"zsk",algorithm:"ED25519",publish_at:$t,activate_at:$t}')" >/dev/null \
		|| fail "failed to create ZSK"
}

wait_for_dnssec_material() {
	local deadline=$((SECONDS + 30))
	local dnskey_out a_out nsec_out
	while ((SECONDS < deadline)); do
		dnskey_out="$(bind_exec dig @"$SERVER_ADDR" -p "$DNS_PORT" "$ZONE" DNSKEY +dnssec +time=1 +tries=1 +noall +answer 2>/dev/null || true)"
		a_out="$(bind_exec dig @"$SERVER_ADDR" -p "$DNS_PORT" "www.$ZONE" A +dnssec +time=1 +tries=1 +noall +answer 2>/dev/null || true)"
		nsec_out="$(bind_exec dig @"$SERVER_ADDR" -p "$DNS_PORT" "missing.$ZONE" TXT +dnssec +time=1 +tries=1 +noall +authority 2>/dev/null || true)"
		if grep -Eq "[[:space:]]DNSKEY[[:space:]]" <<<"$dnskey_out" &&
			grep -Eq "[[:space:]]RRSIG[[:space:]]+DNSKEY[[:space:]]" <<<"$dnskey_out" &&
			grep -Eq "[[:space:]]RRSIG[[:space:]]+A[[:space:]]" <<<"$a_out" &&
			grep -Eq "[[:space:]](NSEC|NSEC3)[[:space:]]" <<<"$nsec_out"; then
			return 0
		fi
		sleep 0.5
	done
	fail "DNSSEC material did not become visible for $ZONE"
}

write_trust_anchor() {
	local anchor="$TMP_ROOT/trust-anchor.key"
	{
		echo 'trust-anchors {'
		bind_exec dig @"$SERVER_ADDR" -p "$DNS_PORT" "$ZONE" DNSKEY +dnssec +time=2 +tries=1 +noall +answer |
			awk '$4 == "DNSKEY" { printf "\t\"%s\" static-key %s %s %s \"%s\";\n", $1, $5, $6, $7, $8 }'
		echo '};'
	} >"$anchor"
	grep -Eq '"[^"]+"[[:space:]]+static-key[[:space:]]+[0-9]+[[:space:]]+3[[:space:]]+[0-9]+[[:space:]]+"[^"]+"' "$anchor" \
		|| fail "could not build delv trust anchor from DNSKEY response"
	[[ -s "$anchor" ]] || fail "could not build delv trust anchor from DNSKEY response"
	echo "$anchor"
}

expect_bind_dig_rrsig() {
	local name="$1"
	local rrtype="$2"
	local covered="$3"
	local output
	output="$(bind_exec dig @"$SERVER_ADDR" -p "$DNS_PORT" "$name" "$rrtype" +dnssec +time=2 +tries=1 +noall +answer)"
	grep -Eq "[[:space:]]$rrtype[[:space:]]" <<<"$output" || fail "BIND dig did not receive $rrtype for $name; output: $output"
	grep -Eq "[[:space:]]RRSIG[[:space:]]+$covered[[:space:]]" <<<"$output" || fail "BIND dig did not receive RRSIG($covered) for $name; output: $output"
}

expect_bind_negative_denial() {
	local name="$1"
	local rrtype="$2"
	local output
	output="$(bind_exec dig @"$SERVER_ADDR" -p "$DNS_PORT" "$name" "$rrtype" +dnssec +time=2 +tries=1 +noall +authority)"
	grep -Eq "[[:space:]]SOA[[:space:]]" <<<"$output" || fail "BIND dig negative response did not include SOA for $name $rrtype; output: $output"
	grep -Eq "[[:space:]](NSEC|NSEC3)[[:space:]]" <<<"$output" || fail "BIND dig negative response did not include NSEC/NSEC3 for $name $rrtype; output: $output"
}


expect_delv_validated() {
	local anchor="$1"
	local name="$2"
	local rrtype="$3"
	local output
	output="$(bind_exec delv -a /work/$(basename "$anchor") @"$SERVER_ADDR" -p "$DNS_PORT" "$name" "$rrtype" +root="$ZONE" +multiline 2>&1)" \
		|| fail "delv failed for $rrtype $name; output: $output"
	grep -Eq "fully validated|validated" <<<"$output" || fail "delv did not validate $rrtype $name; output: $output"
}

expect_delv_negative_validated() {
	local anchor="$1"
	local name="$2"
	local rrtype="$3"
	local output
	output="$(bind_exec delv -a /work/$(basename "$anchor") @"$SERVER_ADDR" -p "$DNS_PORT" "$name" "$rrtype" +root="$ZONE" +multiline 2>&1)" \
		|| fail "delv failed for negative $rrtype $name; output: $output"
	grep -Eq "fully validated|validated" <<<"$output" || fail "delv did not validate negative $rrtype $name; output: $output"
	grep -Eq "NXDOMAIN|NSEC|NSEC3|RRSIG" <<<"$output" || fail "delv negative response did not include denial proof context; output: $output"
}

run_named_checkzone_from_axfr() {
	local zonefile="$TMP_ROOT/axfr.zone"
	bind_exec dig @"$SERVER_ADDR" -p "$DNS_PORT" "$ZONE" AXFR +tcp +dnssec +time=3 +tries=1 +noall +answer >"$zonefile"
	[[ -s "$zonefile" ]] || fail "AXFR output was empty"
	bind_exec named-checkzone -i full -k fail -n fail "$ZONE" /work/$(basename "$zonefile") >/dev/null \
		|| fail "named-checkzone rejected AXFR zone file"
}

run_bind_interop_checks() {
	local anchor
	wait_for_dnssec_material
	anchor="$(write_trust_anchor)"

	echo "running BIND dig checks"
	expect_bind_dig_rrsig "$ZONE" DNSKEY DNSKEY
	expect_bind_dig_rrsig "www.$ZONE" A A
	expect_bind_dig_rrsig "txt.$ZONE" TXT TXT
	expect_bind_dig_rrsig "host.$ZONE" A A
	expect_bind_negative_denial "missing.$ZONE" TXT

	echo "running BIND delv validation checks"
	expect_delv_validated "$anchor" "$ZONE" DNSKEY
	expect_delv_validated "$anchor" "www.$ZONE" A
	if [[ "$STRICT_NEGATIVE_DELV" == "1" ]]; then
		expect_delv_negative_validated "$anchor" "missing.$ZONE" TXT
	fi
	if [[ "$STRICT_WILDCARD_DELV" == "1" ]]; then
		expect_delv_validated "$anchor" "host.$ZONE" A
	fi

	echo "running BIND named-checkzone over DNSSEC AXFR"
	run_named_checkzone_from_axfr
}

main() {
	need_cmd go
	need_cmd jq
	need_cmd awk
	need_cmd "$PODMAN_BIN"

	mkdir -p "$TMP_ROOT"
	start_bind_tools_container
	start_go53
	create_signed_zone
	run_bind_interop_checks

	echo "BIND DNSSEC interop checks passed"
}

main "$@"
