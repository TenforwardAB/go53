#!/usr/bin/env bash
set -Eeuo pipefail

ADMIN_SOCKET="${ADMIN_SOCKET:-/var/lib/go53/admin.sock}"
CATALOG_ZONE="${CATALOG_ZONE:-catalog.go53.}"
MEMBER_ZONE="${MEMBER_ZONE:-catalog-member-a.test.}"

fail() {
	echo "ERROR: $*" >&2
	exit 1
}

api() {
	local method="$1"
	local path="$2"
	local body="${3:-}"
	if [[ -n "$body" ]]; then
		curl -fsS --unix-socket "$ADMIN_SOCKET" \
			-X "$method" \
			-H 'content-type: application/json' \
			--data "$body" \
			"http://admin$path"
	else
		curl -fsS --unix-socket "$ADMIN_SOCKET" -X "$method" "http://admin$path"
	fi
}

wait_for_admin_socket() {
	local deadline=$((SECONDS + 45))
	while ((SECONDS < deadline)); do
		if [[ -S "$ADMIN_SOCKET" ]] && api GET /api/config >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.5
	done
	fail "go53 admin socket did not become ready at $ADMIN_SOCKET"
}

wait_for_dns() {
	local server="$1"
	local port="$2"
	local name="$3"
	local rrtype="$4"
	local deadline=$((SECONDS + 45))
	while ((SECONDS < deadline)); do
		if dig @"$server" -p "$port" "$name" "$rrtype" +time=1 +tries=1 +short >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.5
	done
	fail "DNS server $server:$port did not answer $name $rrtype"
}

wait_for_answer() {
	local server="$1"
	local port="$2"
	local name="$3"
	local rrtype="$4"
	local pattern="$5"
	local deadline=$((SECONDS + 60))
	local output=""
	while ((SECONDS < deadline)); do
		output="$(dig @"$server" -p "$port" "$name" "$rrtype" +time=1 +tries=1 +noall +answer 2>/dev/null || true)"
		if grep -Eq "$pattern" <<<"$output"; then
			return 0
		fi
		sleep 0.5
	done
	fail "did not observe $name $rrtype on $server:$port; last output: $output"
}

assert_no_answer() {
	local server="$1"
	local port="$2"
	local name="$3"
	local rrtype="$4"
	local output
	output="$(dig @"$server" -p "$port" "$name" "$rrtype" +time=1 +tries=1 +noall +answer 2>/dev/null || true)"
	if [[ -n "$output" ]]; then
		fail "$server unexpectedly serves $name $rrtype: $output"
	fi
}

echo "waiting for BIND and go53 services"
wait_for_dns 10.53.0.53 53 "$CATALOG_ZONE" SOA
wait_for_dns 10.53.0.60 53 "$MEMBER_ZONE" SOA
wait_for_dns 10.53.0.10 2053 version.bind TXT
wait_for_admin_socket

echo "configuring go53 secondary with catalog bootstrap primary only"
api POST /api/tsig/catalog-key '{"algorithm":"hmac-sha256.","secret":"YWJjMTIz"}' >/dev/null
api PATCH /api/config '{
  "mode": "secondary",
  "allow_axfr": true,
  "dnssec_enabled": false,
  "enforce_tsig": false,
  "primary": {"ip": "10.53.0.53", "port": 53},
  "secondary": {
    "catalog_enabled": true,
    "catalog_zone": "catalog.go53.",
    "zones": [],
    "min_fetch_interval_sec": 0,
    "max_parallel_fetches": 2,
    "refresh_interval_sec": 0,
    "refresh_jitter_sec": 0
  }
}' >/dev/null

echo "proving catalog primary does not serve the member zone"
assert_no_answer 10.53.0.53 53 "$MEMBER_ZONE" SOA

echo "triggering catalog fetch; member fetch must use primaries.ext -> 10.53.0.60:53"
api POST "/api/secondary/fetch/$CATALOG_ZONE" >/dev/null

wait_for_answer 10.53.0.10 2053 "$CATALOG_ZONE" SOA 'SOA'
wait_for_answer 10.53.0.10 2053 "txt.$MEMBER_ZONE" TXT 'catalog primaries member'

echo "updating member primary and waiting for BIND NOTIFY-triggered refetch"
sed -i \
	-e 's/1 3600 600 86400 300/2 3600 600 86400 300/' \
	-e 's/catalog primaries member/catalog primaries member after notify/' \
	/member-zones/db.catalog-member-a.test
touch /control/reload-member

wait_for_answer 10.53.0.10 2053 "txt.$MEMBER_ZONE" TXT 'catalog primaries member after notify'

echo "catalog primaries interop passed"
