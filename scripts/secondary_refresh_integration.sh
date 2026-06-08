#!/usr/bin/env bash
set -Eeuo pipefail

# Integration test for secondary-mode startup + periodic AXFR refresh.
#
# Spins up TWO go53 instances on loopback:
#   - a primary serving a zone
#   - a secondary pointed at the primary via catalog zone + Primary.Ip/Port
#
# Asserts the secondary converges on the zone:
#   A) at STARTUP, without any NOTIFY (startup sweep -> catalog AXFR -> member AXFR)
#   B) after a primary-side change, without any NOTIFY (periodic ticker -> AXFR)
#
# NOTIFY isolation: the primary sends NOTIFY to AllowTransfer targets on :53, while the
# secondary listens on a non-53 port, so NOTIFY can never reach it. Both convergences
# are therefore driven purely by the new refresh logic. enforce_tsig is left false on
# loopback (mirrors scripts/all_rtypes_integration.sh) to keep the test focused on the
# refresh scheduling rather than TSIG.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_ROOT="${TMPDIR:-/tmp}/go53-secondary-refresh.$$"
BIN_DIR="$TMP_ROOT/bin"
SERVER_BIN="$BIN_DIR/go53-server"
CTL_BIN="$BIN_DIR/go53ctl"

ZONE="refresh-test.example."
CATALOG_ZONE="_catalog.go53."

PRIMARY_DNS_PORT=12061
PRIMARY_API_PORT=18061
SECONDARY_DNS_PORT=12062
SECONDARY_API_PORT=18062

PRIMARY_BADGER="$TMP_ROOT/primary/badger"
PRIMARY_SOCKET="$TMP_ROOT/primary/admin.sock"
PRIMARY_LOG="$TMP_ROOT/primary/server.log"
PRIMARY_PID=""

SECONDARY_BADGER="$TMP_ROOT/secondary/badger"
SECONDARY_SOCKET="$TMP_ROOT/secondary/admin.sock"
SECONDARY_LOG="$TMP_ROOT/secondary/server.log"
SECONDARY_PID=""

cleanup() {
    for pid in "$PRIMARY_PID" "$SECONDARY_PID"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    if [[ -n "${KEEP_TMP:-}" ]]; then
        echo "KEEP_TMP set; preserving $TMP_ROOT" >&2
    else
        rm -rf "$TMP_ROOT"
    fi
}
trap cleanup EXIT

fail() {
    echo "ERROR: $*" >&2
    for log in "$PRIMARY_LOG" "$SECONDARY_LOG"; do
        if [[ -f "$log" ]]; then
            echo "--- server log tail ($log) ---" >&2
            tail -60 "$log" >&2 || true
        fi
    done
    exit 1
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

# api <socket> METHOD path [body]
api() {
    local socket="$1"; shift
    "$CTL_BIN" api --socket "$socket" "$@"
}

wait_for_socket() {
    local socket="$1"
    local deadline=$((SECONDS + 20))
    while (( SECONDS < deadline )); do
        if [[ -S "$socket" ]] && api "$socket" GET /api/config >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
    done
    fail "server did not expose admin socket: $socket"
}

wait_for_dns() {
    local port="$1"
    local deadline=$((SECONDS + 20))
    while (( SECONDS < deadline )); do
        if dig @127.0.0.1 -p "$port" version.bind TXT CH +time=1 +tries=1 +short >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
    done
    fail "server did not answer DNS on 127.0.0.1:$port"
}

soa_serial() {
    # Print the SOA serial (3rd rdata field) for a zone, or empty if not served yet.
    local port="$1"
    local zone="${2:-$ZONE}"
    dig @127.0.0.1 -p "$port" "$zone" SOA +short +time=1 +tries=1 2>/dev/null | awk 'NR==1{print $3}'
}

a_value() {
    local port="$1"
    local name="$2"
    dig @127.0.0.1 -p "$port" "$name" A +short +time=1 +tries=1 2>/dev/null | head -n1
}

start_primary() {
    mkdir -p "$(dirname "$PRIMARY_LOG")" "$PRIMARY_BADGER"
    # exec so the subshell becomes the server process; $! is then the server PID and
    # killing it releases the Badger directory lock promptly.
    (
        cd "$ROOT_DIR"
        exec env BIND_HOST=127.0.0.1 \
            DNS_PORT=":$PRIMARY_DNS_PORT" \
            API_PORT=":$PRIMARY_API_PORT" \
            BADGER_DIR="$PRIMARY_BADGER" \
            ADMIN_SOCKET="$PRIMARY_SOCKET" \
            ADMIN_SOCKET_GROUP="" \
            "$SERVER_BIN"
    ) >"$PRIMARY_LOG" 2>&1 &
    PRIMARY_PID=$!
    wait_for_socket "$PRIMARY_SOCKET"
    api "$PRIMARY_SOCKET" PATCH /api/config \
        '{"mode":"primary","allow_axfr":true,"dnssec_enabled":false,"enforce_tsig":false,
          "secondary":{"catalog_enabled":true,"catalog_zone":"_catalog.go53."}}' >/dev/null \
        || fail "failed to configure primary"
    wait_for_dns "$PRIMARY_DNS_PORT"
}

# start_secondary configures the secondary toward the primary. It does NOT wait for the
# zone — the caller asserts convergence. The badger dir persists across restarts so the
# patched secondary config survives a stop/start (used to test the startup sweep).
start_secondary() {
    mkdir -p "$(dirname "$SECONDARY_LOG")" "$SECONDARY_BADGER"
    # exec so the subshell becomes the server process; $! is then the server PID and
    # killing it releases the Badger directory lock promptly (needed for the restart).
    (
        cd "$ROOT_DIR"
        exec env BIND_HOST=127.0.0.1 \
            DNS_PORT=":$SECONDARY_DNS_PORT" \
            API_PORT=":$SECONDARY_API_PORT" \
            BADGER_DIR="$SECONDARY_BADGER" \
            ADMIN_SOCKET="$SECONDARY_SOCKET" \
            ADMIN_SOCKET_GROUP="" \
            "$SERVER_BIN"
    ) >>"$SECONDARY_LOG" 2>&1 &
    SECONDARY_PID=$!
    wait_for_socket "$SECONDARY_SOCKET"
    wait_for_dns "$SECONDARY_DNS_PORT"
}

stop_secondary() {
    if [[ -n "$SECONDARY_PID" ]] && kill -0 "$SECONDARY_PID" 2>/dev/null; then
        kill "$SECONDARY_PID" 2>/dev/null || true
        wait "$SECONDARY_PID" 2>/dev/null || true
    fi
    SECONDARY_PID=""
}

add_record() {
    local rrtype="$1"
    local payload="$2"
    local output
    output="$(api "$PRIMARY_SOCKET" POST "/api/zones/$ZONE/records/$rrtype" "$payload" 2>&1)" \
        || fail "failed to add $rrtype with payload $payload; output: $output"
}

create_primary_zone() {
    add_record SOA '{"ttl":300,"ns":"ns1.refresh-test.example.","mbox":"hostmaster.refresh-test.example.","refresh":3600,"retry":600,"expire":86400,"minimum":300}'
    add_record NS '{"name":"@","ttl":300,"ns":"ns1.refresh-test.example."}'
    add_record A '{"name":"ns1","ttl":300,"ip":"192.0.2.53"}'
    add_record A '{"name":"www","ttl":300,"ip":"192.0.2.10"}'
    add_record TXT '{"name":"txt","ttl":300,"text":"go53 secondary refresh test"}'
}

assert_primary_catalog_contains_zone() {
    local version
    version="$(dig @127.0.0.1 -p "$PRIMARY_DNS_PORT" "version.$CATALOG_ZONE" TXT +short +time=1 +tries=1 2>/dev/null | tr -d '"')"
    [[ "$version" == "2" ]] || fail "primary catalog version TXT=$version, expected 2"

    local ptrs
    ptrs="$(dig @127.0.0.1 -p "$PRIMARY_DNS_PORT" "$CATALOG_ZONE" AXFR +time=2 +tries=1 2>/dev/null | awk '$4=="PTR"{print $5}')"
    grep -Fxq "$ZONE" <<<"$ptrs" || fail "primary catalog $CATALOG_ZONE does not contain PTR for $ZONE; PTRs: $ptrs"
}

configure_secondary() {
    api "$SECONDARY_SOCKET" PATCH /api/config "$(cat <<JSON
{"mode":"secondary","allow_axfr":true,"dnssec_enabled":false,"enforce_tsig":false,
 "primary":{"ip":"127.0.0.1","port":$PRIMARY_DNS_PORT},
 "secondary":{"min_fetch_interval_sec":2,"max_parallel_fetches":5,
              "refresh_interval_sec":5,"refresh_jitter_sec":1,
              "catalog_enabled":true,"catalog_zone":"$CATALOG_ZONE",
              "zones":[]}}
JSON
)" >/dev/null || fail "failed to configure secondary"
}

# poll_secondary_serial <expected_serial> <deadline_seconds> [zone]
poll_secondary_serial() {
    local expected="$1"
    local timeout="$2"
    local zone="${3:-$ZONE}"
    local deadline=$((SECONDS + timeout))
    local got
    while (( SECONDS < deadline )); do
        got="$(soa_serial "$SECONDARY_DNS_PORT" "$zone")"
        if [[ -n "$got" && "$got" == "$expected" ]]; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

main() {
    need_cmd go
    need_cmd dig
    need_cmd jq
    need_cmd awk

    mkdir -p "$BIN_DIR"
    echo "building local go53 server and go53ctl"
    (cd "$ROOT_DIR" \
        && GOCACHE="$TMP_ROOT/gocache" go build -o "$SERVER_BIN" ./cmd/server \
        && GOCACHE="$TMP_ROOT/gocache" go build -o "$CTL_BIN" ./cmd/go53ctl)

    echo "== starting primary and creating zone $ZONE =="
    start_primary
    create_primary_zone
    PRIMARY_SERIAL="$(soa_serial "$PRIMARY_DNS_PORT")"
    [[ -n "$PRIMARY_SERIAL" ]] || fail "primary did not serve SOA for $ZONE"
    PRIMARY_WWW="$(a_value "$PRIMARY_DNS_PORT" "www.$ZONE")"
    echo "[primary] $ZONE serial=$PRIMARY_SERIAL www=$PRIMARY_WWW"
    assert_primary_catalog_contains_zone
    CATALOG_SERIAL="$(soa_serial "$PRIMARY_DNS_PORT" "$CATALOG_ZONE")"
    [[ -n "$CATALOG_SERIAL" ]] || fail "primary did not serve SOA for catalog $CATALOG_ZONE"
    echo "[primary] catalog $CATALOG_ZONE serial=$CATALOG_SERIAL contains $ZONE"

    echo "== configuring secondary (config persisted, then restarted to exercise startup sweep) =="
    start_secondary
    configure_secondary
    # The first boot ran with default (primary) config, so StartSecondaryRefresh no-opped.
    # Restart so the next boot loads the persisted secondary config and runs the sweep.
    stop_secondary
    start_secondary

    echo "== Assertion A: catalog-driven startup refresh without NOTIFY =="
    poll_secondary_serial "$CATALOG_SERIAL" 15 "$CATALOG_ZONE" \
        || fail "secondary did not converge on catalog serial $CATALOG_SERIAL at startup; got '$(soa_serial "$SECONDARY_DNS_PORT" "$CATALOG_ZONE")'"
    poll_secondary_serial "$PRIMARY_SERIAL" 15 \
        || fail "secondary did not converge on serial $PRIMARY_SERIAL at startup; got '$(soa_serial "$SECONDARY_DNS_PORT")'"
    SEC_WWW="$(a_value "$SECONDARY_DNS_PORT" "www.$ZONE")"
    [[ "$SEC_WWW" == "$PRIMARY_WWW" ]] || fail "secondary www A=$SEC_WWW, expected $PRIMARY_WWW"
    grep -q "\[secondary-refresh\] startup sweep" "$SECONDARY_LOG" \
        || fail "secondary log missing startup sweep line"
    grep -q "\[fetchZone\] AXFR returned" "$SECONDARY_LOG" \
        || fail "secondary log missing AXFR line for startup fetch"
    echo "[A] ok: secondary fetched catalog and serves $ZONE at startup (serial=$PRIMARY_SERIAL, www=$SEC_WWW), no NOTIFY"

    echo "== Assertion B: periodic refresh after a primary-side change, without NOTIFY =="
    add_record A '{"name":"api","ttl":300,"ip":"192.0.2.20"}'
    NEW_PRIMARY_SERIAL="$(soa_serial "$PRIMARY_DNS_PORT")"
    [[ -n "$NEW_PRIMARY_SERIAL" && "$NEW_PRIMARY_SERIAL" != "$PRIMARY_SERIAL" ]] \
        || fail "primary serial did not advance after change (was $PRIMARY_SERIAL, now $NEW_PRIMARY_SERIAL)"
    echo "[primary] bumped: new serial=$NEW_PRIMARY_SERIAL (added api A 192.0.2.20)"

    # refresh_interval_sec=5 (+ jitter 1) + AXFR time; allow generous slack.
    poll_secondary_serial "$NEW_PRIMARY_SERIAL" 25 \
        || fail "secondary did not converge on new serial $NEW_PRIMARY_SERIAL via periodic refresh; got '$(soa_serial "$SECONDARY_DNS_PORT")'"
    SEC_API="$(a_value "$SECONDARY_DNS_PORT" "api.$ZONE")"
    [[ "$SEC_API" == "192.0.2.20" ]] || fail "secondary api A=$SEC_API, expected 192.0.2.20"
    grep -q "\[secondary-refresh\] periodic sweep" "$SECONDARY_LOG" \
        || fail "secondary log missing periodic sweep line"
    echo "[B] ok: secondary picked up the change via periodic refresh (serial=$NEW_PRIMARY_SERIAL, api=$SEC_API), no NOTIFY"

    echo "secondary refresh integration checks passed"
}

main "$@"
