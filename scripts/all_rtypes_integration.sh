#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_ROOT="${TMPDIR:-/tmp}/go53-all-rtypes.$$"
BIN_DIR="$TMP_ROOT/bin"
SERVER_BIN="$BIN_DIR/go53-server"
CTL_BIN="$BIN_DIR/go53ctl"

SERVER_PID=""
CURRENT_BADGER_DIR=""
CURRENT_SOCKET=""
CURRENT_LOG=""

cleanup() {
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
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

wait_for_socket() {
    local deadline=$((SECONDS + 20))
    while (( SECONDS < deadline )); do
        if [[ -S "$CURRENT_SOCKET" ]] && api GET /api/config >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
    done
    fail "server did not expose admin socket: $CURRENT_SOCKET"
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

start_server() {
    local mode="$1"
    local dns_port="$2"
    local api_port="$3"
    local sync_port="$4"

    CURRENT_BADGER_DIR="$TMP_ROOT/$mode/badger"
    CURRENT_SOCKET="$TMP_ROOT/$mode/admin.sock"
    CURRENT_LOG="$TMP_ROOT/$mode/server.log"
    mkdir -p "$(dirname "$CURRENT_LOG")" "$CURRENT_BADGER_DIR"

    (
        cd "$ROOT_DIR"
        BIND_HOST=127.0.0.1 \
        DNS_PORT=":$dns_port" \
        API_PORT=":$api_port" \
        BADGER_DIR="$CURRENT_BADGER_DIR" \
        ADMIN_SOCKET="$CURRENT_SOCKET" \
        ADMIN_SOCKET_GROUP="" \
        "$SERVER_BIN" >"$CURRENT_LOG" 2>&1
    ) &
    SERVER_PID=$!

    wait_for_socket
    wait_for_dns "$dns_port"

    if [[ "$mode" == "distributed" ]]; then
        local keypair private_key
        keypair="$(api POST /api/distributed/keypair)" || fail "could not create distributed keypair"
        private_key="$(jq -r '.private_key' <<<"$keypair")"
        [[ -n "$private_key" && "$private_key" != "null" ]] || fail "could not create distributed private key"
        api PATCH /api/config "$(jq -nc \
            --arg private_key "$private_key" \
            --arg sync_port ":$sync_port" \
            '{mode:"distributed", allow_axfr:true, dnssec_enabled:false,
              distributed:{node_id:"all-rtypes-node", peers:"", transport:"tcp",
              sync_bind_host:"127.0.0.1", sync_port:$sync_port,
              private_key:$private_key, peer_public_keys:{}, push_timeout_ms:500,
              resync_interval_s:5}}')" >/dev/null || fail "failed to configure distributed mode"
        local status
        status="$(api GET /api/distributed/status)" || fail "could not read distributed status"
        jq -e '.enabled == true' <<<"$status" >/dev/null || fail "distributed mode did not enable; status: $status"
    else
        api PATCH /api/config '{"mode":"primary","allow_axfr":true,"dnssec_enabled":false}' >/dev/null || fail "failed to configure primary mode"
    fi
}

stop_server() {
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    SERVER_PID=""
}

add_record() {
    local zone="$1"
    local rrtype="$2"
    local payload="$3"
    local output
    output="$(api POST "/api/zones/$zone/records/$rrtype" "$payload" 2>&1)" || fail "failed to add $rrtype to $zone with payload $payload; output: $output"
}

api_expect_record() {
    local zone="$1"
    local rrtype="$2"
    local name="$3"
    local output
    output="$(api GET "/api/zones/$zone/records/$rrtype/$name")" || fail "API lookup failed for $rrtype $name"
    jq -e 'length > 0' <<<"$output" >/dev/null || fail "API lookup returned no JSON records for $rrtype $name; output: $output"
}

dig_expect_type() {
    local port="$1"
    local name="$2"
    local rrtype="$3"
    local output

    output="$(dig @127.0.0.1 -p "$port" "$name" "$rrtype" +time=2 +tries=1 +noall +answer)"
    grep -Eq "[[:space:]]$rrtype[[:space:]]" <<<"$output" || fail "dig @server did not return $rrtype for $name; output: $output"

    output="$(dig "$name" "$rrtype" @127.0.0.1 -p "$port" +time=2 +tries=1 +noall +answer)"
    grep -Eq "[[:space:]]$rrtype[[:space:]]" <<<"$output" || fail "dig name type @server did not return $rrtype for $name; output: $output"
}

dig_expect_dnssec_rrsig() {
    local port="$1"
    local name="$2"
    local covered="$3"
    local output
    output="$(dig @127.0.0.1 -p "$port" "$name" "$covered" +dnssec +time=2 +tries=1 +noall +answer)"
    grep -Eq "[[:space:]]RRSIG[[:space:]]+$covered[[:space:]]" <<<"$output" || fail "DNSSEC lookup did not return RRSIG($covered) for $name; output: $output"
}

dig_expect_axfr() {
    local port="$1"
    local zone="$2"
    local output
    output="$(dig @127.0.0.1 -p "$port" "$zone" AXFR +tcp +time=3 +tries=1)"
    grep -Eq "[[:space:]]SOA[[:space:]]" <<<"$output" || fail "AXFR did not include SOA for $zone"
    grep -Eq "www\\.$zone[[:space:]].*[[:space:]]A[[:space:]]" <<<"$output" || fail "AXFR did not include A record for $zone"
}

create_all_records() {
    local zone="$1"
    local nsec3_hash="0123456789abcdefghijklmnopqrstuv"
    local ksk_key zsk_key

    add_record "$zone" SOA '{"ttl":300,"ns":"ns1.all-rtypes.test.","mbox":"hostmaster.all-rtypes.test.","refresh":3600,"retry":600,"expire":86400,"minimum":300}'
    ksk_key="$(api POST /api/dnskeys/rollover '{"zone":"all-rtypes.test.","role":"ksk","algorithm":"ED25519"}' | jq -r '.keyid')" || fail "could not create KSK rollover key"
    zsk_key="$(api POST /api/dnskeys/rollover '{"zone":"all-rtypes.test.","role":"zsk","algorithm":"ED25519"}' | jq -r '.keyid')" || fail "could not create ZSK rollover key"
    [[ -n "$ksk_key" && "$ksk_key" != "null" ]] || fail "could not create KSK rollover key"
    [[ -n "$zsk_key" && "$zsk_key" != "null" ]] || fail "could not create ZSK rollover key"
    add_record "$zone" DNSKEY "{\"keyid\":\"$ksk_key\",\"ttl\":300}"
    add_record "$zone" DNSKEY "{\"keyid\":\"$zsk_key\",\"ttl\":300}"
    add_record "$zone" NS '{"name":"@","ttl":300,"ns":"ns1.all-rtypes.test."}'
    add_record "$zone" A '{"name":"www","ttl":300,"ip":"192.0.2.10"}'
    add_record "$zone" AAAA '{"name":"www","ttl":300,"ip":"2001:db8::10"}'
    add_record "$zone" CNAME '{"name":"alias","ttl":300,"target":"www.all-rtypes.test."}'
    add_record "$zone" DNAME '{"name":"old","ttl":300,"target":"new.all-rtypes.test."}'
    add_record "$zone" MX '{"name":"@","ttl":300,"host":"mail.all-rtypes.test.","priority":10}'
    add_record "$zone" TXT '{"name":"txt","ttl":300,"text":"go53 all rtypes txt"}'
    add_record "$zone" SPF '{"name":"spf","ttl":300,"text":"v=spf1 -all"}'
    add_record "$zone" SRV '{"name":"_sip._tcp","ttl":300,"priority":10,"weight":5,"port":5060,"target":"sip.all-rtypes.test."}'
    add_record "$zone" PTR '{"name":"ptr","ttl":300,"ptr":"www.all-rtypes.test."}'
    add_record "$zone" DS '{"name":"child","ttl":300,"key_tag":12345,"algorithm":15,"digest_type":2,"digest":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}'
    add_record "$zone" CDS '{"name":"@","ttl":300,"key_tag":12345,"algorithm":15,"digest_type":2,"digest":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}'
    add_record "$zone" CDNSKEY '{"name":"@","ttl":300,"flags":257,"protocol":3,"algorithm":15,"public_key":"AA=="}'
    add_record "$zone" NSEC '{"name":"@","ttl":300,"next_domain":"www.all-rtypes.test.","types":["SOA","NS","DNSKEY","NSEC","RRSIG"]}'
    add_record "$zone" NSEC3PARAM '{"name":"@","ttl":300,"hash_algorithm":1,"flags":0,"iterations":0,"salt":"-"}'
    add_record "$zone" NSEC3 "{\"name\":\"$nsec3_hash\",\"ttl\":300,\"hash_algorithm\":1,\"flags\":1,\"iterations\":0,\"salt\":\"-\",\"next_hashed\":\"$nsec3_hash\",\"types\":[\"A\",\"RRSIG\"]}"
    add_record "$zone" RRSIG '{"name":"www","ttl":300,"type_covered":"A","algorithm":15,"labels":3,"original_ttl":300,"expiration":4102444800,"inception":1704067200,"key_tag":12345,"signer_name":"all-rtypes.test.","signature":"AA=="}'
}

verify_all_records() {
    local mode="$1"
    local port="$2"
    local zone="all-rtypes.test."
    local nsec3_hash="0123456789abcdefghijklmnopqrstuv"

    echo "[$mode] verifying API FQDN lookups"
    api_expect_record "$zone" SOA "$zone"
    api_expect_record "$zone" DNSKEY "$zone"
    api_expect_record "$zone" NS "$zone"
    api_expect_record "$zone" A "www.$zone"
    api_expect_record "$zone" AAAA "www.$zone"
    api_expect_record "$zone" CNAME "alias.$zone"
    api_expect_record "$zone" DNAME "old.$zone"
    api_expect_record "$zone" MX "$zone"
    api_expect_record "$zone" TXT "txt.$zone"
    api_expect_record "$zone" SPF "spf.$zone"
    api_expect_record "$zone" SRV "_sip._tcp.$zone"
    api_expect_record "$zone" PTR "ptr.$zone"
    api_expect_record "$zone" DS "child.$zone"
    api_expect_record "$zone" CDS "$zone"
    api_expect_record "$zone" CDNSKEY "$zone"
    api_expect_record "$zone" NSEC "$zone"
    api_expect_record "$zone" NSEC3 "$nsec3_hash.$zone"
    api_expect_record "$zone" NSEC3PARAM "$zone"
    api_expect_record "$zone" RRSIG "www.${zone}___A"

    api PATCH /api/config '{"dnssec_enabled":true}' >/dev/null || fail "failed to enable DNSSEC before DNS verification"

    echo "[$mode] verifying DNS lookups with common dig forms"
    dig_expect_type "$port" "$zone" SOA
    dig_expect_type "$port" "$zone" DNSKEY
    dig_expect_type "$port" "$zone" NS
    dig_expect_type "$port" "www.$zone" A
    dig_expect_type "$port" "www.$zone" AAAA
    dig_expect_type "$port" "alias.$zone" CNAME
    dig_expect_type "$port" "old.$zone" DNAME
    dig_expect_type "$port" "$zone" MX
    dig_expect_type "$port" "txt.$zone" TXT
    dig_expect_type "$port" "spf.$zone" SPF
    dig_expect_type "$port" "_sip._tcp.$zone" SRV
    dig_expect_type "$port" "ptr.$zone" PTR
    dig_expect_type "$port" "child.$zone" DS
    dig_expect_type "$port" "$zone" CDS
    dig_expect_type "$port" "$zone" CDNSKEY
    dig_expect_type "$port" "$zone" NSEC
    dig_expect_type "$port" "$nsec3_hash.$zone" NSEC3
    dig_expect_type "$port" "$zone" NSEC3PARAM
    dig_expect_dnssec_rrsig "$port" "www.$zone" A
    dig_expect_axfr "$port" "$zone"
}

run_mode() {
    local mode="$1"
    local dns_port="$2"
    local api_port="$3"
    local sync_port="$4"
    local zone="all-rtypes.test."

    echo "== $mode mode =="
    start_server "$mode" "$dns_port" "$api_port" "$sync_port"
    create_all_records "$zone"
    verify_all_records "$mode" "$dns_port"
    stop_server
    rm -rf "$CURRENT_BADGER_DIR"
    echo "[$mode] ok"
}

main() {
    need_cmd go
    need_cmd dig
    need_cmd jq

    mkdir -p "$BIN_DIR"
    echo "building local go53 server and go53ctl"
    (cd "$ROOT_DIR" && GOCACHE="$TMP_ROOT/gocache" go build -o "$SERVER_BIN" ./cmd/server && GOCACHE="$TMP_ROOT/gocache" go build -o "$CTL_BIN" ./cmd/go53ctl)

    run_mode primary 12053 18053 153530
    run_mode distributed 12054 18054 153531

    echo "all rtype integration checks passed"
}

main "$@"
