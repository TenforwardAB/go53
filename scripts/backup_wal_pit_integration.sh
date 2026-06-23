#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_ROOT="${TMPDIR:-/tmp}/go53-backup-wal-pit.$$"
BIN_DIR="$TMP_ROOT/bin"
SERVER_BIN="$BIN_DIR/go53-server"
CTL_BIN="$BIN_DIR/go53ctl"
BADGER_DIR="$TMP_ROOT/badger"
ADMIN_SOCKET="$TMP_ROOT/admin.sock"
BACKUP_FILE="$TMP_ROOT/base.backup.tar"
PIT_WAL_FILE="$TMP_ROOT/pit.wal"
WAL_ARCHIVE_DIR="$TMP_ROOT/wal-archive"
SERVER_PID=""

cleanup() {
	if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
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
	if [[ -f "$TMP_ROOT/go53.log" ]]; then
		echo "--- go53 log tail ---" >&2
		tail -100 "$TMP_ROOT/go53.log" >&2 || true
	fi
	exit 1
}

need_cmd() {
	command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

ctl() {
	local command="$1"
	local subcommand="$2"
	shift 2
	"$CTL_BIN" "$command" "$subcommand" --socket "$ADMIN_SOCKET" "$@"
}

wait_for_socket() {
	local deadline=$((SECONDS + 20))
	while ((SECONDS < deadline)); do
		if [[ -S "$ADMIN_SOCKET" ]] && "$CTL_BIN" config get --socket "$ADMIN_SOCKET" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.2
	done
	fail "go53 did not expose admin socket: $ADMIN_SOCKET"
}

record_present() {
	local fqdn="$1"
	local name="${fqdn%.pit.test.}"
	"$CTL_BIN" records list-type --socket "$ADMIN_SOCKET" pit.test. A | grep -Eq "\"name\": \"($name|$fqdn)\""
}

require_present() {
	local fqdn="$1"
	record_present "$fqdn" || fail "expected $fqdn to exist"
}

require_absent() {
	local fqdn="$1"
	if record_present "$fqdn"; then
		fail "expected $fqdn to be absent"
	fi
}

snapshot_end_seq() {
	tar -xOf "$BACKUP_FILE" manifest.json | sed -n 's/.*"snapshot_end_seq": \([0-9][0-9]*\).*/\1/p'
}

# dnssec_present succeeds when pit.test. has DNSSEC keys visible through the
# (cache-backed) admin API. After a restore this only returns true if the DNSSEC
# key cache was reloaded, so it doubles as a regression guard for that reload.
dnssec_present() {
	"$CTL_BIN" dnskeys list --socket "$ADMIN_SOCKET" 2>/dev/null | grep -q 'pit\.test'
}

require_dnssec_present() {
	dnssec_present || fail "expected DNSSEC keys for pit.test. to be present"
}

require_dnssec_absent() {
	if dnssec_present; then
		fail "expected DNSSEC keys for pit.test. to be absent"
	fi
}

# wal_status_field reads a numeric field from GET /api/backup/wal/status over the
# admin socket (the JSON has no spaces, e.g. {"archived_seq":3,"last_seq":5}).
wal_status_field() {
	curl -s --unix-socket "$ADMIN_SOCKET" "http://localhost/api/backup/wal/status" \
		| sed -n "s/.*\"$1\":\([0-9][0-9]*\).*/\1/p"
}

# seg_end_seq extracts the trailing (TO) sequence from a wal-follow segment file
# named go53-wal-<FROM>-<TO>.g53wal, stripping the zero padding.
seg_end_seq() {
	basename "$1" | sed -n 's/^go53-wal-[0-9][0-9]*-0*\([0-9][0-9]*\)\.g53wal$/\1/p'
}

main() {
	need_cmd go
	need_cmd tar
	need_cmd sed
	need_cmd curl

	mkdir -p "$BIN_DIR" "$BADGER_DIR"
	echo "building local go53 server and go53ctl"
	(
		cd "$ROOT_DIR"
		GOCACHE="$TMP_ROOT/gocache" go build -o "$SERVER_BIN" ./cmd/server
		GOCACHE="$TMP_ROOT/gocache" go build -o "$CTL_BIN" ./cmd/go53ctl
	)

	(
		cd "$ROOT_DIR"
		exec env \
			BADGER_DIR="$BADGER_DIR" \
			ADMIN_SOCKET="$ADMIN_SOCKET" \
			ADMIN_SOCKET_GROUP="" \
			BIND_HOST="127.0.0.1" \
			DNS_PORT=":$((20000 + ($$ % 20000)))" \
			API_PORT=":$((40000 + ($$ % 20000)))" \
			"$SERVER_BIN" >"$TMP_ROOT/go53.log" 2>&1
	) &
	SERVER_PID=$!
	wait_for_socket

	ctl records add pit.test. SOA '{"ttl":300,"ns":"ns1.pit.test.","mbox":"hostmaster.pit.test.","serial":1,"refresh":3600,"retry":600,"expire":86400,"minimum":300}' >/dev/null
	ctl records add pit.test. NS '{"name":"@","ttl":300,"ns":"ns1.pit.test."}' >/dev/null
	ctl records add pit.test. A '{"name":"www","ttl":300,"ip":"192.0.2.10"}' >/dev/null
	require_present "www.pit.test."
	require_dnssec_absent

	ctl backup create --out "$BACKUP_FILE"
	[[ -s "$BACKUP_FILE" ]] || fail "backup file was not created"
	local base_seq
	base_seq="$(snapshot_end_seq)"
	[[ "$base_seq" =~ ^[0-9]+$ ]] || fail "could not read snapshot_end_seq from backup manifest"

	# No archiver has run yet, so the archived watermark must still be zero.
	local archived_before
	archived_before="$(wal_status_field archived_seq)"
	[[ "${archived_before:-0}" == "0" ]] || fail "archived_seq should be 0 before any archive, got '$archived_before'"

	# DNSSEC key creation happens AFTER the base backup, so the keys live only in
	# the WAL — proving point-in-time replay restores DNSSEC key state, not just
	# records.
	ctl dnskeys create pit.test. >/dev/null
	require_dnssec_present

	ctl records add pit.test. A '{"name":"api","ttl":300,"ip":"192.0.2.20"}' >/dev/null
	require_present "api.pit.test."
	ctl backup wal-follow --dir "$WAL_ARCHIVE_DIR" --after "$base_seq" --once
	PIT_WAL_FILE="$(find "$WAL_ARCHIVE_DIR" -type f -name 'go53-wal-*.g53wal' | sort | tail -1)"
	[[ -s "$PIT_WAL_FILE" ]] || fail "PIT WAL file was not created"

	# wal-follow acknowledges the durably-archived sequence; the server's archived
	# watermark must advance to the segment's end sequence so retention will not
	# prune un-archived WAL.
	local seg_end archived_after
	seg_end="$(seg_end_seq "$PIT_WAL_FILE")"
	archived_after="$(wal_status_field archived_seq)"
	[[ "$seg_end" =~ ^[0-9]+$ ]] || fail "could not parse segment end sequence from $PIT_WAL_FILE"
	[[ "$archived_after" =~ ^[0-9]+$ ]] || fail "could not read archived_seq after archive"
	((archived_after > base_seq)) || fail "archived_seq ($archived_after) did not advance past base_seq ($base_seq)"
	[[ "$archived_after" == "$seg_end" ]] || fail "archived_seq ($archived_after) != archived segment end ($seg_end)"

	ctl records add pit.test. A '{"name":"late","ttl":300,"ip":"192.0.2.30"}' >/dev/null
	require_present "late.pit.test."

	ctl restore backup "$BACKUP_FILE"
	require_present "www.pit.test."
	require_absent "api.pit.test."
	require_absent "late.pit.test."
	# Base backup predates the DNSSEC keys; a correct restore reloads the key
	# cache, so the keys must now read as absent (a stale cache would still show
	# them).
	require_dnssec_absent

	ctl restore wal "$PIT_WAL_FILE"
	require_present "www.pit.test."
	require_present "api.pit.test."
	require_absent "late.pit.test."
	# DNSSEC key events replayed from the WAL and the cache was reloaded.
	require_dnssec_present

	echo "backup/WAL PIT integration passed (records + DNSSEC keys + archive watermark)"
}

main "$@"
