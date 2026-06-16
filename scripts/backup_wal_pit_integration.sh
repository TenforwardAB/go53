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

main() {
	need_cmd go
	need_cmd tar
	need_cmd sed

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

	ctl backup create --out "$BACKUP_FILE"
	[[ -s "$BACKUP_FILE" ]] || fail "backup file was not created"
	local base_seq
	base_seq="$(snapshot_end_seq)"
	[[ "$base_seq" =~ ^[0-9]+$ ]] || fail "could not read snapshot_end_seq from backup manifest"

	ctl records add pit.test. A '{"name":"api","ttl":300,"ip":"192.0.2.20"}' >/dev/null
	require_present "api.pit.test."
	ctl backup wal-follow --dir "$WAL_ARCHIVE_DIR" --after "$base_seq" --once
	PIT_WAL_FILE="$(find "$WAL_ARCHIVE_DIR" -type f -name 'go53-wal-*.g53wal' | sort | tail -1)"
	[[ -s "$PIT_WAL_FILE" ]] || fail "PIT WAL file was not created"

	ctl records add pit.test. A '{"name":"late","ttl":300,"ip":"192.0.2.30"}' >/dev/null
	require_present "late.pit.test."

	ctl restore backup "$BACKUP_FILE"
	require_present "www.pit.test."
	require_absent "api.pit.test."
	require_absent "late.pit.test."

	ctl restore wal "$PIT_WAL_FILE"
	require_present "www.pit.test."
	require_present "api.pit.test."
	require_absent "late.pit.test."

	echo "backup/WAL PIT integration passed"
}

main "$@"
