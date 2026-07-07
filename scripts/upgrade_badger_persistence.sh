#!/usr/bin/env bash
set -euo pipefail

# Upgrade test: run a published go53 release in a pod, seed a zone with a broad
# set of record types onto a persistent Badger volume, then upgrade the pod to
# the go53 built from the current working tree using the SAME volume. Verifies
# that the persisted data survives the upgrade byte-for-byte (still served), and
# that a feature introduced after the old release (ALIAS) works on the new one.
# ALIAS is not seeded on the old side — it did not exist in 0.79.1.
#
# Tears the pod down and removes the volume + built image at the end.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_ID="${RUN_ID:-$(date +%Y%m%d%H%M%S)}"
WORK_DIR="${WORK_DIR:-/tmp/go53-upgrade-${RUN_ID}}"
KEEP_TMP="${KEEP_TMP:-0}"

OLD_IMAGE="${GO53_OLD_IMAGE:-ghcr.io/tenforwardab/go53:v0.79.1}"
NEW_IMAGE="${GO53_NEW_IMAGE:-localhost/go53-upgrade:${RUN_ID}}"
VOLUME="go53-upgrade-${RUN_ID}"
CONTAINER="go53-upgrade-${RUN_ID}"
ZONE="${ZONE:-upgrade.go53.test.}"

LOCAL_HOST="127.0.0.1"
API_PORT="${API_PORT:-18085}"
DNS_PORT="${DNS_PORT:-15359}"
ADMIN_SOCK="/run/go53/admin.sock"
API_BASE="http://${LOCAL_HOST}:${API_PORT}"

FAILURES=0

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
fail() { printf '  ✗ FAIL: %s\n' "$*"; FAILURES=$((FAILURES + 1)); }
pass() { printf '  ✓ %s\n' "$*"; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || { printf 'missing required command: %s\n' "$1" >&2; exit 1; }; }

cleanup() {
	podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
	podman volume rm "$VOLUME" >/dev/null 2>&1 || true
	if [[ "${KEEP_IMAGE:-0}" != "1" ]]; then
		podman rmi "$NEW_IMAGE" >/dev/null 2>&1 || true
	fi
	if [[ "$KEEP_TMP" != "1" ]]; then
		rm -rf "$WORK_DIR"
	else
		log "kept work dir: $WORK_DIR"
	fi
}
trap cleanup EXIT INT TERM

api() {
	local method="$1" path="$2" body="${3:-}"
	if [[ -n "$body" ]]; then
		curl -fsS -m 15 -X "$method" -H 'Content-Type: application/json' -d "$body" "${API_BASE}${path}"
	else
		curl -fsS -m 15 -X "$method" "${API_BASE}${path}"
	fi
}

add_record() {
	local rrtype="$1" payload="$2"
	api POST "/api/zones/${ZONE}/records/${rrtype}" "$payload" >/dev/null
}

dig_short() {
	local name="$1" rtype="$2"
	dig @"$LOCAL_HOST" -p "$DNS_PORT" "$name" "$rtype" +time=1 +tries=1 +short 2>/dev/null | sort
}

wait_health() {
	local deadline=$((SECONDS + 40))
	until curl -fsS -m 2 "${API_BASE}/healthz" >/dev/null 2>&1; do
		(( SECONDS >= deadline )) && { printf 'timeout waiting for /healthz\n' >&2; return 1; }
		sleep 0.3
	done
}

open_auth() {
	# A fresh node defaults to auth "disabled" (TCP API closed); open it to "none"
	# through the in-container admin socket. Idempotent once persisted in the volume.
	local deadline=$((SECONDS + 20))
	until podman exec --user 0:0 "$CONTAINER" \
		curl -fsS -m 2 --unix-socket "$ADMIN_SOCK" http://localhost/api/config >/dev/null 2>&1; do
		(( SECONDS >= deadline )) && { printf 'timeout waiting for admin socket in container\n' >&2; return 1; }
		sleep 0.3
	done
	podman exec --user 0:0 "$CONTAINER" \
		curl -fsS -m 5 --unix-socket "$ADMIN_SOCK" -X PATCH -H 'Content-Type: application/json' \
		-d '{"auth":{"mode":"none"}}' http://localhost/api/config >/dev/null
}

wait_api() {
	local deadline=$((SECONDS + 20))
	until curl -fsS -m 2 "${API_BASE}/api/config" >/dev/null 2>&1; do
		(( SECONDS >= deadline )) && { printf 'timeout waiting for TCP API\n' >&2; return 1; }
		sleep 0.3
	done
}

run_pod() {
	local image="$1"
	# --user 0:0 so the go53 process can create the admin socket under /run and
	# write the mounted volume (the image's default USER go53 cannot in rootless).
	podman run -d --name "$CONTAINER" --user 0:0 \
		-v "${VOLUME}:/data" \
		-e BADGER_DIR=/data/go53 \
		-e STORAGE_BACKEND=badger \
		-e BIND_HOST=0.0.0.0 \
		-e DNS_PORT=:53 \
		-e API_PORT=:8053 \
		-p "${API_PORT}:8053" \
		-p "${DNS_PORT}:53/udp" \
		-p "${DNS_PORT}:53/tcp" \
		"$image" >/dev/null
	wait_health
	open_auth
	wait_api
}

stop_pod() {
	podman rm -f "$CONTAINER" >/dev/null 2>&1 || true
}

seed_zone() {
	add_record SOA   "{\"ttl\":300,\"ns\":\"ns1.${ZONE}\",\"mbox\":\"hostmaster.${ZONE}\",\"refresh\":3600,\"retry\":600,\"expire\":86400,\"minimum\":300}"
	add_record NS    "{\"name\":\"@\",\"ttl\":300,\"ns\":\"ns1.${ZONE}\"}"
	add_record A     "{\"name\":\"ns1\",\"ttl\":300,\"ip\":\"192.0.2.1\"}"
	add_record A     "{\"name\":\"www\",\"ttl\":300,\"ip\":\"192.0.2.10\"}"
	add_record AAAA  "{\"name\":\"www\",\"ttl\":300,\"ip\":\"2001:db8::10\"}"
	add_record CNAME "{\"name\":\"alias\",\"ttl\":300,\"target\":\"www.${ZONE}\"}"
	add_record DNAME "{\"name\":\"old\",\"ttl\":300,\"target\":\"new.${ZONE}\"}"
	add_record MX    "{\"name\":\"@\",\"ttl\":300,\"host\":\"mail.${ZONE}\",\"priority\":10}"
	add_record CAA   "{\"name\":\"@\",\"ttl\":300,\"flag\":0,\"tag\":\"issue\",\"value\":\"letsencrypt.org\"}"
	add_record TXT   "{\"name\":\"txt\",\"ttl\":300,\"text\":\"go53 upgrade persistence\"}"
	add_record SPF   "{\"name\":\"spf\",\"ttl\":300,\"text\":\"v=spf1 -all\"}"
	add_record SRV   "{\"name\":\"_sip._tcp\",\"ttl\":300,\"priority\":10,\"weight\":5,\"port\":5060,\"target\":\"sip.${ZONE}\"}"
	add_record PTR   "{\"name\":\"ptr\",\"ttl\":300,\"ptr\":\"www.${ZONE}\"}"
}

# name|type queries whose served answer must be identical before and after upgrade.
QUERY_SPECS=(
	"ns1.${ZONE}|A"
	"www.${ZONE}|A"
	"www.${ZONE}|AAAA"
	"alias.${ZONE}|CNAME"
	"old.${ZONE}|DNAME"
	"${ZONE}|MX"
	"${ZONE}|CAA"
	"txt.${ZONE}|TXT"
	"_sip._tcp.${ZONE}|SRV"
	"ptr.${ZONE}|PTR"
	"${ZONE}|NS"
	"${ZONE}|SOA"
)

snapshot() {
	local spec name rtype
	for spec in "${QUERY_SPECS[@]}"; do
		name="${spec%%|*}"
		rtype="${spec##*|}"
		printf '%s %s = %s\n' "$name" "$rtype" "$(dig_short "$name" "$rtype" | tr '\n' ';')"
	done
}

need_cmd podman
need_cmd go
need_cmd dig
need_cmd curl

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"

log "building new image from the working tree: $NEW_IMAGE"
podman build -f "$ROOT_DIR/Dockerfile" -t "$NEW_IMAGE" "$ROOT_DIR" >"$WORK_DIR/build.log" 2>&1 \
	|| { tail -20 "$WORK_DIR/build.log"; printf 'image build failed\n' >&2; exit 1; }

log "pulling old image: $OLD_IMAGE"
podman pull "$OLD_IMAGE" >/dev/null

log "creating persistent volume: $VOLUME"
podman volume create "$VOLUME" >/dev/null

log "starting OLD pod ($OLD_IMAGE)"
run_pod "$OLD_IMAGE"

log "seeding zone ${ZONE} with a broad set of record types"
seed_zone

printf '\n=== OLD release serves the seeded records ===\n'
old_snapshot="$(snapshot)"
old_missing=0
while IFS= read -r line; do
	[[ "$line" == *"= "* && "$line" != *"= " ]] || { old_missing=$((old_missing + 1)); printf '  missing: %s\n' "$line"; }
done <<<"$old_snapshot"
if (( old_missing == 0 )); then
	pass "all ${#QUERY_SPECS[@]} record queries answered on the old release"
else
	fail "${old_missing} record(s) not served on the old release (seed problem)"
fi

log "stopping OLD pod (keeping the volume)"
stop_pod

printf '\n=== UPGRADE: start NEW pod on the SAME volume ===\n'
log "starting NEW pod ($NEW_IMAGE) on volume $VOLUME"
run_pod "$NEW_IMAGE"

new_snapshot="$(snapshot)"
if [[ "$new_snapshot" == "$old_snapshot" ]]; then
	pass "all persisted records survive the upgrade and are served identically"
else
	fail "served records changed across the upgrade"
	printf '  --- before ---\n%s\n  --- after ---\n%s\n' "$old_snapshot" "$new_snapshot"
fi

printf '\n=== NEW release adds a record type the old one lacked (ALIAS) ===\n'
if api POST "/api/zones/${ZONE}/records/ALIAS" "{\"name\":\"@\",\"ttl\":60,\"target\":\"www.${ZONE}\"}" >/dev/null 2>&1; then
	if api GET "/api/zones/${ZONE}/records/ALIAS" | grep -q "www.${ZONE}"; then
		pass "ALIAS accepted and stored on the upgraded node"
	else
		fail "ALIAS POST succeeded but the record is not retrievable"
	fi
else
	fail "ALIAS not accepted on the upgraded node"
fi

printf '\n=== Summary ===\n'
if (( FAILURES == 0 )); then
	printf 'ALL CHECKS PASSED\n'
	exit 0
else
	printf '%d CHECK(S) FAILED\n' "$FAILURES"
	exit 1
fi
