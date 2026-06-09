#!/usr/bin/env bash
set -Eeuo pipefail

# Integration test for DNSSEC zone/key import:
#   - signed zone import with --dnssec preserve becomes read-only
#   - private-key import accepts generated dummy keys for supported algorithms

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_ROOT="${TMPDIR:-/tmp}/go53-dnssec-import.$$"
BIN_DIR="$TMP_ROOT/bin"
SERVER_BIN="$BIN_DIR/go53-server"
CTL_BIN="$BIN_DIR/go53ctl"

BASE_PORT="${BASE_PORT:-$((15000 + ($$ % 20000)))}"
DNS_PORT="${DNS_PORT:-$BASE_PORT}"
API_PORT="${API_PORT:-$((BASE_PORT + 1))}"
SOCKET="$TMP_ROOT/admin.sock"
BADGER_DIR="$TMP_ROOT/badger"
SERVER_LOG="$TMP_ROOT/server.log"
SERVER_PID=""

PRESERVE_ZONE="preserve-import.test."
KEY_ZONE="key-import.test."

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
	if [[ -f "$SERVER_LOG" ]]; then
		echo "--- server log tail ($SERVER_LOG) ---" >&2
		tail -80 "$SERVER_LOG" >&2 || true
	fi
	exit 1
}

need_cmd() {
	command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

api() {
	"$CTL_BIN" api --socket "$SOCKET" "$@"
}

wait_for_socket() {
	local deadline=$((SECONDS + 20))
	while ((SECONDS < deadline)); do
		if [[ -S "$SOCKET" ]] && api GET /api/config >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.2
	done
	fail "server did not expose admin socket: $SOCKET"
}

wait_for_dns() {
	local deadline=$((SECONDS + 20))
	while ((SECONDS < deadline)); do
		if dig @127.0.0.1 -p "$DNS_PORT" version.bind TXT CH +time=1 +tries=1 +short >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.2
	done
	fail "server did not answer DNS on 127.0.0.1:$DNS_PORT"
}

write_preserve_zone() {
	local zone_file="$TMP_ROOT/preserve-import.zone"
	cat >"$zone_file" <<ZONE
\$ORIGIN $PRESERVE_ZONE
\$TTL 300
@ IN SOA ns1.$PRESERVE_ZONE hostmaster.$PRESERVE_ZONE 1 3600 600 86400 300
@ IN NS ns1.$PRESERVE_ZONE
ns1 IN A 192.0.2.53
www IN A 192.0.2.10
@ IN DNSKEY 257 3 15 G0sLtp9EyPkNlDG+e8H/fjDMEDLUwcmfR2CIEOzwqR8=
www IN RRSIG A 15 3 300 20300101000000 20260101000000 12345 $PRESERVE_ZONE WfOe3DWVdxF/jksVKYk0LlTOGpfcMsdI9nU4gCHUzAc=
ZONE
	echo "$zone_file"
}

write_key_generator() {
	local helper="$TMP_ROOT/generate_dummy_keys.go"
	cat >"$helper" <<'GO'
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type keyFile struct {
	Format  string `json:"format"`
	Version int    `json:"version"`
	Source  string `json:"source"`
	Zone    string `json:"zone"`
	Keys    []key  `json:"keys"`
}

type key struct {
	SourceKeyID      string `json:"source_key_id"`
	Role             string `json:"role"`
	Flags            uint16 `json:"flags"`
	Algorithm        string `json:"algorithm"`
	AlgorithmNumber  uint8  `json:"algorithm_number"`
	KeyTag           uint16 `json:"keytag"`
	PrivateKeyFormat string `json:"private_key_format"`
	PrivateAlgorithm string `json:"private_algorithm"`
	PrivateKey       string `json:"private_key"`
}

func main() {
	if len(os.Args) != 3 {
		panic("usage: generate_dummy_keys OUT_DIR ZONE")
	}
	outDir, zone := os.Args[1], os.Args[2]
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		panic(err)
	}
	mustECDSA(outDir, zone, "ECDSAP256SHA256", 13, elliptic.P256(), 32)
	mustECDSA(outDir, zone, "ECDSAP384SHA384", 14, elliptic.P384(), 48)
	mustED25519(outDir, zone)
}

func mustECDSA(outDir, zone, name string, alg uint8, curve elliptic.Curve, size int) {
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	scalar := leftPad(priv.D.Bytes(), size)
	pub := append(leftPad(priv.X.Bytes(), size), leftPad(priv.Y.Bytes(), size)...)
	writeKey(outDir, zone, name, alg, scalar, keyTag(257, alg, pub))
}

func mustED25519(outDir, zone string) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	writeKey(outDir, zone, "ED25519", 15, priv.Seed(), keyTag(257, 15, pub))
}

func writeKey(outDir, zone, name string, alg uint8, private []byte, tag uint16) {
	path := filepath.Join(outDir, name+".key")
	data, err := json.MarshalIndent(keyFile{
		Format:  "go53-dnssec-private-keys",
		Version: 1,
		Source:  "go53 integration test",
		Zone:    zone,
		Keys: []key{{
			SourceKeyID:      "dummy-" + name,
			Role:             "CSK",
			Flags:            257,
			Algorithm:        name,
			AlgorithmNumber:  alg,
			KeyTag:           tag,
			PrivateKeyFormat: "raw",
			PrivateAlgorithm: name,
			PrivateKey:       base64.StdEncoding.EncodeToString(private),
		}},
	}, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		panic(err)
	}
	fmt.Printf("%s\t%d\t%s\n", name, tag, path)
}

func leftPad(in []byte, size int) []byte {
	if len(in) > size {
		panic("value wider than expected")
	}
	out := make([]byte, size)
	copy(out[size-len(in):], in)
	return out
}

func keyTag(flags uint16, alg uint8, pub []byte) uint16 {
	rdata := make([]byte, 4+len(pub))
	rdata[0] = byte(flags >> 8)
	rdata[1] = byte(flags)
	rdata[2] = 3
	rdata[3] = alg
	copy(rdata[4:], pub)

	var ac uint32
	for i, b := range rdata {
		if i&1 == 0 {
			ac += uint32(b) << 8
		} else {
			ac += uint32(b)
		}
	}
	ac += (ac >> 16) & 0xffff
	return uint16(ac & 0xffff)
}
GO
	echo "$helper"
}

start_go53() {
	mkdir -p "$BIN_DIR" "$BADGER_DIR"
	echo "building local go53 server and go53ctl"
	(
		cd "$ROOT_DIR"
		GOCACHE="$TMP_ROOT/gocache" go build -o "$SERVER_BIN" ./cmd/server
		GOCACHE="$TMP_ROOT/gocache" go build -o "$CTL_BIN" ./cmd/go53ctl
	)

	echo "starting go53 on 127.0.0.1:$DNS_PORT"
	(
		cd "$ROOT_DIR"
		exec env BIND_HOST=127.0.0.1 \
			DNS_PORT=":$DNS_PORT" \
			API_PORT=":$API_PORT" \
			BADGER_DIR="$BADGER_DIR" \
			ADMIN_SOCKET="$SOCKET" \
			ADMIN_SOCKET_GROUP="" \
			"$SERVER_BIN"
	) >"$SERVER_LOG" 2>&1 &
	SERVER_PID=$!

	wait_for_socket
	api PATCH /api/config '{"mode":"primary","allow_axfr":true,"dnssec_enabled":false,"enforce_tsig":false}' >/dev/null \
		|| fail "failed to configure go53"
	wait_for_dns
}

assert_preserve_import() {
	local zone_file
	zone_file="$(write_preserve_zone)"

	echo "testing --dnssec preserve zone import"
	"$CTL_BIN" zones import --socket "$SOCKET" --dnssec preserve "$PRESERVE_ZONE" "$zone_file" >/dev/null \
		|| fail "preserve zone import failed"

	local soa
	soa="$(dig @127.0.0.1 -p "$DNS_PORT" "$PRESERVE_ZONE" SOA +short +time=1 +tries=1)"
	[[ -n "$soa" ]] || fail "preserve imported zone is not served"

	local output
	if output="$("$CTL_BIN" records add --socket "$SOCKET" "$PRESERVE_ZONE" A '{"name":"blocked","ttl":300,"ip":"192.0.2.55"}' 2>&1)"; then
		fail "record mutation unexpectedly succeeded for preserve read-only zone"
	fi
	grep -qi "read-only" <<<"$output" || fail "read-only mutation failed without read-only error; output: $output"
}

assert_key_imports() {
	local helper key_dir manifest
	helper="$(write_key_generator)"
	key_dir="$TMP_ROOT/keys"
	manifest="$TMP_ROOT/key_manifest.tsv"

	echo "generating dummy private-key import files"
	GOCACHE="$TMP_ROOT/gocache" go run "$helper" "$key_dir" "$KEY_ZONE" >"$manifest"

	echo "testing private-key imports for supported algorithms"
	while IFS=$'\t' read -r alg tag path; do
		[[ -n "$alg" && -n "$tag" && -n "$path" ]] || continue
		"$CTL_BIN" dnskeys import-private --socket "$SOCKET" --key-file "$path" >/dev/null \
			|| fail "private-key import failed for $alg"
		local count
		count="$("$CTL_BIN" dnskeys list --socket "$SOCKET" | jq --arg zone "${KEY_ZONE%.}" --arg alg "$alg" --argjson tag "$tag" \
			'[.[] | select(.zone == $zone and .algorithm == $alg and .key_tag == $tag and .flags == 257)] | length')"
		[[ "$count" == "1" ]] || fail "imported key not found exactly once for $alg keytag=$tag; count=$count"
		echo "  imported $alg keytag=$tag"
	done <"$manifest"
}

need_cmd go
need_cmd dig
need_cmd jq

start_go53
assert_preserve_import
assert_key_imports

echo "DNSSEC preserve/key import integration test passed"
