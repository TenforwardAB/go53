#!/usr/bin/env bash
set -Eeuo pipefail

DNS_SERVER="${DNS_SERVER:-127.0.0.1}"
OUT_DIR="${OUT_DIR:-.}"
PDNSUTIL="${PDNSUTIL:-pdnsutil}"

usage() {
	cat >&2 <<'EOF'
Usage: pdns_export_go53_zone.sh [--dnssec preserve|strip] ZONE [OUT_DIR]

Exports a PowerDNS-hosted zone into files intended for future go53 import:
  OUT_DIR/ZONE.zone  DNS master file from AXFR
  OUT_DIR/ZONE.key   go53 DNSSEC private-key import JSON

Options:
  --dnssec preserve  (default) Export the full AXFR verbatim, including the
                     existing DNSSEC material (DNSKEY/RRSIG/NSEC*/CDS/CDNSKEY).
                     Intended for `go53ctl zones import --dnssec preserve`.
  --dnssec strip     Drop this zone's own signing material so go53 can take
                     over signing. Strips DNSKEY, RRSIG, NSEC, NSEC3,
                     NSEC3PARAM, CDS and CDNSKEY. DS records are KEPT because
                     they are secure-delegation data for child zones, not this
                     zone's signing material. Import the resulting file as a
                     normal zone (without --dnssec preserve) and import the
                     accompanying .key file; go53 re-signs with the same keys,
                     so the parent DS stays valid (no rollover needed).

Environment:
  DNS_SERVER   AXFR source server for dig (default: 127.0.0.1)
  PDNSUTIL     pdnsutil binary path (default: pdnsutil)
  OUT_DIR      output directory when positional OUT_DIR is omitted (default: .)

Examples:
  scripts/pdns_export_go53_zone.sh solutrix.se.
  scripts/pdns_export_go53_zone.sh --dnssec strip solutrix.se. /tmp/go53-export
  DNS_SERVER=127.0.0.1 scripts/pdns_export_go53_zone.sh solutrix.se. /tmp/go53-export
EOF
	exit 1
}

need_cmd() {
	command -v "$1" >/dev/null 2>&1 || {
		echo "missing required command: $1" >&2
		exit 1
	}
}

zone_file_name() {
	local zone="${1%.}"
	printf '%s' "$zone"
}

export_zone_data() {
	local zone="$1"
	local out="$2"
	local mode="${3:-preserve}"

	{
		printf '$ORIGIN %s\n' "$zone"
		printf '$TTL 3600\n\n'
		dig @"$DNS_SERVER" "$zone" AXFR +noall +answer | awk -v zone="$zone" -v mode="$mode" '
BEGIN {
	soa_seen=0
}
{
	name=$1
	ttl=$2
	type=$4

	# In strip mode, drop this zone own signing material so go53 can take
	# over signing. DS is intentionally kept: it is secure-delegation data
	# for child zones, not this zone signing material.
	if (mode == "strip" && type ~ /^(DNSKEY|RRSIG|NSEC|NSEC3|NSEC3PARAM|CDS|CDNSKEY)$/)
		next

	if (type == "SOA") {
		soa_seen++
		if (soa_seen > 1)
			next

		mname=$5
		rname=$6
		serial=$7
		refresh=$8
		retry=$9
		expire=$10
		minimum=$11

		if (name == zone)
			name="@"
		else
			sub("\\." zone "$", "", name)

		printf "%-8s %s IN SOA %s %s (\n", name, ttl, mname, rname
		printf "        %s\n", serial
		printf "        %s\n", refresh
		printf "        %s\n", retry
		printf "        %s\n", expire
		printf "        %s )\n\n", minimum
		next
	}

	if (name == zone) {
		name="@"
	} else {
		sub("\\." zone "$", "", name)
	}

	content=""
	for (i=5; i<=NF; i++) {
		content=content $i " "
	}
	sub(/[ ]+$/, "", content)

	printf "%-8s %s IN %-8s %s\n", name, ttl, type, content
}
'
	} >"$out"
}

pdns_role_flags() {
	case "$1" in
	KSK) printf '257' ;;
	ZSK) printf '256' ;;
	CSK) printf '257' ;;
	*) printf '0' ;;
	esac
}

pdns_algorithm_number() {
	case "$1" in
	RSASHA256) printf '8' ;;
	RSASHA512) printf '10' ;;
	ECDSAP256SHA256) printf '13' ;;
	ECDSAP384SHA384) printf '14' ;;
	ED25519) printf '15' ;;
	ED448) printf '16' ;;
	*) printf '0' ;;
	esac
}

export_key_data() {
	local zone="$1"
	local out="$2"
	local tmp
	tmp="$(mktemp)"
	trap 'rm -f "$tmp"' RETURN

	jq -n \
		--arg format "go53-dnssec-private-keys" \
		--arg version "1" \
		--arg source "powerdns" \
		--arg zone "$zone" \
		'{format:$format, version:($version|tonumber), source:$source, zone:$zone, keys:[]}' >"$tmp"

	while read -r role active published size algorithm key_id location keytag; do
		[[ -n "$key_id" ]] || continue

		if [[ "$role" == "CSK" ]]; then
			{
				echo "WARNING: key $key_id is a CSK (combined signing key)."
				echo "         go53 has no CSK concept: it imports this as a KSK (flags 257) that"
				echo "         signs ONLY the DNSKEY RRset, so zone data (SOA/NS/MX/TXT/...) will be"
				echo "         left unsigned. After importing keys + zone, add a separate ZSK so go53"
				echo "         signs the data (the parent DS keeps pointing at this KSK, stays valid):"
				echo "             go53ctl dnskeys rollover ${zone} ZSK ${algorithm}"
				echo "             go53ctl zones import ${zone} <unsigned-zone-file>"
			} >&2
		fi

		local exported private_format private_algorithm private_key flags algorithm_number key_json
		exported="$("$PDNSUTIL" export-zone-key "$zone" "$key_id")"
		private_format="$(awk -F': *' '$1=="Private-key-format"{print $2}' <<<"$exported")"
		private_algorithm="$(awk -F': *' '$1=="Algorithm"{print $2}' <<<"$exported")"
		private_key="$(awk -F': *' '$1=="PrivateKey"{print $2}' <<<"$exported")"
		flags="$(pdns_role_flags "$role")"
		algorithm_number="$(pdns_algorithm_number "$algorithm")"

		key_json="$(jq -n \
			--arg source_key_id "$key_id" \
			--arg role "$role" \
			--arg active "$active" \
			--arg published "$published" \
			--arg size "$size" \
			--arg algorithm "$algorithm" \
			--arg algorithm_number "$algorithm_number" \
			--arg flags "$flags" \
			--arg location "$location" \
			--arg keytag "$keytag" \
			--arg private_key_format "$private_format" \
			--arg private_algorithm "$private_algorithm" \
			--arg private_key "$private_key" \
			'{
				source_key_id:$source_key_id,
				role:$role,
				flags:($flags|tonumber),
				algorithm:$algorithm,
				algorithm_number:($algorithm_number|tonumber),
				keytag:($keytag|tonumber),
				size:($size|tonumber),
				location:$location,
				pdns:{active:$active, published:$published},
				private_key_format:$private_key_format,
				private_algorithm:$private_algorithm,
				private_key:$private_key
			}')"

		jq --argjson key "$key_json" '.keys += [$key]' "$tmp" >"$tmp.next"
		mv "$tmp.next" "$tmp"
	done < <("$PDNSUTIL" list-keys "$zone" | awk '
		$2 ~ /^(KSK|ZSK|CSK)$/ && $7 ~ /^[0-9]+$/ { print $2, $3, $4, $5, $6, $7, $8, $9 }
	')

	mv "$tmp" "$out"
	trap - RETURN
}

main() {
	local dnssec_mode="preserve"
	local positional=()

	while [[ $# -gt 0 ]]; do
		case "$1" in
		--dnssec)
			dnssec_mode="${2:-}"
			shift 2
			;;
		--dnssec=*)
			dnssec_mode="${1#*=}"
			shift
			;;
		-h | --help)
			usage
			;;
		--)
			shift
			while [[ $# -gt 0 ]]; do
				positional+=("$1")
				shift
			done
			;;
		-*)
			echo "unknown option: $1" >&2
			usage
			;;
		*)
			positional+=("$1")
			shift
			;;
		esac
	done

	case "$dnssec_mode" in
	preserve | strip) ;;
	*)
		echo "invalid --dnssec mode: '$dnssec_mode' (expected 'preserve' or 'strip')" >&2
		usage
		;;
	esac

	[[ ${#positional[@]} -ge 1 ]] || usage
	local zone="${positional[0]}"
	OUT_DIR="${positional[1]:-$OUT_DIR}"

	need_cmd dig
	need_cmd jq
	need_cmd "$PDNSUTIL"

	zone="$(printf '%s.' "${zone%.}")"
	mkdir -p "$OUT_DIR"

	local base zone_out key_out
	base="$(zone_file_name "$zone")"
	zone_out="$OUT_DIR/$base.zone"
	key_out="$OUT_DIR/$base.key"

	export_zone_data "$zone" "$zone_out" "$dnssec_mode"
	export_key_data "$zone" "$key_out"

	printf 'exported zone: %s (dnssec=%s)\n' "$zone_out" "$dnssec_mode"
	printf 'exported keys: %s\n' "$key_out"
}

main "$@"
