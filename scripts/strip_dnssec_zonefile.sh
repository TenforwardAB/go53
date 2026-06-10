#!/usr/bin/env bash
set -Eeuo pipefail

# Strip a zone's own DNSSEC signing material from an existing zone file so that
# go53 can take over signing. Removes DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM,
# CDS and CDNSKEY. DS records are KEPT on purpose: they are secure-delegation
# data for child zones, not this zone's signing material.
#
# Parenthesised multi-line records (e.g. SOA) and records with an omitted owner
# name are handled correctly: a logical record is only emitted or dropped as a
# whole, never split. $ORIGIN/$TTL/$INCLUDE directives, comments and blank lines
# are passed through verbatim.

usage() {
	cat >&2 <<'EOF'
Usage: strip_dnssec_zonefile.sh [INPUT] [OUTPUT]

Strips this zone's DNSSEC signing material from a zone file so go53 can take
over signing (DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM, CDS, CDNSKEY removed;
DS kept as child-delegation data).

  INPUT    zone file to read (default: stdin)
  OUTPUT   file to write     (default: stdout)

Examples:
  strip_dnssec_zonefile.sh mailtrix.eu.zone > mailtrix.eu.unsigned.zone
  strip_dnssec_zonefile.sh mailtrix.eu.zone mailtrix.eu.unsigned.zone
  cat mailtrix.eu.zone | strip_dnssec_zonefile.sh > unsigned.zone
EOF
	exit 1
}

[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && usage

read -r -d '' AWK_PROG <<'AWK' || true
# Net parenthesis depth of a physical line, ignoring quoted strings and the
# part after an unquoted ';' comment.
function paren_delta(s,    i, c, d, inq) {
	d = 0; inq = 0
	for (i = 1; i <= length(s); i++) {
		c = substr(s, i, 1)
		if (c == "\"") { inq = !inq; continue }
		if (inq) continue
		if (c == ";") break
		if (c == "(") d++
		else if (c == ")") d--
	}
	return d
}

# Strip an unquoted ';' comment from a physical line.
function strip_comment(s,    i, c, inq, out) {
	out = ""; inq = 0
	for (i = 1; i <= length(s); i++) {
		c = substr(s, i, 1)
		if (c == "\"") { inq = !inq; out = out c; continue }
		if (c == ";" && !inq) break
		out = out c
	}
	return out
}

# Decide on the buffered logical record and emit it verbatim unless its type is
# part of this zone's signing material.
function decide_and_emit(    i, joined, ntok, tok, idx, t, type) {
	joined = ""
	for (i = 1; i <= buf_count; i++)
		joined = joined " " strip_comment(buf[i])
	gsub(/[()]/, " ", joined)

	ntok = split(joined, tok, /[ \t\r]+/)
	idx = 1
	while (idx <= ntok && tok[idx] == "") idx++

	# Owner name: present only when the first physical line has no leading WS.
	if (!rec_leadws) idx++

	# Skip optional TTL and CLASS in any order.
	while (idx <= ntok) {
		t = tok[idx]
		if (t ~ /^[0-9]+[smhdwSMHDW]?$/) { idx++; continue }
		if (t ~ /^(IN|CH|HS|CS|NONE|ANY|CLASS[0-9]+)$/) { idx++; continue }
		break
	}

	type = toupper(tok[idx])
	if (type ~ /^(DNSKEY|RRSIG|NSEC|NSEC3|NSEC3PARAM|CDS|CDNSKEY)$/)
		return

	for (i = 1; i <= buf_count; i++)
		print buf[i]
}

BEGIN { depth = 0; buf_count = 0 }

{
	if (depth == 0) {
		stripped = $0
		sub(/^[ \t]+/, "", stripped)
		# Directives, comment-only and blank lines: pass through as-is.
		if (stripped == "" || stripped ~ /^;/ || stripped ~ /^\$/) {
			print
			next
		}
		buf_count = 0
		rec_leadws = ($0 ~ /^[ \t]/)
	}

	buf[++buf_count] = $0
	depth += paren_delta($0)
	if (depth < 0) depth = 0
	if (depth == 0) { decide_and_emit(); buf_count = 0 }
}

END { if (buf_count > 0) decide_and_emit() }
AWK

in="${1:-/dev/stdin}"
out="${2:-}"

if [[ -n "$out" ]]; then
	tmp="$(mktemp)"
	trap 'rm -f "$tmp"' EXIT
	awk "$AWK_PROG" "$in" >"$tmp"
	mv "$tmp" "$out"
	trap - EXIT
else
	awk "$AWK_PROG" "$in"
fi
