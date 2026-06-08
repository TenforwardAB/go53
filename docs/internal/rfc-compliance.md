# go53 Authoritative DNS RFC Compliance Matrix

Scope: authoritative DNS service only. Recursive resolver behavior, DoH/DoT,
Dynamic Update, and uncommon RR-specific extensions are tracked as out of scope
unless explicitly implemented.

| Area | RFCs | Status | Notes |
| --- | --- | --- | --- |
| Core DNS message/query handling | RFC 1034, RFC 1035, RFC 2181, RFC 9619 | partial | QUERY with QDCOUNT=1 is supported; unsupported opcodes return NOTIMP; unknown zones are non-authoritative REFUSED by default. |
| Authoritative positive answers | RFC 1034, RFC 1035, RFC 2181 | partial | RRset TTL uniformity and CNAME coexistence are enforced on normal mutations. |
| Negative answers | RFC 2308 | partial | NXDOMAIN/NODATA include SOA for known zones; DNSSEC denial records are included and signed when DO is set. |
| EDNS(0) | RFC 6891, RFC 5001 | partial | EDNS version 0, UDP payload capping, DO mirroring, and optional NSID are supported. |
| TCP transport | RFC 7766 | partial | UDP and TCP listeners are present; response truncation is applied to UDP only. |
| ANY minimization | RFC 8482 | supported | Default policy returns minimal HINFO; config may refuse. |
| AXFR/IXFR/NOTIFY | RFC 1995, RFC 1996, RFC 5936 | partial | AXFR, NOTIFY, and IXFR fallback paths exist; BIND 9.18 primary/secondary interop passes in both directions. Journaled IXFR deltas remain out of scope. |
| Catalog zones | RFC 9432 | partial | Schema version 2 catalog zones can be maintained and followed for secondary member-zone discovery. Member PTR handling, startup/periodic refresh, NOTIFY-triggered fetches, and pruning removed catalog members are implemented; BIND-style custom properties such as primaries/masters and TSIG metadata are not yet implemented. |
| TSIG | RFC 2845, RFC 4635 | partial | TSIG keys and transfer enforcement are supported; broader TSIG use outside configured transfer paths is not complete. |
| DNSSEC | RFC 4033, RFC 4034, RFC 4035, RFC 5155 | partial | DNSKEY/RRSIG, NSEC/NSEC3, wildcard denial, query-time signing, longest authoritative zone matching, case-insensitive owner lookups, and RFC 4034 wildcard RRSIG label counts exist; BIND 9.18 strict delv interop passes for positive, negative, wildcard, and AXFR checks. |
| DNSSEC parent signaling | RFC 7344, RFC 8078 | supported | DS/CDS/CDNSKEY endpoints and records are implemented. |
| Recursion | RFC 1034, RFC 1035 resolver behavior | out of scope | go53 is authoritative-only and returns RA=false. |
