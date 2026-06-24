---
title: "Roadmap"
weight: 5
description: "go53 release roadmap, auto-generated from the go53 Roadmap GitHub Project."
---

# go53 Roadmap

go53 evolves toward a modern, secure, high-performance authoritative DNS
server with first-class DNSSEC and distributed operation. The project
prioritizes, in order: **reliability, RFC compliance, operational simplicity,
performance, distributed resilience, and new features** — stability and
maintainability over feature count.

> This page is generated automatically from the
> [go53 Roadmap project](https://github.com/orgs/TenforwardAB/projects/10).
> Status reflects the project board; see the board for live detail.

## Releases

### Release 0.79

**Theme:** Operations &nbsp;·&nbsp; **Goal:** Backup & Stability

| Issue | Title | Theme | Status |
|-------|-------|-------|--------|
| [#20](https://github.com/TenforwardAB/go53/issues/20) | Add rate limiting and abuse protection | Security | Done |
| [#46](https://github.com/TenforwardAB/go53/issues/46) | Release 0.79: Backup, WAL and point-in-time restore | Operations | Done |

### Release 0.80

**Theme:** Performance Foundation &nbsp;·&nbsp; **Goal:** Remove obvious performance bottlenecks and establish benchmarks

| Issue | Title | Theme | Status |
|-------|-------|-------|--------|
| [#42](https://github.com/TenforwardAB/go53/issues/42) | Enhancement: Remove hot-path query logging | Performance | — |
| [#43](https://github.com/TenforwardAB/go53/issues/43) | Enhancement: Normalize DNS names at write-time and eliminate fallback scans | Performance | — |
| [#45](https://github.com/TenforwardAB/go53/issues/45) | Enhancement: Reduce configuration lock usage on DNS request path | Performance | — |

### Release 0.81

**Theme:** Performance &nbsp;·&nbsp; **Goal:** RRset Optimization

| Issue | Title | Theme | Status |
|-------|-------|-------|--------|
| [#40](https://github.com/TenforwardAB/go53/issues/40) | Enhancement: Cache pre-built RRsets to reduce query-time allocations | Performance | — |

### Release 0.82

**Theme:** Performance &nbsp;·&nbsp; **Goal:** Large Scale Zone Hosting

| Issue | Title | Theme | Status |
|-------|-------|-------|--------|
| [#41](https://github.com/TenforwardAB/go53/issues/41) | Enhancement: Optimize authoritative zone lookup | Performance | — |

### Release 0.83

**Theme:** DNSSEC &nbsp;·&nbsp; **Goal:** DNSSEC Production Hardening

| Issue | Title | Theme | Status |
|-------|-------|-------|--------|
| [#22](https://github.com/TenforwardAB/go53/issues/22) | Verifera validate resolver interoperabilitet | DNSSEC | — |
| [#26](https://github.com/TenforwardAB/go53/issues/26) | Improve documentation for core DNS and replication logic | Documentation | — |
| [#27](https://github.com/TenforwardAB/go53/issues/27) | Implement RSA DNSSEC private-key import for external signer migration | DNSSEC | — |
| [#44](https://github.com/TenforwardAB/go53/issues/44) | Enhancement: Add DNSSEC signing and cache metrics | DNSSEC | — |

### Release 0.84

**Theme:** Distributed &nbsp;·&nbsp; **Goal:** Distributed Hardening

_No tickets assigned yet._

### Release 0.85

**Theme:** Operations &nbsp;·&nbsp; **Goal:** Production Operations

| Issue | Title | Theme | Status |
|-------|-------|-------|--------|
| [#15](https://github.com/TenforwardAB/go53/issues/15) | Add Prometheus metrics export | Operations | — |
| [#16](https://github.com/TenforwardAB/go53/issues/16) | Add structured logging with trace IDs | Operations | — |
| [#17](https://github.com/TenforwardAB/go53/issues/17) | Support DNSTAP logging (optional) | Operations | — |
| [#25](https://github.com/TenforwardAB/go53/issues/25) | Standardize admin API error responses as JSON | Operations | — |
| [#28](https://github.com/TenforwardAB/go53/issues/28) | Support Offline Mode in go53ctl Using Direct BadgerDB Access (Future also postgres) | Operations | — |

### Release 0.86

**Theme:** Interoperability &nbsp;·&nbsp; **Goal:** Modern DNS Ecosystem Support

| Issue | Title | Theme | Status |
|-------|-------|-------|--------|
| [#37](https://github.com/TenforwardAB/go53/issues/37) | Add SSHFP and TLSA record types (RFC 4255 / RFC 6698 DANE) | Record Types | — |
| [#38](https://github.com/TenforwardAB/go53/issues/38) | Add SVCB and HTTPS record types (RFC 9460) | Record Types | — |

### Release 0.90

**Theme:** Release &nbsp;·&nbsp; **Goal:** Production Ready Community Edition

| Issue | Title | Theme | Status |
|-------|-------|-------|--------|
| [#47](https://github.com/TenforwardAB/go53/issues/47) | Security: Support encrypted backups and WAL archives | Operations | — |

### Release 1.0

**Theme:** Release &nbsp;·&nbsp; **Goal:** Recommended For Production

_No tickets assigned yet._

### Future / Unscheduled

Interesting ideas that are not currently roadmap priorities.

| Issue | Title | Theme | Status |
|-------|-------|-------|--------|
| [#6](https://github.com/TenforwardAB/go53/issues/6) | Add audit logging for query and zone changes | Security | — |
| [#8](https://github.com/TenforwardAB/go53/issues/8) | Implement Dynamic DNS (RFC 2136) | Interoperability | — |
| [#19](https://github.com/TenforwardAB/go53/issues/19) | Add ACME-DNS support for DNS-01 challenge | Future | — |
| [#21](https://github.com/TenforwardAB/go53/issues/21) | Support Response Policy Zones (RPZ) | Future | — |
| [#39](https://github.com/TenforwardAB/go53/issues/39) | Add DNS-over-HTTPS (DoH) support (RFC 8484) | Future | — |
| [#49](https://github.com/TenforwardAB/go53/issues/49) | API: MX payload field names + PATCH/DELETE owner-name form inconsistent (docs fixed for v1; v2 to correct) |  | — |

## Themes

| Theme | Scope |
|-------|-------|
| Performance | QPS, latency, memory, allocation pressure, lock contention |
| Operations | Production operations: metrics, backup/restore, offline tooling, health |
| DNSSEC | Signing, validation interoperability, key rollover/management, metrics |
| Distributed | Replication, vector clocks, Merkle trees, cluster & split-brain handling |
| Interoperability | Compatibility with external DNS software, RFCs, industry standards |
| Record Types | New RR type support (TLSA, SSHFP, SVCB, HTTPS, …) |
| Documentation | Developer and operator documentation |
| Security | Security hardening and auditing |
| Future | Interesting ideas not currently prioritized |

## How this roadmap works

- **Priority** — `P0 Critical` (must ship before the next release), `P1 High` (on the current roadmap; 10–15 in Ready/In Progress at most), `P2 Medium` (valid, not yet scheduled), `P3 Low` (nice-to-have).
- **Sprints** — two weeks, targeting one major item plus a few small ones; finishing work is favored over starting many in parallel.
- **Future** items remain open but are intentionally not assigned to a release.

The roadmap is successful when query latency drops, QPS rises, DNSSEC stays
correct, distributed clusters stay stable, operators can monitor and recover
easily, and external users adopt go53 in production.
