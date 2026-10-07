
# go53
[![Matrix Chat](https://img.shields.io/badge/chat-%23go53%3Amatrix.org-479ab5?logo=matrix&logoColor=white)](https://matrix.to/#/#go53:matrix.org)
![coverage_badge.svg](docs/images/coverage_badge.svg)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=TenforwardAB_go53&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=TenforwardAB_go53)

**go53** is a focused, API-driven authoritative DNS server written in Go. It is designed to be lightweight, fast, and easy to deploy, while offering extensibility and transparency through a well-structured API and modern design principles.

## Try go53 with webadmin

You can try go53 through our browser-based admin UI,
[go53-webadmin](https://github.com/TenforwardAB/go53-webadmin).

Public demo:

- URL: [https://demo.go53.eu](https://demo.go53.eu)
- Username: `go53_admin`
- Password: `go53_admin`

The demo runs go53 with a resettable `go53.demo.` DNSSEC zone and is intended
for quick evaluation of zone management, records, DNSSEC keys, distributed mode,
and the webadmin workflow.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/TenforwardAB/go53/main/scripts/install.sh | sudo bash
```

This installs the `go53` server and the `go53ctl` CLI with a systemd unit. See
[Installation](docs/INSTALLATION.md) for manual binaries, [Containers](docs/CONTAINER.md)
for Docker/Compose, and [Releases](docs/RELEASES.md) for per-release upgrade notes.

## Why go53?

Many existing DNS solutions attempt to cover both recursive and authoritative functionality, often resulting in bloated systems with steep learning curves or poor automation support. In contrast, `go53` is built from scratch to provide a clean, authoritative-only DNS server that is easy to manage through a structured API.

The goal of go53 is to bring clarity to authoritative DNS management, enabling sysadmins, DevOps engineers, and infrastructure teams to define and automate DNS zones without dealing with file-based or manual processes. By limiting its scope, go53 delivers predictable behavior and high performance while remaining flexible to integrate into modern infrastructure.

## Architecture

- **Written in Go**: A modern systems language with built-in concurrency and static binaries.
- **In-memory read path**: All active zones are served from memory. Storage is read at startup and written on mutation; the query path never touches disk.
- **Embedded storage**: [BadgerDB](https://github.com/hypermodeinc/badger) keyed by zone name, with no external database to operate.
- **API first**: Zones, records, TSIG keys, DNSSEC keys, backups and runtime config are all managed over HTTP, with a local Unix admin socket as the break-glass path.

## Project Snapshot

- **Authoritative DNS**: UDP/TCP DNS serving with zone data managed through HTTP API routes.
- **DNSSEC**: Query-time signing, cached RRSIGs, NSEC/NSEC3 denial, and key lifecycle metadata.
- **Distributed mode**: Persistent TLS socket replication with signed events, vector clocks, and Merkle repair.
- **Operations**: Full backups, WAL export and point-in-time restore, health probes, and per-client rate limiting.

## Implemented

- **Authoritative DNS over UDP and TCP**
  Authoritative query handling, TCP fallback paths, CHAOS version response, and no recursive service scope.
  References: RFC 1034, RFC 1035, RFC 7766.

- **EDNS-aware responses**
  Configurable EDNS enablement, UDP payload sizing, and EDNS COOKIE/OPT validation for modern resolver interoperability.
  References: RFC 6891.

- **NSID support**
  EDNS0 NSID responses for node identification, emitted only when the client signals interest. Disabled by default via the `nsid` config knob.
  References: RFC 5001.

- **ANY-query policy**
  Configurable `any_query_policy`: a minimal HINFO answer or `REFUSED`, to limit amplification exposure.
  References: RFC 8482.

- **API-managed zones and RRsets**
  HTTP API routes for zone record creation, lookup, deletion, TSIG keys, DNSSEC keys, and runtime config.
  References: RFC 1035, JSON API.

- **API key authentication**
  Selectable API auth mode (`disabled`, `none`, `x-auth-key`) with constant-time key comparison on the TCP listener, and the local Unix admin socket as the always-available break-glass path gated by filesystem permissions.
  References: X-Auth-Key, operational.

- **Zone-file import and export**
  Import master-file zones and export the served zone through the API, including for DNSSEC-signed zones.
  References: RFC 1035, JSON API.

- **AXFR, IXFR, and NOTIFY paths**
  Zone transfer handling, SOA serial behavior, transfer ACLs, DNSSEC material in AXFR, and NOTIFY scheduling.
  References: RFC 1995, RFC 1996, RFC 5936.

- **TSIG validation and key API**
  TSIG key storage, API management, transfer enforcement option, and distributed TSIG key replication.
  References: RFC 2845, RFC 4635.

- **Catalog zones**
  Catalog-zone workflow for secondary provisioning, including multi-primary membership and catalog primary TSIG.
  References: RFC 9432.

- **DNSSEC signing and denial**
  DNSKEY/RRSIG support, query-time signing cache, NSEC/NSEC3 chains, wildcard denial, and no-data proofs.
  References: RFC 4033, RFC 4034, RFC 4035, RFC 5155.

- **DNSSEC key lifecycle and parent signaling**
  KSK/ZSK metadata, rollover helpers, revoke/retire timing, DS, CDS, and CDNSKEY endpoints.
  References: RFC 5011, RFC 7344, RFC 8078.

- **CNAME and DNAME DNSSEC chains**
  Signed answer-chain handling and denial coverage around target and no-data cases.
  References: RFC 6672, RFC 4035.

- **Canonical DNSSEC ordering**
  Canonical owner-name comparison for escaped labels, case folding, IDNA, root, and wildcard names.
  References: RFC 4034.

- **CAA records**
  Certificate Authority Authorization RRsets over the API and the signed query path.
  References: RFC 8659.

- **ALIAS records**
  Apex-safe ALIAS pseudo-records flattened to A/AAAA from multiple resolvers, refreshed on a freshness window and served like ordinary signed RRsets.
  References: pseudo-RR, operational.

- **Distributed mode**
  Signed event replication over persistent TCP/TLS, vector clocks, Merkle repair, and config/key/zone event coverage.
  References: TLS 1.3, Ed25519, internal go53 frame protocol.

- **go53ctl cluster onboarding**
  JWT invite creation, one-time invite consume, self-registering joins, generated distributed node keys, and cluster node removal.
  References: RFC 7519, EdDSA.

- **Backup, WAL, and point-in-time restore**
  Full backups and write-ahead-log exports over the local admin socket, archiver-aware retention, and restore to a point in time including DNSSEC key state.
  References: `go53ctl backup`, operational.

- **Health and readiness probes**
  Unauthenticated `/healthz` and `/readyz` HTTP endpoints for liveness and readiness checks behind load balancers and orchestrators.
  References: operational, Kubernetes.

- **Per-client rate limiting**
  Opt-in per-source-IP token bucket on the UDP query path via `rate_limit_qps`; disabled by default.
  References: operational.

- **In-memory read path with persistent mutations**
  Zone and DNSSEC key material are loaded for read-heavy serving, while Badger persists changes.
  References: BadgerDB, go53 storage model.

- **Canonical, case-insensitive names**
  Zone and owner names are stored and matched in canonical lower case with exact key lookups; existing data is migrated in place on upgrade.
  References: RFC 4343.

- **Query-path performance foundation**
  A per-zone owner index for existence, wildcard, referral and DNSSEC-denial checks; one shared record decoder for serving, transfers and signing; and an allocation-free name validator (23 ns, zero allocations). Positive answers 0.8-1.6 µs, NODATA 1.9 µs, NXDOMAIN 3.5 µs.
  Measured on an AMD Ryzen AI 9 365 (`GOMAXPROCS=20`) with records in the `encoding/json` storage shape, using the single-goroutine benchmarks in `dns/handler_bench_test.go`. These are best-case single-query latencies and are sensitive to `GOMAXPROCS`, so treat them as a floor rather than a capacity figure. Further benchmarking on server-grade CPUs is planned for a later release.
  References: performance, [notes](docs/internal/performance.md).

## DNSSEC and Replication

The current beta focus is validation quality: interoperability testing with common validating resolvers, transfer edge cases, and operational hardening around distributed cluster membership.

The DNSSEC implementation is built around RFC 4033/4034/4035 behavior, with NSEC3 coverage from RFC 5155 and parent signaling through CDS/CDNSKEY endpoints.

Distributed mode is go53's multi-node replication mode. Nodes exchange signed events over persistent socket transport, track vector-clock state, and use Merkle roots/branches for integrity repair.

## Future Work

These items remain planned or intentionally deferred until the beta test surface is stable. See the [roadmap](docs/roadmap.md) for the per-release breakdown.

- **API roles and token lifecycle**
  Operator roles, scoped tokens with rotation and expiry, and OIDC, on top of the existing API key authentication.

- **Resolver interoperability matrix**
  Automated validation against BIND, Knot, Unbound, PowerDNS Recursor, and common secondary setups.

- **DoT listener**
  Native DNS-over-TLS listener for authoritative service once the core DNS and auth surfaces settle.
  Reference: RFC 7858.

- **Metrics**
  Prometheus metrics for queries, DNSSEC signing and cache behavior, and structured query/error logging. Health and readiness endpoints are already in place.

- **Large-scale zone hosting and typed storage**
  Zone resolution independent of zone count, a canonical Merkle leaf hash negotiated per peer, and a single typed storage format with in-place migration.

## Documentation

- [Installation](docs/INSTALLATION.md) - install methods, systemd service, and first-run quickstart.
- [Containers](docs/CONTAINER.md) - container images and Compose deployment.
- [Administrator Guide](docs/guides/administrator-guide.md) - primary/secondary/distributed setup, API examples, DNSSEC, TSIG, transfers, and `go53ctl` workflows.
- [Backup and Restore](docs/guides/backup-and-restore.md) - backups, WAL retention, and point-in-time restore.
- [Config Reference](docs/reference/configuration.md) - every environment and live config parameter with type, default, and implementation effect.
- [API Reference](docs/api/openapi.yaml) - OpenAPI spec for the admin API.
- [Concepts](docs/concepts/) - DNSSEC behavior, distributed replication, and the query path and record storage model.
- [Internals](docs/internal/) - storage layout, zone model, RFC compliance, and performance notes.
- [Releases](docs/RELEASES.md) - release process and per-release operator notes.
- [Roadmap](docs/roadmap.md) - planned work per release.

## When NOT to use go53

If you're looking for a DNS server that supports:

- Recursive DNS resolution
- Service discovery
- Dynamic backend plugins (e.g. for Kubernetes)
- Load balancing or policy routing

...then [**CoreDNS**](https://coredns.io) may be a better fit. It supports a wide range of plugins and is designed to work well in containerized and service-mesh environments.

## License

Copyright 2025 go53 Project.

This project is licensed under the EUPL-1.2.
See the [LICENSE](./LICENSE) file for details.

It also includes third-party software:
- `miekg/dns` (BSD-3-Clause) - see [NOTICE](./NOTICE) and [LICENSES/](./LICENSES)
- `hypermodeinc/badger` (Apache License 2.0) - see [NOTICE](./NOTICE) and [LICENSES/](./LICENSES)
