---
title: "Configuration Reference"
linkTitle: "Configuration"
weight: 10
description: "Technical reference for go53 environment parameters and persisted live config fields."
---

# Configuration Reference

Technical reference for process environment parameters and persisted live config
fields. This page describes what each parameter does in the implementation.

- Live config API: `GET`/`PATCH /api/config`
- Source: `config.LiveConfig`

## Deployment Parameters

Deployment parameters are read from environment variables during process startup.

| Parameter | Type | Default | Effect |
|-----------|------|---------|--------|
| `BIND_HOST` | string | `0.0.0.0` | Bind address used when starting the DNS UDP/TCP listeners and the HTTP API listener. |
| `DNS_PORT` | string | `:2053` | Port or host-port suffix used for the authoritative DNS UDP/TCP listeners. |
| `API_PORT` | string | `:8053` | Port or host-port suffix used for the HTTP API listener. |
| `STORAGE_BACKEND` | string | `badger` | Selects the storage implementation passed to `storage.Init`; currently `badger` is the implemented backend. |
| `POSTGRES_DSN` | string | `host=localhost port=5432 user=postgres password=postgres dbname=go53 sslmode=disable` | Stored in base config for a Postgres backend; current storage initialization does not enable Postgres. |
| `BADGER_DIR` | string | `/data/go53` | Filesystem directory opened by the Badger storage backend. |
| `ADMIN_SOCKET` | string | `/run/go53/admin.sock` | Path to the local admin Unix socket serving the full API gated by filesystem permissions instead of API tokens (break-glass local admin). Empty disables it. |
| `ADMIN_SOCKET_GROUP` | string | `go53_admin` | OS group granted access to the admin socket (mode `0660`). A missing group falls back to owner-only access. |

## Runtime Parameters

Runtime parameters are persisted in the `config` table and exposed through
`GET`/`PATCH /api/config`. Secret-bearing fields such as `auth.x_auth_key` are
not returned by `GET /api/config` and must be managed through the local admin
socket.

| JSON path | Type | Default | Effect |
|-----------|------|---------|--------|
| `log_level` | string | `info` | Runtime log level value stored in config and returned by the config API. |
| `mode` | string | `primary` | Selects primary, secondary, or distributed behavior for mutation blocking, NOTIFY/transfer behavior, DNSSEC signing paths, and distributed replication enablement. |
| `allow_transfer` | string | `127.0.0.1` | Comma-separated client address allowlist used for AXFR/IXFR authorization and NOTIFY target selection. |
| `allow_recursion` | bool | `false` | Reserved runtime flag for recursion behavior; go53 query handling is authoritative-focused. |
| `dnssec_enabled` | bool | `true` | Enables DNSSEC signing/material generation paths for authoritative answers and zone mutation maintenance when the node is not secondary. |
| `default_ttl` | int seconds | `3600` | Fallback TTL used when records or generated DNSSEC records do not carry an explicit TTL. |
| `version` | string | `go53 1.0.1` | Version string returned in CHAOS/version handling and distributed node discovery/status. |
| `max_udp_size` | int bytes | `1232` | Configured EDNS UDP payload size limit for DNS responses. |
| `enable_edns` | bool | `true` | Controls whether EDNS handling is enabled in DNS responses. |
| `rate_limit_qps` | int | `0` | Max queries per second per source IP (token bucket, burst equal to this value). `0` (default) disables it. Only UDP queries are limited; TCP, AXFR/IXFR and NOTIFY are exempt. Over-limit queries are dropped silently. Up to 100000 source IPs are tracked to bound memory; idle entries are reclaimed about 10 minutes after a source goes quiet. |
| `allow_axfr` | bool | `false` | Allows AXFR/IXFR response handling when client allowlist and TSIG policy also pass. |
| `default_ns` | string | `ns1.go53.local.` | Default nameserver value used by helper logic that needs an NS name when zone data does not provide one. |
| `enforce_tsig` | bool | `false` | Requires valid TSIG on DNS requests in TSIG validation paths and on AXFR/IXFR when enabled. |
| `any_query_policy` | string | `hinfo` | Authoritative ANY-query policy. `hinfo` returns a minimal RFC 8482-style HINFO answer; `refuse` returns REFUSED. |
| `unknown_zone_policy` | string | `refused` | Response policy for names outside all loaded authoritative zones. Default is non-authoritative REFUSED. |

## Authentication Parameters

The TCP admin API is gated by `auth.mode`. The local Unix admin socket bypasses
API-token authentication and is controlled by filesystem permissions; use it for
break-glass administration and for setting the API key.

| JSON path | Type | Default | Effect |
|-----------|------|---------|--------|
| `auth.mode` | string | `disabled` | Controls TCP API access. `disabled` returns `503`, `none` allows unauthenticated TCP API access, `x-auth-key` requires a valid static key, and `oidc` is reserved. |
| `auth.x_auth_key` | string | `""` | Static base62 API key used when `auth.mode=x-auth-key`. It must match `^[A-Za-z0-9]{48,}$`. If unset or invalid, the TCP API returns `403`. |
| `auth.oidc_issuer` | string | `""` | Reserved OIDC issuer URL. |
| `auth.oidc_audience` | string | `""` | Reserved OIDC audience/client id. |
| `auth.oidc_jwks_url` | string | `""` | Reserved JWKS endpoint override. |

Set or inspect the key locally with `go53ctl config set xauth_key --generate`,
`go53ctl config set xauth_key VALUE`, and `go53ctl config get xauth_key`. TCP
clients authenticate with `X-Auth-Key: VALUE`.

## Primary Parameters

| JSON path | Type | Default | Effect |
|-----------|------|---------|--------|
| `primary.notify_debounce_ms` | int milliseconds | `2000` | Delay used to coalesce NOTIFY sends after zone record changes. |
| `primary.ip` | string | `127.0.0.1` | Primary DNS address used by secondary transfer logic. |
| `primary.port` | int | `53` | Primary DNS port used by secondary transfer logic. |

## Secondary Parameters

| JSON path | Type | Default | Effect |
|-----------|------|---------|--------|
| `secondary.fetch_debounce_ms` | int milliseconds | `3000` | Delay used to coalesce secondary AXFR/IXFR fetch scheduling. |
| `secondary.min_fetch_interval_sec` | int seconds | `10` | Minimum interval between transfer fetches for the same zone. |
| `secondary.max_parallel_fetches` | int | `5` | Maximum number of concurrent secondary zone fetches. |
| `secondary.catalog_enabled` | bool | `false` | Maintains and follows an RFC 9432 catalog zone for dynamic secondary member-zone discovery. |
| `secondary.catalog_zone` | string | `_catalog.go53.` | Catalog zone name used as the secondary bootstrap catalog and primary-side member list. |

## DNSSEC Policy Parameters

DNSSEC rollover key generation supports `RSASHA256`, `RSASHA512`,
`ECDSAP256SHA256`, `ECDSAP384SHA384`, and `ED25519` (`ED25519` is the default).
Legacy SHA-1 and DSA algorithms, `ECC-GOST`, and `ED448` are not supported for
go53-generated signing keys; see the DNSSEC guide for the full algorithm table
and rationale.

| JSON path | Type | Default | Effect |
|-----------|------|---------|--------|
| `dnssec.validity_seconds` | int seconds | `604800` | RRSIG validity window for non-DNSKEY RRsets. |
| `dnssec.dnskey_validity_seconds` | int seconds | `1209600` | RRSIG validity window for DNSKEY RRsets. |
| `dnssec.refresh_before_seconds` | int seconds | `86400` | Remaining validity threshold that marks an existing RRSIG as needing refresh. |
| `dnssec.jitter_seconds` | int seconds | `3600` | Deterministic per-signature refresh offset used to spread RRSIG refresh timing. |
| `dnssec.inception_skew_seconds` | int seconds | `3600` | Amount by which signature inception is backdated to tolerate clock skew. |

## Distributed Parameters

| JSON path | Type | Default | Effect |
|-----------|------|---------|--------|
| `distributed.node_id` | string | `""` | Stable local node identity used for event origin, vector-clock keys, HELLO proof, node discovery, and generated TLS certificate identity. |
| `distributed.peers` | string | `""` | Comma-separated peer endpoints used by distributed outbound workers and resync logic. |
| `distributed.transport` | string | `http` | Selects distributed transport behavior; supported values are `http`, `tcp`, `tls`, and `mtls`. |
| `distributed.sync_bind_host` | string | `0.0.0.0` | Bind address used by the persistent distributed sync listener. |
| `distributed.sync_port` | string | `:53530` | Port or host-port suffix used by the persistent distributed sync listener and local discovery endpoint. |
| `distributed.private_key` | string | `""` | Base64 Ed25519 private key used for event signatures, HELLO challenge proof, public key derivation, and automatic TLS certificate generation. |
| `distributed.peer_public_keys` | object | `{}` | Map of trusted peer `node_id` to base64 Ed25519 public key used for event signature verification, HELLO verification, and TLS certificate public key pinning. |
| `distributed.push_timeout_ms` | int milliseconds | `2000` | Timeout used by distributed HTTP client paths, socket peer workers, vector fetches, event delivery, and Merkle repair requests. |
| `distributed.resync_interval_s` | int seconds | `30` | Interval for background distributed resync, vector comparison, and Merkle integrity repair. |

## Storage Shape

| Storage key/table | Type | Effect |
|-------------------|------|--------|
| `config/{top-level-json-field}` | JSON value | Each top-level live config field is persisted separately under the `config` table and merged with defaults at startup. |
| `zones/{zone}` | JSON zone data | Persistent zone storage loaded into the in-memory zone store during server startup. |
| `distributed-events/{event-id}` | JSON event | Distributed event log used for vector comparison, replay, and repair. |
| `distributed-vector/{node-id}` | JSON integer | Persisted local vector-clock state for distributed replication. |
| `distributed-entities/{entity}` | JSON entity clock | Per-entity conflict metadata used by distributed event dominance checks. |
| `distributed_invites/{jti}` | JSON invite record | Stored cluster invite usage state consumed when a pending join is approved, auto-accepted, or manually accepted. |
| `distributed_join_requests/{node-id}` | JSON join request | Pending self-registration requests submitted over the distributed sync endpoint. |

---

This page is a parameter reference. Operational setup examples live in the
[Guides](/guides/).
