
# go53

**go53** is a focused, API-driven authoritative DNS server written in Go. It is designed to be lightweight, fast, and easy to deploy, while offering extensibility and transparency through a well-structured API and modern design principles.

## Why go53?

Many existing DNS solutions attempt to cover both recursive and authoritative functionality, often resulting in bloated systems with steep learning curves or poor automation support. In contrast, `go53` is built from scratch to provide a clean, authoritative-only DNS server that is easy to manage through a structured API.

The goal of go53 is to bring clarity to authoritative DNS management, enabling sysadmins, DevOps engineers, and infrastructure teams to define and automate DNS zones without dealing with file-based or manual processes. By limiting its scope, go53 delivers predictable behavior and high performance while remaining flexible to integrate into modern infrastructure.

## Architecture

- **Written in Go**: A modern systems language with built-in concurrency and static binaries.
- **In-memory zone handling**: All active zones are managed in-memory for ultra-fast lookup performance.
- **Pluggable storage backend**:
    - **BadgerDB (default)**: A fast, embeddable key-value store with no external dependencies.
    - **PostgreSQL**: Optional support for environments requiring shared state, high availability, or external DB integration.

## Core Protocol Support

| Protocol       | Status      | Notes                                  |
|----------------|-------------|----------------------------------------|
| UDP / TCP      | In progress | Standard DNS query protocols           |
| DoT (RFC 7858) | Planned     | DNS-over-TLS (decision pending)        |

## Planned v1 Features

Each feature is designed to serve real operational needs for authoritative-only DNS infrastructure:

- **API-Managed Zone Data**  
  Full CRUD API for managing DNS records, with optional zone file import/export support.

- **DNSSEC Signing**  
  On-the-fly DNSSEC support (starting with NSEC-based denial of existence), minimizing manual key management.

- **Zone Transfers (AXFR / IXFR)**  
  Authoritative support for full and incremental zone transfers to secondary servers.

- **Prometheus Metrics**  
  Built-in Prometheus-compatible metrics endpoint to monitor queries, performance, and errors.

- **Query and Error Logging**  
  Structured logs for incoming queries, responses, and server errors for observability and debugging.

- **ANY Query Blocking**  
  Blocks `ANY` queries by default to reduce abuse and unnecessary traffic.

- **NSID Support**  
  Adds support for identifying nameserver instances (e.g. in multi-node setups).

- **CHAOS Class Version Reporting**  
  `CH TXT version.bind` support to expose build/version for diagnostics.

## Client Support

A CLI/API-based client will be available to facilitate:

- Remote zone management via API
- Importing/exporting zone data
- Configuring DNSSEC, transfers, logging, and metrics
- Integration with CI/CD or infrastructure-as-code tooling

## When NOT to use go53

If you're looking for a DNS server that supports:

- Recursive DNS resolution
- Service discovery
- Dynamic backend plugins (e.g. for Kubernetes)
- Load balancing or policy routing

...then [**CoreDNS**](https://coredns.io) may be a better fit. It supports a wide range of plugins and is designed to work well in containerized and service-mesh environments.

---

© Copyleft ↄ 2025 go53 Project — Released under an open source license (to be announced).
## License

This project is licensed under the EUPL-1.2.  
See the [LICENSE](./LICENSE) file for details.

It also includes third-party software:
- `miekg/dns` (BSD-3-Clause) – see [NOTICE](./NOTICE) and [LICENSES/](./LICENSES)
- `hypermodeinc/bardger` (Apache-2 Common License) – see [NOTICE](./NOTICE) and [LICENSES/](./LICENSES)