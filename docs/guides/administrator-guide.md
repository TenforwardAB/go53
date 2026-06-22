---
title: "Administrator Guide"
linkTitle: "Administrator Guide"
weight: 10
description: "Configure go53, operate primary/secondary/distributed nodes, manage zones and records through the API, and run DNSSEC."
---

# go53 Administrator Guide

This page documents how to configure go53, operate primary, secondary, and
distributed nodes, manage zones and records through the API, and run DNSSEC with
stored keys and query-time signing.

- API base: `/api`
- Authoritative DNS only

## Installation

go53 ships as two self-contained binaries: `go53` (the server) and `go53ctl`
(the admin CLI). Container images bundle both. Pick the method that matches your
environment — the container path is the fastest way to a running server, the
quadlet path gives you a rootless systemd-managed service, and the install
script lays down native binaries with a system-wide systemd unit.

- **Podman run** — Fastest start. One command pulls the image and runs the
  server. Good for evaluation and disposable environments.
- **Podman quadlet** — Rootless systemd integration with auto-restart and
  auto-update. Recommended for a persistent server on Linux.
- **Install script** — Native binaries plus a root systemd service. Best for
  dedicated hosts that should not run a container runtime.

### Port Model

Inside the container, go53 listens on `2053` so it never needs root to bind. Map
it to the standard port `53` on the host. The API and the distributed sync
listener keep their native ports.

| Host port | Container port | Purpose |
|-----------|----------------|---------|
| `53` (UDP/TCP) | `2053` | Authoritative DNS queries. |
| `8053` | `8053` | HTTP admin API. |
| `53530` | `53530` | Distributed cluster sync. |

### Method 1 — Podman Run

Create a named volume so zone data, keys, and config survive restarts and
upgrades, then start the container.

```sh
podman volume create go53_data

podman run -d \
  --name go53 \
  --restart unless-stopped \
  -p 53:2053/udp \
  -p 53:2053/tcp \
  -p 8053:8053/tcp \
  -p 53530:53530/tcp \
  -v go53_data:/var/lib/go53 \
  ghcr.io/tenforwardab/go53:latest
```

Manage the running container and reach the bundled CLI through `podman exec`:

```sh
podman logs -f go53
podman exec go53 go53ctl config get
```

Upgrade by pulling a new image and recreating the container. The named volume
keeps your data intact.

```sh
podman pull ghcr.io/tenforwardab/go53:latest
podman stop go53 && podman rm go53
podman run -d --name go53 --restart unless-stopped \
  -p 53:2053/udp -p 53:2053/tcp \
  -p 8053:8053/tcp -p 53530:53530/tcp \
  -v go53_data:/var/lib/go53 \
  ghcr.io/tenforwardab/go53:latest
```

### Method 2 — Podman Quadlet (Rootless Systemd)

Quadlets let systemd manage a Podman container from a small unit file. This runs
go53 as your user, with no root and no long-lived `podman run` process.

```sh
mkdir -p ~/.config/containers/systemd
```

Create `~/.config/containers/systemd/go53.container`:

```ini
[Unit]
Description=go53 DNS Server
After=network-online.target
Wants=network-online.target

[Container]
Image=ghcr.io/tenforwardab/go53:latest
ContainerName=go53
PublishPort=53:2053/udp
PublishPort=53:2053/tcp
PublishPort=8053:8053/tcp
PublishPort=53530:53530/tcp
Volume=go53_data.volume:/var/lib/go53
AutoUpdate=registry

[Service]
Restart=always
TimeoutStartSec=30

[Install]
WantedBy=default.target
```

Create the matching volume unit `~/.config/containers/systemd/go53_data.volume`:

```ini
[Volume]
```

Reload systemd so it generates the service from the quadlet, then start and
enable it.

```sh
systemctl --user daemon-reload
systemctl --user start go53
systemctl --user enable go53

systemctl --user status go53
journalctl --user -u go53 -f
```

> **Note:** To keep the service running after you log out, enable lingering for
> your user: `sudo loginctl enable-linger $USER`. Because the unit sets
> `AutoUpdate=registry`, you can let Podman pull new images automatically with
> `systemctl --user enable --now podman-auto-update.timer`, or trigger it on
> demand with `podman auto-update`.

### Automated Rootless Quadlet (Distributed Node)

For distributed clusters, `scripts/install_quadlet_distributed.sh` automates the
whole rootless setup: it installs Podman and the rootless helpers, creates the
`podman_go53` service user, writes the `.container` and `.volume` quadlet units,
enables lingering and the auto-update timer, and patches the node into
distributed mode. The node ID defaults to the host's short hostname
(`hostname -s`), matching the container name `go53-<hostname>`.

```sh
NODE_ID=a-ns01 \
DNS_HOST_PORT=2053 \
SYNC_HOST_PORT=53530 \
scripts/install_quadlet_distributed.sh
```

The defaults suit a host where another resolver still owns port 53: DNS is
published on `2053`, the API binds to loopback `8053`, and distributed sync
listens on `53530`. Override any of these with the matching `*_HOST_PORT` and
`*_BIND` variables.

To serve DNS on the privileged host port 53, set both flags:

```sh
ALLOW_HOST_53=1 DNS_HOST_PORT=53 scripts/install_quadlet_distributed.sh
```

> ⚠️ **Heads up — this opens host ports 53–1023 to every unprivileged user.**
> Because the container is rootless, binding a host port below 1024 requires
> lowering the kernel threshold `net.ipv4.ip_unprivileged_port_start`. The
> installer sets it to the lowest published port (53) and persists it to
> `/etc/sysctl.d/99-go53-unprivileged-ports.conf`. The threshold is host-wide:
> afterwards *any* unprivileged process can bind *any* port in 53–1023, not just
> go53 on 53.

If that trade-off is too broad, keep DNS on the high port (`2053`, the default —
do not set `ALLOW_HOST_53`) and expose 53 with one of these instead:

- **A — nftables redirect (recommended).** Redirect only port 53 to 2053; no
  sysctl change and the container is untouched.

  ```sh
  sudo nft add table ip go53
  sudo nft add chain ip go53 prerouting '{ type nat hook prerouting priority dstnat; }'
  sudo nft add rule ip go53 prerouting udp dport 53 redirect to :2053
  sudo nft add rule ip go53 prerouting tcp dport 53 redirect to :2053
  ```

  Persist with `sudo nft list ruleset > /etc/nftables.conf`. Add a matching
  `OUTPUT` rule if local `127.0.0.1:53` queries must also reach go53.
- **B — file capability on the port forwarder.**
  `sudo setcap cap_net_bind_service=+ep /usr/bin/pasta` (or `rootlessport`).
  Scoped to that one binary, but it still permits any port below 1024 and is
  reset on every Podman/passt upgrade.
- **C — systemd socket activation.** A privileged `.socket` unit binds :53 and
  hands the file descriptor to the rootless container. The cleanest isolation,
  but the most moving parts.

### Method 3 — Install Script (Native Binaries)

The install script detects your OS and CPU architecture, downloads the matching
release, installs both binaries to `/usr/local/bin`, creates a `go53` system
user, and installs and enables a systemd service.

```sh
curl -fsSL https://raw.githubusercontent.com/TenforwardAB/go53/main/scripts/install.sh | sudo bash
```

Pin a specific version by passing it as an argument:

```sh
curl -fsSL https://raw.githubusercontent.com/TenforwardAB/go53/main/scripts/install.sh | sudo bash -s v0.77.1
```

Manage the service with systemd and inspect logs through the journal.

```sh
sudo systemctl start go53
sudo systemctl status go53
journalctl -u go53 -f
```

| Path | Purpose |
|------|---------|
| `/usr/local/bin/go53` | Server binary. |
| `/usr/local/bin/go53ctl` | Admin CLI. |
| `/etc/go53/` | Configuration directory. |
| `/var/lib/go53/` | Data directory. |
| `/etc/systemd/system/go53.service` | Systemd unit file. |

### Verify The Server Is Up

Once go53 is running, confirm both the DNS listener and the API respond.

```sh
dig @127.0.0.1 example.com. SOA +short
curl http://127.0.0.1:8053/api/config
```

With a server running, continue to [Quick Start](#quick-start) to create your
first zone and records.

## Quick Start

go53 starts one DNS listener and one HTTP API listener. Static deployment
settings come from environment variables. Live server behavior is stored in the
configured storage backend and can be read or patched through `/api/config`.

```sh
DNS_PORT=:2053 \
BIND_HOST=0.0.0.0 \
API_PORT=:8053 \
STORAGE_BACKEND=badger \
go53-server
```

For a new primary node, create the SOA and NS records first, then add ordinary
records. SOA serials are updated automatically for non-SOA record changes.

```sh
curl -X POST http://127.0.0.1:8053/api/zones/example.com./records/SOA \
  -H 'Content-Type: application/json' \
  -d '{
    "ttl": 3600,
    "ns": "ns1.example.com.",
    "mbox": "hostmaster.example.com.",
    "refresh": 3600,
    "retry": 600,
    "expire": 1209600,
    "minimum": 3600
  }'

curl -X POST http://127.0.0.1:8053/api/zones/example.com./records/NS \
  -H 'Content-Type: application/json' \
  -d '{"name":"example.com.","ttl":3600,"ns":"ns1.example.com."}'

curl -X POST http://127.0.0.1:8053/api/zones/example.com./records/A \
  -H 'Content-Type: application/json' \
  -d '{"name":"www.example.com.","ttl":300,"ip":"192.0.2.10"}'
```

## Deployment Config

These settings are read at process start. Restart the process after changing
them.

| Variable | Default | Description |
|----------|---------|-------------|
| `DNS_PORT` | `:2053` | DNS listener port. Include the leading colon unless you provide a complete host-port elsewhere. |
| `BIND_HOST` | `0.0.0.0` | Address used by both DNS and API listeners. |
| `API_PORT` | `:8053` | HTTP API listener port. |
| `STORAGE_BACKEND` | `badger` | Storage backend. Current deployments normally use Badger for local persistence. |
| `POSTGRES_DSN` | `host=localhost port=5432 user=postgres password=postgres dbname=go53 sslmode=disable` | PostgreSQL connection string when a Postgres backend is used. |
| `ADMIN_SOCKET` | `/run/go53/admin.sock` | Path to the local admin Unix socket that serves the full API gated by filesystem permissions instead of API tokens. Set empty to disable. |
| `ADMIN_SOCKET_GROUP` | `go53_admin` | OS group granted access to the admin socket (mode `0660`). If the group does not exist the socket falls back to owner-only access. |

## Runtime Config

Runtime config is loaded from storage at startup. Use `GET /api/config` to
inspect the active values and `PATCH /api/config` to update fields. Secret-
bearing fields such as `auth.x_auth_key` are not returned by `GET /api/config`
and must be managed through the local admin socket.

```sh
curl http://127.0.0.1:8053/api/config

curl -X PATCH http://127.0.0.1:8053/api/config \
  -H 'Content-Type: application/json' \
  -d '{"mode":"primary","allow_axfr":true,"allow_transfer":"127.0.0.1","dnssec_enabled":true}'
```

| Field | Default | Description |
|-------|---------|-------------|
| `log_level` | `info` | Logging level used by the server. |
| `mode` | `primary` | `primary` allows record changes and sends NOTIFY. `secondary` blocks zone and key mutations and fetches from the primary. `distributed` enables multi-node event replication. |
| `allow_transfer` | `127.0.0.1` | Comma-separated client IP allowlist for AXFR and IXFR. |
| `allow_recursion` | `false` | Reserved for resolver behavior. go53 is intended as an authoritative DNS server. |
| `dnssec_enabled` | `true` | Enables DNSSEC material in answers when DNSSEC is requested. |
| `default_ttl` | `3600` | Fallback TTL for records that do not include one. |
| `version` | `go53 1.0.1` | Server version string. |
| `max_udp_size` | `1232` | EDNS UDP payload size advertised by the server. |
| `enable_edns` | `true` | Controls EDNS support. |
| `rate_limit_qps` | `0` | Per-source query limit. `0` disables rate limiting. |
| `allow_axfr` | `false` | Enables transfer responses when the client also passes the allowlist and TSIG policy. |
| `default_ns` | `ns1.go53.local.` | Default nameserver used by helper logic when a zone does not specify one. |
| `enforce_tsig` | `false` | Requires valid TSIG for transfers when enabled. |
| `auth.mode` | `disabled` | Controls TCP API access. `disabled` returns `503`, `none` allows unauthenticated TCP API access, `x-auth-key` requires a static key, and `oidc` is reserved. |
| `auth.x_auth_key` | `""` | Static base62 API key for `auth.mode=x-auth-key`. It must match `^[A-Za-z0-9]{48,}$`. If unset or invalid, the TCP API returns `403`. |
| `primary.notify_debounce_ms` | `2000` | Delay used to coalesce NOTIFY after record changes. |
| `primary.ip` | `127.0.0.1` | Primary DNS address used by secondary nodes. |
| `primary.port` | `53` | Primary DNS port used by secondary nodes. |
| `secondary.fetch_debounce_ms` | `3000` | Delay used to coalesce secondary transfer fetches. |
| `secondary.min_fetch_interval_sec` | `10` | Minimum interval between secondary fetches for the same zone. |
| `secondary.max_parallel_fetches` | `5` | Maximum concurrent secondary transfer fetches. |
| `secondary.catalog_enabled` | `false` | Maintains and follows an RFC 9432 catalog zone for dynamic secondary member-zone discovery. |
| `secondary.catalog_zone` | `_catalog.go53.` | Catalog zone name used as the secondary bootstrap catalog and primary-side member list. |
| `distributed.node_id` | `""` | Stable unique node name used in event origins, vectors, TLS identity, and peer trust maps. |
| `distributed.peers` | `""` | Comma-separated peer endpoints. Use `tls://host:port` or `mtls://host:port` for encrypted socket replication. |
| `distributed.transport` | `http` | Replication transport: `http`, `tcp`, `tls`, or `mtls`. Production distributed clusters should use `tls` or `mtls`. |
| `distributed.sync_bind_host` | `0.0.0.0` | Address for the persistent distributed sync listener. |
| `distributed.sync_port` | `:53530` | Port or host-port for the distributed sync listener. |
| `distributed.private_key` | `""` | Base64 Ed25519 private key for event signatures, HELLO proof, and automatic TLS certificate generation. |
| `distributed.peer_public_keys` | `{}` | Map of trusted peer `node_id` to base64 Ed25519 public key. |
| `distributed.push_timeout_ms` | `2000` | Timeout for peer push, vector, event, Merkle, and repair requests. |
| `distributed.resync_interval_s` | `30` | Periodic background sync interval. Each pass compares vectors first, then Merkle roots per zone for integrity repair. |

## Zones And Records

Records are created through `POST /api/zones/{zone}/records/{rrtype}`. For all
normal types, the JSON body must contain `name`. The `ttl` field is optional.
SOA records use the zone apex as the owner name and do not require `name`.

| Type | Example body |
|------|--------------|
| `A` | `{"name":"www.example.com.","ttl":300,"ip":"192.0.2.10"}` |
| `AAAA` | `{"name":"www.example.com.","ttl":300,"ip":"2001:db8::10"}` |
| `NS` | `{"name":"example.com.","ttl":3600,"ns":"ns1.example.com."}` |
| `MX` | `{"name":"example.com.","ttl":3600,"host":"mail.example.com.","priority":10}` |
| `TXT` | `{"name":"example.com.","ttl":300,"text":"v=spf1 -all"}` |
| `SPF` | `{"name":"example.com.","ttl":300,"text":"v=spf1 -all"}` |
| `CNAME` | `{"name":"alias.example.com.","ttl":300,"target":"www.example.com."}` |
| `DNAME` | `{"name":"old.example.com.","ttl":300,"target":"new.example.com."}` |
| `PTR` | `{"name":"10.2.0.192.in-addr.arpa.","ttl":300,"ptr":"host.example.com."}` |
| `SRV` | `{"name":"_sip._tcp.example.com.","ttl":300,"priority":10,"weight":5,"port":5060,"target":"sip.example.com."}` |
| `SOA` | `{"ttl":3600,"ns":"ns1.example.com.","mbox":"hostmaster.example.com.","refresh":3600,"retry":600,"expire":1209600,"minimum":3600}` |

For multi-value RRsets such as A, AAAA, NS, MX, TXT, PTR, and SRV, send one value
per POST. go53 appends distinct values to the owner name internally. Use
`GET /api/zones/{zone}/records/{rrtype}/{name}` to read one owner name and
`DELETE /api/zones/{zone}/records/{rrtype}/{name}` to delete it. A delete request
may include a JSON body when only one value in a multi-value RRset should be
removed.

**Long TXT and SPF values:** pass the full value in a single `text` field. go53
splits values longer than 255 bytes into 255-byte DNS character-strings on the
wire and joins them back without a separator, so long records such as DKIM public
keys round-trip correctly.

## DNSSEC

go53 keeps DNSSEC keys in storage and also uses an in-memory key cache on
read-heavy paths. Positive RRsets can be signed at query time and stored RRSIG
records are reused as cache until refresh policy says they should be resigned.
NSEC and NSEC3 denial material is generated and maintained from zone contents.

> **Note:** For the signing flows in depth — timing, jitter, query-time signing,
> the RRSIG cache, NSEC/NSEC3 chains, CDS/CDNSKEY, and the key lifecycle, with
> diagrams — see the [DNSSEC Technical Guide](/concepts/dnssec/).

| Policy field | Default | Description |
|--------------|---------|-------------|
| `dnssec.validity_seconds` | `604800` | RRSIG validity for ordinary RRsets. |
| `dnssec.dnskey_validity_seconds` | `1209600` | RRSIG validity for DNSKEY RRsets. |
| `dnssec.refresh_before_seconds` | `86400` | Signatures are refreshed before this much validity remains. |
| `dnssec.jitter_seconds` | `3600` | Randomizes refresh timing to avoid all signatures refreshing at once. |
| `dnssec.inception_skew_seconds` | `3600` | Backdates signature inception to tolerate clock skew. |

```sh
curl -X POST 'http://127.0.0.1:8053/api/dnskeys?zone=example.com.'

curl -X POST http://127.0.0.1:8053/api/dnskeys/rollover \
  -H 'Content-Type: application/json' \
  -d '{"zone":"example.com.","role":"zsk","algorithm":"ED25519"}'

curl http://127.0.0.1:8053/api/ds/example.com.
curl http://127.0.0.1:8053/api/cds/example.com.
curl http://127.0.0.1:8053/api/cdnskey/example.com.
```

Rollover key generation accepts the DNSSEC algorithm names below. Imported zone
files may contain DNSKEY and RRSIG records with other algorithm numbers as data,
but go53 can only generate private keys and sign RRsets with the algorithms
marked as supported.

> **Private key import limitation:** `go53ctl dnskeys import-private` currently
> imports ECDSA P-256, ECDSA P-384, and ED25519 private keys from the go53
> key-import JSON format. go53 can generate RSA signing keys, but importing RSA
> private keys from external systems is not implemented yet because PowerDNS,
> BIND, and Knot expose different native private-key formats that still need
> explicit mappers.

| DNSSEC alg | Name | Status | Notes |
|------------|------|--------|-------|
| `8` | `RSASHA256` | Supported | Generates 2048-bit RSA keys. |
| `10` | `RSASHA512` | Supported | Generates 2048-bit RSA keys. |
| `13` | `ECDSAP256SHA256` | Supported | Uses ECDSA P-256. |
| `14` | `ECDSAP384SHA384` | Supported | Uses ECDSA P-384. |
| `15` | `ED25519` | Supported; default | Default for `/api/dnskeys/rollover` when no algorithm is supplied. |
| `16` | `ED448` | Not supported | The name is recognized, but key generation fails because ED448 is not available in Go's standard crypto library. |
| `5` | `RSASHA1` | Not supported | Legacy SHA-1 based signing algorithm; go53 does not generate or sign with it. |
| `7` | `RSASHA1-NSEC3-SHA1` | Not supported | Legacy SHA-1 based signing algorithm; go53 does not generate or sign with it. |
| `3` | `DSA` | Not supported | Obsolete DNSSEC algorithm; no key generation/signing path is implemented. |
| `6` | `DSA-NSEC3-SHA1` | Not supported | Obsolete DNSSEC algorithm; no key generation/signing path is implemented. |
| `12` | `ECC-GOST` | Not supported | Not implemented in go53's key generation/signing path. |

### Key Roles: KSK And ZSK

go53 signs with a split key set. A **KSK** (flags `257`) signs only the DNSKEY
RRset, and a **ZSK** (flags `256`) signs all other zone data (SOA, NS, MX, TXT,
NSEC/NSEC3, and so on). A zone must have at least one active KSK *and* one active
ZSK to be fully signed. `POST /api/dnskeys?zone=...` generates a complete
KSK + ZSK set; `POST /api/dnskeys/rollover` with `role` set to `KSK` or `ZSK`
adds a single key of that role.

> **No CSK (combined signing key):** a single key is treated strictly as either a
> KSK or a ZSK based on its flags — go53 does not support one key that signs both
> the DNSKEY RRset and the zone data. If you import a CSK from another server
> (PowerDNS, for example, commonly uses a CSK), it is stored as a KSK and signs
> only the DNSKEY RRset, leaving the rest of the zone unsigned until you add a
> ZSK.

### Taking Over Signing From Another Server

To migrate an already-signed zone and let go53 own the signing, import the
existing private key as the **KSK** so the parent DS keeps validating, then
generate a **ZSK** in go53 to sign the zone data. Because the parent DS still
points at the imported KSK, no DS change at the registrar is required.

```sh
# 1. import the existing key (stored as the KSK), then add a ZSK
go53ctl dnskeys import-private --key-file example.com.key
go53ctl dnskeys rollover example.com. ZSK ECDSAP256SHA256

# 2. import the zone WITHOUT old DNSSEC records so go53 signs it itself
go53ctl zones import example.com. example.com.unsigned.zone
```

Import the zone data without the source server's DNSSEC records (DNSKEY, RRSIG,
NSEC/NSEC3, CDS, CDNSKEY) so go53 builds its own signatures and denial chain. Use
`--dnssec preserve` only when you want to keep the source signatures verbatim;
that mode serves the zone read-only. The repository ships helper scripts to
prepare an unsigned zone file: `scripts/pdns_export_go53_zone.sh` (export a
PowerDNS zone, with a `--dnssec strip` mode) and
`scripts/strip_dnssec_zonefile.sh` (strip DNSSEC records from an existing zone
file). DS records at delegation points are preserved, since they are
child-delegation data rather than this zone's own signing material.

### NSEC And NSEC3

Authenticated denial defaults to **NSEC**. NSEC3 is enabled per zone by the
presence of an `NSEC3PARAM` record in that zone — there is no global on/off
switch in the `dnssec` config block. Switching between NSEC and NSEC3 does not
affect the parent DS and needs no registrar change.

The DNSSEC key lifecycle API supports pre-publish, activation, retirement,
revocation, and removal metadata. Use `PATCH /api/dnskeys/{keyid}/lifecycle` for
explicit lifecycle changes, or the helper endpoints for common operations.

| Endpoint | Purpose |
|----------|---------|
| `GET /api/dnskeys` | List stored DNSSEC keys. |
| `GET /api/dnskeys/{keyid}` | Current implementation treats this path value as a zone name and returns keys for that zone. |
| `POST /api/dnskeys?zone=example.com.` | Generate and store the default DNSSEC key set for a zone. |
| `POST /api/dnskeys/rollover` | Create a rollover key. Body or query fields: `zone`, `role`, `algorithm`, `publish_at`, `activate_at`. |
| `PATCH /api/dnskeys/{keyid}/lifecycle` | Update timing and lifecycle metadata for a stored key. |
| `POST /api/dnskeys/{keyid}/retire` | Mark a key retired. Optional `remove_after_days`, default `30`. |
| `POST /api/dnskeys/{keyid}/revoke` | Mark a key revoked. Optional `remove_after_days`, default `30`. |
| `DELETE /api/dnskeys/{keyid}` | Delete a stored key. |

DS and CDS endpoints accept `digest` or `digest_type` as comma-separated digest
selectors. CDS and CDNSKEY also accept `delete=true` to publish delete signaling
records.

## Transfers

AXFR and IXFR are controlled by runtime config. A primary must enable
`allow_axfr` and include the secondary source address in `allow_transfer`. If
`enforce_tsig` is true, transfer requests must also carry a valid TSIG.

```sh
curl -X PATCH http://127.0.0.1:8053/api/config \
  -H 'Content-Type: application/json' \
  -d '{
    "mode": "primary",
    "allow_axfr": true,
    "allow_transfer": "127.0.0.1",
    "enforce_tsig": true
  }'
```

**Primary** — Record changes update the SOA serial and schedule NOTIFY.
`primary.notify_debounce_ms` controls how aggressively changes are coalesced.

**Secondary** — Zone and key mutation endpoints are disabled in secondary mode.
Fetch behavior is controlled by `secondary.fetch_debounce_ms`,
`secondary.min_fetch_interval_sec`, and `secondary.max_parallel_fetches`.

Transfer responses should include complete DNSSEC material for signed zones. IXFR
support exists on the transfer path; validate incremental behavior against your
production resolver and secondary mix before relying on IXFR-only operation.

## Distributed Mode

Distributed mode is go53's multi-node replication mode. All nodes run with
`mode=distributed`, accept local mutations, and exchange signed events with
peers. Zone records, SOA updates, TSIG keys, DNSSEC keys, and selected live
config changes are replicated. Node-local distributed settings are not
replicated through config events.

> **Recommended transport:** use `tls` or `mtls`. The sync socket is persistent
> TCP with length-prefixed frames. TLS certificates are generated automatically
> from each node's Ed25519 distributed key, and peers are trusted by
> `distributed.peer_public_keys`.

### What Replicates

| Data | Behavior |
|------|----------|
| Zone records | Record add/delete events replicate per RRset entity. SOA serial changes are published as SOA events. |
| TSIG keys | TSIG add/update/delete events persist to the peer and refresh the in-memory TSIG cache. |
| DNSSEC keys | DNSSEC key create/update/delete events persist to the peer, refresh the DNSSEC key cache, and refresh zone DNSSEC key material when applicable. Repair can also bootstrap pre-existing KSK/ZSK private key material when no historical event exists. |
| Live config | Non-distributed live config can replicate. Distributed cluster membership (`peers` and `peer_public_keys`) can replicate, while node-local distributed identity, private key, listener, timing, and transport settings are stripped. |
| Integrity repair | Periodic sync compares vectors, then Merkle roots per zone. Mismatched branches are narrowed to leaves and repaired from latest signed events, with current-record and DNSSEC-key snapshot fallback for pre-existing data that has no event history. |

### Frame Protocol

The socket transport uses `HELLO`, `VECTOR_REQUEST`/`VECTOR`, `EVENT`/`ACK`,
`EVENTS_REQUEST`/`EVENTS`, Merkle frames for roots, branches, leaves, repair
events, and current-record fallback, plus DNSSEC-key snapshot frames for
onboarding repair. `HELLO` is signed with the node Ed25519 private key. Event
payloads are also Ed25519 signed.

### Required Ports

Each node needs its DNS listener, API listener, and distributed sync listener.
The API is used for administration and discovery. Peer-to-peer replication uses
`distributed.sync_bind_host` and `distributed.sync_port`.

| Port | Purpose |
|------|---------|
| `DNS_PORT` | Authoritative DNS UDP/TCP listener. |
| `API_PORT` | Admin API and `/.well-known/go53-node.json` discovery. |
| `distributed.sync_port` | Persistent distributed socket listener. Open this between all distributed peers. |

### Bootstrap Two Nodes

The examples below use node A at `10.0.0.10` and node B at `10.0.0.11`. Replace
addresses and ports with your deployment values.

```sh
# On node A
curl -s -X POST http://10.0.0.10:8053/api/distributed/keypair

# On node B
curl -s -X POST http://10.0.0.11:8053/api/distributed/keypair
```

Save both responses. Each response contains one `private_key` and one
`public_key`. The private key stays on that node. The public key is configured on
peer nodes under that node's `node_id`.

```sh
# Configure node A
curl -X PATCH http://10.0.0.10:8053/api/config \
  -H 'Content-Type: application/json' \
  -d '{
    "mode": "distributed",
    "distributed": {
      "node_id": "node-a",
      "transport": "tls",
      "sync_bind_host": "0.0.0.0",
      "sync_port": ":53530",
      "peers": "tls://10.0.0.11:53530",
      "private_key": "NODE_A_PRIVATE_KEY",
      "peer_public_keys": {
        "node-b": "NODE_B_PUBLIC_KEY"
      },
      "push_timeout_ms": 2000,
      "resync_interval_s": 30
    }
  }'

# Configure node B
curl -X PATCH http://10.0.0.11:8053/api/config \
  -H 'Content-Type: application/json' \
  -d '{
    "mode": "distributed",
    "distributed": {
      "node_id": "node-b",
      "transport": "tls",
      "sync_bind_host": "0.0.0.0",
      "sync_port": ":53530",
      "peers": "tls://10.0.0.10:53530",
      "private_key": "NODE_B_PRIVATE_KEY",
      "peer_public_keys": {
        "node-a": "NODE_A_PUBLIC_KEY"
      },
      "push_timeout_ms": 2000,
      "resync_interval_s": 30
    }
  }'
```

Verify both nodes expose their advertised identity and TLS material:

```sh
curl http://10.0.0.10:8053/.well-known/go53-node.json
curl http://10.0.0.11:8053/.well-known/go53-node.json

curl http://10.0.0.10:8053/api/distributed/status
curl http://10.0.0.11:8053/api/distributed/status
```

### Add A New Node

When adding node C, generate its keypair, configure node C with all existing
peers, then patch every existing node to include node C in both
`distributed.peers` and `distributed.peer_public_keys`.

```sh
# 1. Generate node C keypair
curl -s -X POST http://10.0.0.12:8053/api/distributed/keypair

# 2. Configure node C with node A and B as trusted peers
curl -X PATCH http://10.0.0.12:8053/api/config \
  -H 'Content-Type: application/json' \
  -d '{
    "mode": "distributed",
    "distributed": {
      "node_id": "node-c",
      "transport": "tls",
      "sync_bind_host": "0.0.0.0",
      "sync_port": ":53530",
      "peers": "tls://10.0.0.10:53530,tls://10.0.0.11:53530",
      "private_key": "NODE_C_PRIVATE_KEY",
      "peer_public_keys": {
        "node-a": "NODE_A_PUBLIC_KEY",
        "node-b": "NODE_B_PUBLIC_KEY"
      },
      "push_timeout_ms": 2000,
      "resync_interval_s": 30
    }
  }'

# 3. Patch node A to trust and dial node C
curl -X PATCH http://10.0.0.10:8053/api/config \
  -H 'Content-Type: application/json' \
  -d '{
    "distributed": {
      "peers": "tls://10.0.0.11:53530,tls://10.0.0.12:53530",
      "peer_public_keys": {
        "node-b": "NODE_B_PUBLIC_KEY",
        "node-c": "NODE_C_PUBLIC_KEY"
      }
    }
  }'

# 4. Patch node B to trust and dial node C
curl -X PATCH http://10.0.0.11:8053/api/config \
  -H 'Content-Type: application/json' \
  -d '{
    "distributed": {
      "peers": "tls://10.0.0.10:53530,tls://10.0.0.12:53530",
      "peer_public_keys": {
        "node-a": "NODE_A_PUBLIC_KEY",
        "node-c": "NODE_C_PUBLIC_KEY"
      }
    }
  }'
```

> ⚠️ **Do not reuse distributed private keys.** Each node must have a unique
> `node_id` and private key. Reusing either breaks event identity and conflict
> resolution.

### Validation

Create or change a record on any node, then check DNS or the distributed vector
on the others. The vector should advance for the origin node. Merkle repair will
also converge zone state if a peer missed or drifted from an event.

```sh
curl -X POST http://10.0.0.10:8053/api/zones/example.com./records/A \
  -H 'Content-Type: application/json' \
  -d '{"name":"www.example.com.","ttl":300,"ip":"192.0.2.10"}'

dig @10.0.0.11 www.example.com. A +short

curl http://10.0.0.11:8053/api/distributed/vector
curl http://10.0.0.11:8053/api/distributed/merkle/roots
```

## go53ctl

`go53ctl` is the local administration helper. It has three areas: local
break-glass admin over a Unix socket, distributed cluster onboarding, and direct
Badger inspection for zone storage.

### Local Admin Socket (Break-Glass)

go53 also serves the full admin API over a local Unix domain socket
(`ADMIN_SOCKET`, default `/run/go53/admin.sock`). Access is controlled by
filesystem permissions instead of API tokens: the socket is created with mode
`0660` and group-owned by `ADMIN_SOCKET_GROUP` (default `go53_admin`), so `root`
and members of that group can administer the local node even when the external
IdP that protects the TCP API is unreachable. The socket handler intentionally
bypasses API authentication; the TCP listener is where token auth is enforced.

> **Note:** Grant an operator local admin by adding them to the group:
> `sudo usermod -aG go53_admin alice`. Under systemd, provision the socket
> directory with `RuntimeDirectory=go53` so `/run/go53` exists with the right
> ownership.

The management subcommands call the admin API over the socket by default. They
read the socket path from `--socket` or `$GO53_ADMIN_SOCKET`, falling back to
`/run/go53/admin.sock`. Pass `--api URL` to target the TCP API instead. The
lower-level `go53ctl api` command remains available as a raw passthrough for any
route not covered by a typed helper.

```sh
# Read live config locally, no token required
go53ctl config get

# Change a setting
go53ctl config patch '{"default_ttl":120}'

# Generate and store a 48-character base62 API key locally
go53ctl config set xauth_key --generate

# Inspect or set the key explicitly over the local admin socket
go53ctl config get xauth_key
go53ctl config set xauth_key abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV

# Enable x-auth-key on the TCP API after a valid key exists
go53ctl config patch '{"auth":{"mode":"x-auth-key"}}'

# List zones and records
go53ctl zones list --limit 50
go53ctl records list example.com.
go53ctl records list-type example.com. A

# Create, read, update, and delete a record
go53ctl records add example.com. A '{"name":"www","ttl":300,"ip":"192.0.2.10"}'
go53ctl records get example.com. A www.example.com.
go53ctl records patch example.com. A www.example.com. '{"ip":"192.0.2.11","ttl":300}'
go53ctl records delete example.com. A www.example.com.

# Zone file import/export
go53ctl zones export example.com. > example.com.zone
go53ctl zones import example.com. example.com.zone
go53ctl zones import example.com. signed.zone --dnssec preserve
go53ctl dnskeys import-private --key-file example.com.key

# Catalog, secondary, notify, and docs
go53ctl catalog status
go53ctl catalog members --limit 100
go53ctl secondary fetch example.com.
go53ctl notify example.com.
go53ctl docs openapi > openapi.yaml

# Explicit socket path or TCP fallback
go53ctl config get --socket /run/go53/admin.sock
go53ctl config get --api http://127.0.0.1:8053

# Raw API passthrough remains available
go53ctl api GET /api/config
go53ctl api PATCH /api/config '{"default_ttl":120}'
```

When `auth.mode=x-auth-key`, TCP clients must send `X-Auth-Key: VALUE`. If the
key is unset, shorter than 48 characters, or contains characters outside `A-Z`,
`a-z`, and `0-9`, the TCP API returns `403`. The key cannot be read or changed
through `GET/PATCH /api/config`; use `go53ctl config get/set xauth_key` over the
local admin socket.

| Command group | Purpose |
|---------------|---------|
| `config` | Read or patch live runtime config. |
| `zones` | List, delete, import, and export zones. |
| `records` | List, add, read, patch, and delete RRsets. |
| `catalog` | Inspect catalog-zone status and member zones. |
| `secondary` | Queue explicit secondary fetches. |
| `notify` | Schedule DNS NOTIFY for a zone. |
| `tsig` | List, add, and delete TSIG keys. |
| `dnskeys` | Manage DNSSEC key creation, rollover, lifecycle, retire, revoke, and delete operations. |
| `ds`, `cds`, `cdnskey` | Generate parent-signaling records. |
| `distributed` | Inspect vectors, events, Merkle state, invites, and node discovery. |
| `docs` | Fetch the OpenAPI spec or Swagger UI HTML. |
| `api` | Raw method/path passthrough for advanced use. |

> ⚠️ The socket grants unauthenticated, full administrative control of the local
> node to anyone who can open it. Keep `go53_admin` membership tight and ensure
> the socket directory is not world-writable. Cluster onboarding is local-first:
> `go53ctl cluster` uses the local Unix socket by default and does not require
> remote admin APIs between nodes.

### Cluster Invite

`go53ctl cluster invite` creates an Ed25519-signed JWT invite for a new
distributed node. The command runs against the issuer's local admin socket by
default, embeds the issuer's pinned sync identity in the token, and saves the
invite on the issuer through `POST /api/distributed/invites`.

```sh
go53ctl cluster invite --usage-count 1
```

For provisioned workflows, the joining node identity and sync endpoint can be
embedded when the invite is created:

```sh
go53ctl cluster invite \
  --join-node-id node-b \
  --join-sync-endpoint tls://10.0.0.11:53530 \
  --issuer-sync-endpoint tls://10.0.0.10:53530
```

| Flag | Meaning |
|------|---------|
| `--socket` | Issuer node Unix admin socket. Defaults from `GO53_ADMIN_SOCKET` or `/run/go53/admin.sock`. |
| `--api` | Optional TCP API base URL for controlled management networks. Overrides `--socket`. |
| `--issuer-node` | Node ID that signs the invite. Defaults from discovery. |
| `--issuer-private-key` | Base64 Ed25519 private key. Defaults from the issuer live config. |
| `--issuer-sync-endpoint` | Public distributed sync endpoint for the issuer node. Use this when discovery would otherwise advertise a bind-local value such as `tls://127.0.0.1:53530`. |
| `--cluster-id` | Stable cluster identifier embedded in the token. Defaults to the issuer node ID. |
| `--join-node-id` | Optional node ID to configure on the joining node. If omitted, `cluster join` fills it from local config/discovery or generates one. |
| `--join-sync-endpoint` | Optional distributed sync endpoint for the joining node. If omitted, `cluster join` uses `--sync-endpoint` or local discovery. |
| `--ttl` | Token lifetime. Default is `10m`. |
| `--usage-count` | Allowed consumes for the stored invite. Default is `1`. |
| `--transport` | Distributed transport written into the joining node config. Default is `tls`. |
| `--sync-bind-host` | Bind host written into the joining node config. Default is `0.0.0.0`. |
| `--sync-port` | Sync listener port written into the joining node config. Defaults from `--join-sync-endpoint` at invite time or `--sync-endpoint` at join time. |
| `--push-timeout-ms` | Distributed push timeout written into the joining node config. |
| `--resync-interval-s` | Distributed resync interval written into the joining node config. |

### Cluster Join

`go53ctl cluster join` verifies the invite JWT, uses or generates a local
Ed25519 keypair, patches the joining node's local config through its local admin
socket, and sends a signed self-registration request to the issuer over the
issuer's distributed sync endpoint. By default the issuer stores that request as
pending. An operator approves it locally on the issuer, which consumes one
allowed invite use, pins the joining node's public key, adds its sync endpoint,
and replicates that membership update to existing peers.

```sh
go53ctl cluster join \
  --token INVITE_JWT \
  --sync-endpoint tls://10.0.0.11:53530
```

```sh
go53ctl cluster pending
go53ctl cluster approve node-b
```

### Cluster Accept

`go53ctl cluster accept` is the manual fallback for offline or recovery
workflows. It runs locally on an existing cluster node, verifies the same invite
token, pins the joining node's public key in `distributed.peer_public_keys`, and
adds the joining node's sync endpoint to `distributed.peers`. When run on the
issuer node, it also consumes the stored invite usage. Operators should compare
the printed public key over the same trusted channel used to transfer the invite.

```sh
go53ctl cluster accept \
  --token INVITE_JWT \
  --join-node-id node-b \
  --join-sync-endpoint tls://10.0.0.11:53530 \
  --join-public-key PUBLIC_KEY
```

### Cluster Remove

`go53ctl cluster remove-node` removes a pinned peer public key from the local
node and removes the peer sync endpoint from `distributed.peers`. The live config
stores peer endpoints as a comma-separated list and public keys as a `node_id`
map, so there is no durable one-to-one endpoint mapping. In a two-node cluster
the endpoint can be inferred and the peer list is cleared. In larger clusters,
pass the endpoint explicitly with `--peer`.

```sh
go53ctl cluster remove-node node-b
```

```sh
go53ctl cluster remove-node --peer tls://10.0.0.11:53530 node-b
```

| Flag | Meaning |
|------|---------|
| `--token` | JWT invite produced by `go53ctl cluster invite`. |
| `--socket` | Local Unix admin socket. Defaults from `GO53_ADMIN_SOCKET` or `/run/go53/admin.sock`. |
| `--api` | Optional TCP API base URL for controlled management networks. Overrides `--socket`. |
| `--issuer-sync-endpoint` | Override the issuer sync endpoint embedded in the invite token. Useful when an existing invite contains `127.0.0.1` from local discovery. |
| `--sync-endpoint` | Advertised distributed sync endpoint for the joining node. Required when the local discovery endpoint is not reachable by existing nodes. |
| `--auto-accept` | Ask the issuer to approve immediately. Use only when the invite token is handled as a join capability. |
| `--no-register` | Skip self-registration over the issuer sync endpoint and use manual `cluster accept` instead. |
| `pending` | Lists pending join requests on the local issuer node. |
| `approve NODE` | Approves a pending join request locally on the issuer node. |
| `remove-node NODE` | Removes a node from the local distributed membership. Use `--peer` when more than one peer endpoint remains. |
| `--peer` | Peer sync endpoint to remove with `cluster remove-node`. |
| `--join-node-id` | Joining node ID printed by `cluster join`; used by `cluster accept`. |
| `--join-sync-endpoint` | Joining node sync endpoint printed by `cluster join`; used by `cluster accept`. |
| `--join-public-key` | Joining node Ed25519 public key printed by `cluster join`; used by `cluster accept` for public-key pinning. |
| `--dry-run` | Prints generated local config patches without applying them. |

### Storage Inspection

The legacy storage commands open Badger directly and must be used only when that
Badger directory is not already locked by a running go53 process.

```sh
go53ctl --db /data/go53 --list-all-zones --count-only
go53ctl --db /data/go53 --list-zone example.com.
go53ctl --db /data/go53 --list-zone example.com. --count-only
```

## TSIG

TSIG keys are stored separately from DNSSEC keys. Add shared TSIG secrets before
enforcing TSIG for transfers.

```sh
curl -X POST http://127.0.0.1:8053/api/tsig/transfer-key. \
  -H 'Content-Type: application/json' \
  -d '{"algorithm":"hmac-sha256.","secret":"BASE64_SECRET"}'

curl http://127.0.0.1:8053/api/tsig

curl -X DELETE http://127.0.0.1:8053/api/tsig/transfer-key.
```

| Endpoint | Purpose |
|----------|---------|
| `GET /api/tsig` | List configured TSIG keys. |
| `POST /api/tsig/{name}` | Add or replace a TSIG key. Body fields: `algorithm`, `secret`. |
| `DELETE /api/tsig/{name}` | Delete a TSIG key. |

## API Routes

| Method | Route | Notes |
|--------|-------|-------|
| `GET` | `/api/config` | Read live runtime config. |
| `PATCH` | `/api/config` | Patch live runtime config. |
| `GET` | `/api/config/auth/x-auth-key` | Read the static API key. Local admin socket only; TCP returns `403`. |
| `PATCH` | `/api/config/auth/x-auth-key` | Set the static API key. Local admin socket only; key must be base62 and at least 48 characters. |
| `GET` | `/api/zones` | List loaded zones. |
| `POST` | `/api/zones/{zone}/records/{rrtype}` | Add a record. Disabled in secondary mode. |
| `GET` | `/api/zones/{zone}/records/{rrtype}/{name}` | Read one RRset owner name. |
| `DELETE` | `/api/zones/{zone}/records/{rrtype}/{name}` | Delete an RRset or selected value. |
| `GET` | `/api/tsig` | List TSIG keys. |
| `POST` | `/api/tsig/{name}` | Add TSIG key. |
| `DELETE` | `/api/tsig/{name}` | Delete TSIG key. |
| `GET` | `/api/dnskeys` | List DNSSEC keys. |
| `GET` | `/api/dnskeys/{keyid}` | Current handler uses the value as a zone name. |
| `POST` | `/api/dnskeys` | Create default DNSSEC keys. Requires `zone` query parameter. |
| `POST` | `/api/dnskeys/rollover` | Create rollover key. |
| `PATCH` | `/api/dnskeys/{keyid}/lifecycle` | Update key lifecycle metadata. |
| `POST` | `/api/dnskeys/{keyid}/retire` | Retire key. |
| `POST` | `/api/dnskeys/{keyid}/revoke` | Revoke key. |
| `DELETE` | `/api/dnskeys/{keyid}` | Delete key. |
| `GET` | `/api/ds/{zone}` | Return DS records for parent publication. |
| `GET` | `/api/cds/{zone}` | Return CDS records or CDS delete signaling. |
| `GET` | `/api/cdnskey/{zone}` | Return CDNSKEY records or CDNSKEY delete signaling. |
| `GET` | `/.well-known/go53-node.json` | Distributed node discovery document with node ID, public key, fingerprint, advertised sync endpoint, and TLS certificate material. |
| `GET` | `/api/distributed/status` | Show distributed enablement, transport flags, local public key, vector, and node discovery info. |
| `POST` | `/api/distributed/keypair` | Generate an Ed25519 distributed keypair. Store the private key only on the local node. |
| `GET` | `/api/distributed/vector` | Return the local event vector. |
| `GET` | `/api/distributed/events` | Return eventlog entries. Optional query: `origin`, `after`. |
| `POST` | `/api/distributed/events` | Manual event ingest. In socket transport mode this is disabled unless `?resync=true` is supplied. |
| `GET` | `/api/distributed/merkle/roots` | Debug/fallback endpoint for Merkle zone roots. |
| `GET` | `/api/distributed/merkle/branches?zone=example.com.` | Debug/fallback endpoint for one zone's Merkle branches. |
| `POST` | `/api/distributed/merkle/leaves` | Debug/fallback endpoint for Merkle leaves. Body fields: `zone`, `prefixes`. |
| `POST` | `/api/distributed/merkle/repair-events` | Debug/fallback endpoint returning latest signed events for requested entities. |
| `POST` | `/api/distributed/merkle/records` | Debug/fallback endpoint returning current record snapshots for requested entities when no historical event exists. |
| `POST` | `/api/distributed/dnssec-keys` | Debug/fallback endpoint returning current DNSSEC key snapshots, including private key material, for onboarding repair. |
| `POST` | `/api/distributed/invites` | Stores a cluster invite record in the running node's persistence backend. |
| `POST` | `/api/distributed/invites/{jti}/consume` | Consumes one allowed use for a stored cluster invite. |

## Operations

### Storage And Memory

go53 is designed for read-heavy authoritative service. Zone data and DNSSEC key
data should be loaded into memory at startup and persisted to storage on
mutations. Badger remains the local persistence layer, while normal query
handling should avoid storage reads.

### Troubleshooting

- If record mutations fail with `503`, check whether `mode` is set to
  `secondary`.
- If AXFR or IXFR fails, check `allow_axfr`, `allow_transfer`, source address
  matching, and TSIG policy.
- If DNSSEC answers are unsigned, check `dnssec_enabled`, key lifecycle state,
  and whether the zone has active signing keys.
- If DS, CDS, or CDNSKEY output is empty, verify that the zone has an active KSK
  and that key metadata is loaded.
- If distributed peers do not connect, check that both sides have each other's
  `node_id` in `peer_public_keys`, use matching `tls://` peer endpoints, and can
  reach the sync port.
- If TLS handshakes fail, compare `public_key` and `tls_public_key_pin` from
  `/.well-known/go53-node.json` with the configured peer public key.
- If vectors match but zone data differs, check
  `/api/distributed/merkle/roots`; the background sync loop should repair
  differing branches from signed events or current-record fallback for
  pre-existing data.
- If the TCP API returns `503`, check whether `auth.mode` is `disabled`. Use the
  local admin socket to change it.
- If the TCP API returns `403` with `auth.mode=x-auth-key`, verify that
  `auth.x_auth_key` is a valid base62 key of at least 48 characters and that
  clients send `X-Auth-Key`.
