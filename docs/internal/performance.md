---
title: "Performance Notes"
linkTitle: "Performance"
weight: 40
description: "Known performance characteristics and forward-looking optimization ideas, for future analysis."
---

# Performance Notes

Internal notes on go53's performance characteristics and a few scoped
optimization ideas. None of these are urgent — they are recorded here so a future
performance pass has a starting point. Measure before optimizing.

## DNS query hot path

The authoritative read path is intentionally lock-light: zone data is served from
the in-memory store, and the backup/WAL, health-probe, and DNSSEC-key-cache work
does **not** touch query handling. Query-time DNSSEC signing
(`EnsureSignedRRSet`) is unchanged. The one place an optional feature reaches the
hot path is the per-client rate limiter.

### Per-client rate limiter: single global mutex

When `rate_limit_qps > 0`, every UDP query calls `clientLimiter.allow`, which
takes one **global `sync.Mutex`** to read and update the per-IP token bucket. At
very high QPS that lock is a serialization point — all UDP queries queue through
it.

- **Default (`rate_limit_qps == 0`):** only a `live.RateLimitQPS > 0` comparison
  runs, so there is no measurable cost. The limiter is opt-in.
- **Enabled, under high load:** the shared mutex may become measurable.

**Future optimization (not urgent):** shard the bucket map across N stripes keyed
by source-IP hash, each with its own mutex (and its own cleanup sweep), so
unrelated clients no longer contend. Only do this if measurements show the lock
is hot — it is premature otherwise. Code: `dns/ratelimit.go`.

## Mutation path: WAL pruning is O(N) per append

`wal.Append` runs on every mutating operation (record, zone, config, TSIG, and
DNSSEC key changes) and calls `wal.PruneOlderThan`, which loads and decodes the
**entire** `wal-events` table on each call. The cost grows with the number of
retained WAL events, so a high mutation rate combined with a large WAL makes each
mutation progressively more expensive. This is pre-existing behaviour; DNSSEC key
events now flow through the same path, so more operations hit it.

**Future optimization (not urgent):** move pruning off the synchronous append
path onto a periodic ticker (the rate-limiter cleanup sweep is a good model), or
prune by sequence range / index instead of scanning the whole table. Retention
correctness is unaffected — this is purely about not paying an O(N) scan on every
mutation. Code: `wal.PruneOlderThan` in `wal/wal.go`.

## How to validate a change

Both ideas are self-contained and benchmarkable before/after:

- Rate limiter: a concurrent `allow` micro-benchmark across many goroutines/IPs,
  plus an end-to-end UDP query throughput test with `rate_limit_qps` enabled.
- WAL pruning: a mutation-throughput benchmark with a deliberately large
  `wal-events` table, comparing synchronous vs periodic pruning.
