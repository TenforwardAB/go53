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

## Query path cost model (measured for 0.81)

`dns/handler_bench_test.go` runs `handleRequest` end to end per answer kind,
with RRsets stored typed and in the `encoding/json` shape (what every zone has
after a restart). Numbers on a single-zone store, DNSSEC off, Go 1.26:

| answer | v0.80.0 (est.) | after #57+#60 | after #40 owner index |
|---|---|---|---|
| A (3 RRs) | ~4 µs / ~70 allocs | 1.29 µs / 22 | **1.15 µs / 14** |
| MX apex | | 1.07 µs / 15 | **0.91 µs / 10** |
| CNAME chain | | 2.07 µs / 25 | **1.68 µs / 17** |
| NODATA | | 2.51 µs / 18 | **2.03 µs / 10** |
| NXDOMAIN | | 5.82 µs / 51 | **3.62 µs / 13** |

What each release removed, in order of size:

1. **#60** `SanitizeFQDN` compiled a regexp per call: 2.3 µs and 38 allocs on
   *every* `rtypes.Lookup`. A whole Lookup went from ~3 µs to 0.3–0.5 µs.
2. **#40 owner index** (`memory/ownerindex.go`): owner/type existence,
   closest encloser and delegation are one map lookup per candidate label
   instead of iterating every rtype map and splitting/joining the name.
3. **#57** unified decoding removed the per-shape drift; the decode itself is
   ~1 alloc and <100 ns of a query.
4. `SplitName` used to strip the zone's trailing dot only for every caller to
   re-add it: one string alloc per Lookup.

### Where the remaining time goes

CPU profile of an NXDOMAIN after the above:

- **Zone resolution per Lookup (~17 %)** plus its lock traffic (~6 %):
  `internal.SplitName` → `memory.AuthoritativeNameParts` is called 5–8 times
  per query (every Lookup, `NameExists`, `WildcardName`, `DelegationFor`,
  each chain hop), and each call lower-cases the whole name and scans every
  zone key under `RLock`. Linear in the number of hosted zones. → **#66**
  (resolve once per query) together with **#41** (trie/suffix index), 0.82.
- **`net.ParseIP` and `&dns.X{}` per record per query (~10 % of a positive
  answer):** the RRset cache as originally described in #40. Worth doing only
  after the stored shape is typed (#63 → #64), when it is the only decode
  cost left. → **#65**, 0.84.
- Message construction (`SetReply`, `Answer` slices) and the response writer:
  unavoidable per query.

### How to validate a change

`go test ./dns/ -run '^$' -bench BenchmarkHandleRequest -benchmem -count=6`
before and after, compared with `benchstat`; allocs/op is deterministic and
the primary signal, sec/op on this machine has ±5–20 % noise. Per-shape
Lookup micro-benchmarks live in `zone/rtypes/lookup_bench_test.go`.

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
