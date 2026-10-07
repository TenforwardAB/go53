---
title: "Issue #57: record shape decoding"
linkTitle: "Record shape decoding (#57)"
weight: 45
description: "Design for the shared decode layer that replaces the per-rtype type switches. Step 1 of #40."
---

# Issue #57 — one decode layer for stored record values

Status: **implemented** on branch `issue57` (steps 0–8 below). Parent: #40 (RRset cache), release 0.81.
Scope per the issue: **refactor only, no behaviour change** on the wire, except
that records a reader used to drop because of a shape it did not know are now
served (the #55/#56 class of bug, fixed for every type at once).

## 1. What the code does today

Every stored record value in `memory.InMemoryZoneStore` is an untyped `any`.
Depending on *who* wrote it, the same RRset can be in any of these shapes:

| shape | produced by |
|---|---|
| `[]types.XRecord` (typed slice) | most rtype `Add`s (`mx`, `ns`, `ptr`, `srv`, `txt`, `caa`, `aaaa`, `ds`, `dnskey`, …) |
| `[]map[string]interface{}` | `a.go` Add, the ALIAS flattener (`dns/dnsutils/alias.go:147`), RRSIG Add |
| `[]interface{}` of `map[string]interface{}`, numbers as `float64` | **everything after a restart** (`loadFromStorage` → `encoding/json`), distributed replication, merkle repair, WAL/backup restore |
| `[]interface{}` of typed structs / pointers | DNSSEC signer (`storeRRSIG`), legacy |
| `map[string]interface{}` (single record) | SOA, CNAME, DNAME, SPF, NSEC, NSEC3, NSEC3PARAM, ALIAS after a restart |
| `types.XRecord` (single, typed) | the same types when freshly written; NSEC/NSEC3 chain rebuild writes typed values straight into the cache map |

Each rtype file re-implements a `switch val.(type)` over a *subset* of those in
`Add`, `Lookup` and `Delete` independently, and `internal.RRBuilders` (the AXFR
and DNSSEC-signing path) plus `memory/` (`ttlFromMap`, `firstRecordTTL`,
`nsecRecordFromRaw`, `soaRecordFromRaw`, `rrsigRecordsFromRaw`) are a third and
fourth copy. That is 21 files × up to 3 switches, plus 20 builders, plus 6
store-side decoders, all drifting. Numeric decoding also differs: most read
`ttl` as `float64` only, `soa.go` accepts eight numeric kinds, `ds.go` accepts
four but not `uint32`, `rrsig.go` round-trips through `encoding/json`.

### Gaps found in the inventory (all the same bug class)

- `a.go` `Lookup` does not accept `[]types.ARecord`; `RRBuilders["A"]` does.
- `aaaa.go` `Add` and `Delete` do not accept `[]map[string]interface{}` (the
  shape the ALIAS flattener writes). A manual AAAA `Add` at a flattened owner
  drops the flattened addresses; a `Delete` with a value **wipes the whole
  RRset** because the switch has no `default` and an empty filtered list means
  "delete the key". The same missing-`default` pattern is in `mx`, `ns`, `ptr`,
  `srv`, `txt` `Delete`.
- `RRBuilders["AAAA"]` does not accept `[]map[string]interface{}`, so flattened
  AAAA RRsets are answered but **not signed and absent from AXFR** until a
  persist round-trip changes their shape.
- `mx`, `ns`, `ptr`, `srv`, `txt`, `caa`, `ds`, `cds`, `dnskey`, `cdnskey`
  `Lookup` do not accept `[]map[string]interface{}` at all.
- `RRBuilders` for CNAME, DNAME, SPF, SOA, DNSKEY, CDNSKEY use unchecked type
  assertions on map fields and panic on a missing or non-`float64` field;
  `dns/dnsutils/utils.go:35-44` (SOA serial bump) likewise.
- `rrsig.go` `Add` writes `map[string][]map[string]interface{}` but
  `memory.cachedRRSIGs`/`invalidateRRSIGLocked` assert `map[string]any`, so
  API-added RRSIGs are neither cache-served nor invalidated.

## 2. Constraint that shapes the design: the stored form is protocol

`distributed/merkle.go:149-172` hashes each leaf as
`sha256(json.Marshal(value))` of the **raw in-memory Go value**. `encoding/json`
emits struct fields in declaration order and map keys alphabetically, so
`[]types.MXRecord{...}` and the equivalent `[]map[string]any` hash differently
even though they are the same records. A node that changes what it *stores* for
a type therefore disagrees with every peer still on the old release for the
whole rolling upgrade window, and anti-entropy repair will keep "fixing" it.

Consequence: **#57 must not change what any writer stores.** It normalises at
*read* time only. Changing the stored shape (typed everywhere, one shape on
disk) is step 1 of #40 and needs a canonical leaf hash (hash the decoded rows,
not the Go value) shipped one release ahead. That is out of scope here and
recorded as a prerequisite for #40.

## 3. The model

One new package, `go53/recshape`, imported by `internal`, `memory`,
`zone/rtypes`, `dns/dnsutils` and `distributed`. It depends only on `types` and
the standard library, so it sits below everything that reads records.

### 3.1 Rows: the one intermediate form

```go
package recshape

// Row is one record's fields as stored by any writer.
type Row map[string]any

// Rows folds any dynamic stored value into rows, without copying maps.
//   []map[string]any        → each element
//   []any                   → each element that is map[string]any (or Row)
//   map[string]any / Row    → one row (single-record types)
//   nil, anything else      → ok=false
func Rows(v any) ([]Row, bool)
```

Tolerant field access, one implementation for the whole repo, semantics = the
union of today's widest decoders (`soaUint32` ∪ `ttlFromMap` ∪ `rawFloat64`):

```go
func (r Row) String(key string) (string, bool)
func (r Row) Strings(key string) ([]string, bool)   // []string or []any of string (NSEC types)
func (r Row) Bool(key string) (bool, bool)
func (r Row) Uint32(key string) (uint32, bool)      // float64, float32, all int/uint kinds, json.Number
func (r Row) Uint16(key string) (uint16, bool)
func (r Row) Uint8(key string) (uint8, bool)
func (r Row) TTL(def uint32) uint32                 // "ttl", missing/unparsable/out of range → def
```

Integer getters return `ok=false` for negative, fractional or out-of-range
values instead of wrapping. Today `uint32(float64(-1))` is implementation-
defined; making it "not ok → default" is the only deliberate semantic change
and it only affects values that were already garbage.

### 3.2 Decode: typed fast path, rows slow path

```go
// Decode returns the typed records held in v.
//   []T   → returned as-is: no copy, no allocation (the hot path once #40 stores typed)
//   T     → []T{v}
//   else  → Rows(v) mapped through from; rows from rejects are skipped
func Decode[T any](v any, from func(Row) (T, bool)) ([]T, bool)

// Single is Decode for single-record types (SOA, CNAME, DNAME, SPF, ALIAS, NSEC, NSEC3, NSEC3PARAM).
func Single[T any](v any, from func(Row) (T, bool)) (T, bool)
```

Per-type constructors are the **only** per-type code left, one function each,
next to each other in `recshape/records.go`, using the exact JSON field names
of the `types` structs:

```go
func ARecord(r Row) (types.ARecord, bool) {
	ip, ok := r.String("ip")
	if !ok || ip == "" {
		return types.ARecord{}, false
	}
	return types.ARecord{IP: ip, TTL: r.TTL(3600)}, true
}
```

`ok=false` from a constructor means "this row is not a usable record of this
type" and the row is skipped, exactly as today's `continue` branches do.

Extra keys a writer adds (`alias`, `resolved_at` from the flattener) survive
because `Rows` never copies the map; readers that need them (`alias.go`) keep
using `Row` directly.

### 3.3 What each call site becomes

```go
// Lookup, list type
recs, ok := recshape.Decode(val, recshape.MXRecord)
if !ok || len(recs) == 0 { return nil, false }
// build []dns.RR from recs (unchanged code)

// Add, list type (read-modify-write)
current, _ := recshape.Decode(val, recshape.MXRecord)   // missing/foreign shape → empty, same as today
// dedupe, append, store as today

// Delete with a value
current, ok := recshape.Decode(raw, recshape.MXRecord)
if !ok { return fmt.Errorf("MX %s: undecodable stored value %T", host, raw) } // never wipe on unknown shape
```

`RRBuilders[X]` becomes `Decode`/`Single` + the existing RR construction, so
the query path, AXFR and the signer decode through the same function for the
first time. The store-side helpers (`ttlFromMap` + the 17-way `firstRecordTTL`
switch, `soaRecordFromRaw`, `nsecRecordFromRaw`, `nsec3RecordFromRaw`,
`nsec3ParamFromRaw`, `alias.go`'s `ttlFromAny`/`recordEntries`,
`utils.go`'s SOA bump) collapse to `Rows` + getters or `Single`.

`Add` and `Delete` continue to **write exactly the shape they write today**
(§2). Nothing in this issue touches `AddRecord`/`PutRecordRaw` or persistence.

## 4. Safety net: shape-parity test

The reason the #55/#56 class keeps recurring is that no test feeds the *same*
records in *every* shape to *every* reader. `zone/rtypes/shape_parity_test.go`
does exactly that and is the acceptance test for this issue:

1. For each rtype, one canonical record set declared once as typed structs.
2. Generated shapes: typed slice; `[]map[string]any` with `float64` numbers;
   `[]map[string]any` with `uint32` ttl (ALIAS/RRSIG style); `[]any` of maps;
   `encoding/json` round-trip of the typed slice (what a restart produces); for
   single-record types the single typed value and the single map.
3. Each shape is stored with `memStore.AddRecord` and read through
   `rtypes.Get(t).Lookup` **and** `internal.RRBuilders[t]`. All results must be
   identical (sorted `dns.RR.String()`), and identical to the typed-shape
   result.
4. `Delete` with a value on every shape must remove exactly that value and
   never empty the RRset.

The test is written first and is expected to fail for the gaps listed in §1;
each migration commit turns rows of the table green. It stays as the guard for
#40, whose whole point is to change shapes.

Existing tests remain unchanged and must stay green throughout:
`a_test.go` (#55), `aaaa_test.go` (#56), the per-type lifecycle tests,
`dnssec_lifecycle_test.go`, `internal/rrbuilder_test.go`,
`memory/dnssec_proofs_test.go`, `memory/memory_test.go` (TTL-mismatch guard),
`dns/dnsutils/alias_test.go`.

## 5. Performance

- `Decode` on `[]T` is a type switch and a return: no copy, no allocation. This
  is the shape #40 will store, so the cache-less hot path is already right.
- On the JSON shapes it allocates the `[]T` slice once (`make` with
  `len(rows)`), which is ≤ what the current `append`-grown code does. The rows
  themselves are the stored maps, not copies.
- Generic instantiation is per `T`; `from` is a direct function value. No
  reflection anywhere, no `encoding/json` on the read path (removes the
  per-signature `json.Marshal`+`Unmarshal` in `rrsig.go` if RRSIG is migrated).
- Baseline benchmarks are added **before** any migration and re-run after each
  phase: `BenchmarkLookup{A,AAAA,MX,TXT,SOA}` × {typed, json-slice, map-slice}
  in `zone/rtypes`, plus `BenchmarkRRBuilderA`. Acceptance: no benchmark
  regresses in ns/op or allocs/op. These are also the "establish benchmarks"
  deliverable the 0.80 goal left open and the baseline #40 measures against.
- Not fixed here but found on the hot path and worth their own two-line PRs:
  `internal.SanitizeFQDN` compiles a regexp on every call (`internal/util.go:86`,
  #60), and `dnskey.go`/`ds.go` allocate a dedupe map per query.

### Baseline (step 0, `go test -bench`, Go 1.26, before any migration)

`zone/rtypes/lookup_bench_test.go`, 2–3 records per RRset:

| benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| LookupA/typed | *skipped — not served today* | | |
| LookupA/json | 2925 | 3219 | 49 |
| LookupA/mapslice | 3455 | 3171 | 47 |
| LookupAAAA/typed | 3009 | 3066 | 45 |
| LookupAAAA/json | 2945 | 3139 | 47 |
| LookupAAAA/mapslice | 3022 | 3114 | 46 |
| LookupMX/typed | 2826 | 3018 | 43 |
| LookupMX/json | 3099 | 3082 | 44 |
| LookupMX/mapslice | *skipped — not served today* | | |
| LookupTXT/typed | 2980 | 3066 | 45 |
| LookupTXT/json | 2995 | 3211 | 47 |
| LookupTXT/mapslice | *skipped — not served today* | | |
| LookupSOA/typed | 2899 | 2986 | 42 |
| LookupSOA/json | 3238 | 3050 | 50 |

`internal/sanitize_bench_test.go`: `SanitizeFQDN` alone = **2349 ns/op, 2826 B/op,
38 allocs/op**. So ~80 % of a Lookup today is the regexp compile (#60), and the
shape decode is the remaining 4–8 allocs. #57 is measured on allocs/op for the
`json`/`mapslice` rows and must not raise them; the big ns/op win belongs to #60
and the typed fast path to #40.

## 6. Order of work (one commit each, all green before the next)

| # | step | files | risk |
|---|---|---|---|
| 0 | Benchmarks, baseline numbers recorded in this doc | `zone/rtypes/*_bench_test.go` | none |
| 1 | `recshape` package + exhaustive unit tests (every shape × every numeric kind × out-of-range) | `recshape/` | none, not wired |
| 2 | Shape-parity test, failing rows documented | `zone/rtypes/shape_parity_test.go` | none |
| 3 | List types with lifecycle tests: A, AAAA, MX, NS, PTR, SRV, TXT, CAA | `zone/rtypes/{a,aaaa,mx,ns,ptr,srv,txt,caa}.go` | low |
| 4 | DNSSEC list types: DS, CDS, DNSKEY, CDNSKEY (keep the dedupe helpers, replace `ParseToDNSKEYRecord`) | `zone/rtypes/{ds,cds,dnskey,cdnskey}.go`, `internal/util.go` | medium |
| 5 | Single-record types: CNAME, DNAME, SPF, ALIAS, SOA, NSEC, NSEC3, NSEC3PARAM | `zone/rtypes/…` | medium (denial path) |
| 6 | `internal.RRBuilders` → `recshape` (signing + AXFR now share the decoder) | `internal/rrbuilder.go` | medium; parity test is the gate |
| 7 | Store and dnsutils helpers: `firstRecordTTL`/`ttlFromMap`, `*FromRaw`, `alias.go` readers, `utils.go` SOA bump | `memory/memory.go`, `dns/dnsutils/{alias,utils}.go` | medium |
| 8 | Delete `ParseToDNSKEYRecord`, `toTTL`, `getFloat64`, `decodeRecord`, `soaUint32`, `rawFloat64`, … | — | none |

RRSIG is **deferred**: its value is a nested `typeCovered → owner → []sig` map,
it has a real bug (§1, last bullet) and its `Delete` is unimplemented. It gets
its own issue; `Decode` handles its inner lists when that work happens.

Also deliberately out of scope, filed as follow-ups rather than folded in:
stored-shape unification and canonical merkle hashing (#40 step 1);
`cname.go`/`spf.go` keying on the raw name instead of `normalizeRecordKey`;
`PutRecordRaw` skipping `validateRRSetMutationLocked`; the `SanitizeFQDN`
regexp.

### Result (step 8, `benchstat`, n=6 full run / n=12 focused run vs the step-0 commit)

allocs/op (deterministic):

| benchmark | before | after |
|---|---|---|
| LookupA/typed | *not served* | 47 |
| LookupA/json | 49 | **48** |
| LookupA/mapslice | 47 | 48 (A used to build RRs with no intermediate slice) |
| LookupAAAA/typed · json · mapslice | 45 · 47 · 46 | 45 · **46** · 46 |
| LookupMX/typed · json · mapslice | 43 · 44 · *not served* | 43 · 44 · 44 |
| LookupTXT/typed · json · mapslice | 45 · 47 · *not served* | 45 · **46** · 46 |
| LookupSOA/typed · json | 42 · 50 | 42 · **42** (legacy-key fallback no longer allocates) |
| geomean | 45.85 | 45.10 (−2 %) |

sec/op: no row is consistently significant across runs (full run geomean
+3.6 % with ±8–15 % noise; the focused n=12 run on the three JSON rows that
looked slower gives geomean +0.4 %, AAAA −6 %, MX +3 %, TXT +4 %, all within
noise). As predicted in §5, the decode is not where Lookup's time goes.

Three allocation leaks were found and fixed in `recshape` during the
migration: a closure capturing the output slice, a `make` before the
type check in `typedElements`, and the SOA legacy-key candidates being
built per field. Each showed up only because allocs/op was compared per
step.

## 7. Done when

- [x] No `switch … .(type)` over stored shapes remains in `zone/rtypes/*.go`,
  `internal/rrbuilder.go`, `memory/memory.go` or `dns/dnsutils/` other than
  inside `recshape` and in the RRSIG code deferred to #61. (`firstRecordTTL`
  keeps a typed dispatch over `[]types.X` slices; that is type dispatch, not
  shape tolerance, and the map shapes go through `recshape.Rows`.)
- [x] Shape-parity test: 19 types, every shape × Lookup × RRBuilders × Delete;
  `knownGaps` holds only the two NSEC3 rows that belong to #62.
- [x] All pre-existing tests green; `-race` clean for `recshape`, `memory`,
  `security`, `internal` and the parity test (the `-race` failures in
  `zone/rtypes` DNSSEC lifecycle and `dns/dnsutils` predate this branch and
  reproduce on `v0.80.0`).
- [x] Benchmarks: allocs/op at or below baseline except A/`[]map` (+1); time
  within noise. Numbers above are the #40 baseline.
- [ ] Upgrade test against `v0.80.0` data (run before merging).

Follow-ups filed while doing this: #59 (Delete wipes RRset; fixed here,
close with the PR), #60 (`SanitizeFQDN` regexp), #61 (RRSIG shape and
cache), #62 (NSEC3 direct query never matches since #43).
