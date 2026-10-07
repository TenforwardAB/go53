package recshape

import (
	"encoding/json"
	"math"
	"reflect"
	"testing"

	"go53/types"
)

// jsonShape round-trips v through encoding/json: the shape every stored value
// has after a restart, replication or restore.
func jsonShape(t *testing.T, v any) any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRowsShapes(t *testing.T) {
	m1 := map[string]any{"ip": "192.0.2.1"}
	m2 := map[string]any{"ip": "192.0.2.2"}
	cases := []struct {
		name string
		in   any
		want []Row
		ok   bool
	}{
		{"nil", nil, nil, false},
		{"string", "nope", nil, false},
		{"typed slice is not a map shape", []types.ARecord{{IP: "x"}}, nil, false},
		{"single map", m1, []Row{m1}, true},
		{"single Row", Row(m1), []Row{m1}, true},
		{"[]map", []map[string]any{m1, m2}, []Row{m1, m2}, true},
		{"[]Row", []Row{m1, m2}, []Row{m1, m2}, true},
		{"[]any of maps", []any{m1, m2}, []Row{m1, m2}, true},
		{"[]any skips non-maps", []any{m1, "junk", 3, m2}, []Row{m1, m2}, true},
		{"empty []any", []any{}, []Row{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Rows(tc.in)
			if ok != tc.ok {
				t.Fatalf("ok=%v want %v", ok, tc.ok)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d rows, want %d", len(got), len(tc.want))
			}
			for i := range got {
				if !reflect.DeepEqual(map[string]any(got[i]), map[string]any(tc.want[i])) {
					t.Errorf("row %d = %v want %v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestRowsDoesNotCopyMaps(t *testing.T) {
	m := map[string]any{"ip": "192.0.2.1", "alias": true}
	rows, _ := Rows([]any{m})
	rows[0]["seen"] = true
	if _, ok := m["seen"]; !ok {
		t.Fatal("Rows copied the map; readers must see the writer's extra keys through the same map")
	}
}

func TestNumericGetters(t *testing.T) {
	ok := []struct {
		name string
		in   any
		want uint64
	}{
		{"float64", float64(300), 300},
		{"float32", float32(300), 300},
		{"int", int(300), 300},
		{"int8", int8(100), 100},
		{"int16", int16(300), 300},
		{"int32", int32(300), 300},
		{"int64", int64(300), 300},
		{"uint", uint(300), 300},
		{"uint8", uint8(200), 200},
		{"uint16", uint16(300), 300},
		{"uint32", uint32(300), 300},
		{"uint64", uint64(300), 300},
		{"json.Number int", json.Number("300"), 300},
		{"json.Number float", json.Number("300.0"), 300},
		{"zero", float64(0), 0},
		{"max uint32 as float", float64(math.MaxUint32), math.MaxUint32},
	}
	for _, tc := range ok {
		t.Run("ok/"+tc.name, func(t *testing.T) {
			got, isOK := Row{"n": tc.in}.Uint64("n")
			if !isOK || got != tc.want {
				t.Fatalf("Uint64 = %d,%v want %d,true", got, isOK, tc.want)
			}
		})
	}

	reject := []struct {
		name string
		in   any
	}{
		{"missing", nil},
		{"string", "300"},
		{"bool", true},
		{"negative float", float64(-1)},
		{"negative int", int(-1)},
		{"negative int64", int64(-5)},
		{"fraction", 1.5},
		{"NaN", math.NaN()},
		{"+Inf", math.Inf(1)},
		{"too large float", float64(math.MaxUint64) * 2},
		{"json.Number negative", json.Number("-1")},
		{"json.Number garbage", json.Number("abc")},
	}
	for _, tc := range reject {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			r := Row{}
			if tc.in != nil {
				r["n"] = tc.in
			}
			if got, isOK := r.Uint64("n"); isOK {
				t.Fatalf("Uint64 accepted %v as %d", tc.in, got)
			}
		})
	}
}

func TestBoundedGetters(t *testing.T) {
	r := Row{
		"u32ok": float64(math.MaxUint32), "u32over": float64(math.MaxUint32) + 1,
		"u16ok": float64(math.MaxUint16), "u16over": float64(math.MaxUint16) + 1,
		"u8ok": float64(math.MaxUint8), "u8over": float64(math.MaxUint8) + 1,
	}
	if v, ok := r.Uint32("u32ok"); !ok || v != math.MaxUint32 {
		t.Errorf("Uint32 max: %d,%v", v, ok)
	}
	if _, ok := r.Uint32("u32over"); ok {
		t.Error("Uint32 accepted an out-of-range value")
	}
	if v, ok := r.Uint16("u16ok"); !ok || v != math.MaxUint16 {
		t.Errorf("Uint16 max: %d,%v", v, ok)
	}
	if _, ok := r.Uint16("u16over"); ok {
		t.Error("Uint16 accepted an out-of-range value")
	}
	if v, ok := r.Uint8("u8ok"); !ok || v != math.MaxUint8 {
		t.Errorf("Uint8 max: %d,%v", v, ok)
	}
	if _, ok := r.Uint8("u8over"); ok {
		t.Error("Uint8 accepted an out-of-range value")
	}
}

func TestTTL(t *testing.T) {
	cases := []struct {
		name string
		row  Row
		want uint32
	}{
		{"float64 (json)", Row{"ttl": float64(60)}, 60},
		{"uint32 (typed writer)", Row{"ttl": uint32(60)}, 60},
		{"int (tests)", Row{"ttl": 60}, 60},
		{"missing → default", Row{}, DefaultTTL},
		{"string → default", Row{"ttl": "60"}, DefaultTTL},
		{"negative → default, never wrapped", Row{"ttl": float64(-1)}, DefaultTTL},
		{"too large → default, never truncated", Row{"ttl": float64(math.MaxUint32) + 1}, DefaultTTL},
		{"zero is a valid ttl", Row{"ttl": float64(0)}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.row.TTL(DefaultTTL); got != tc.want {
				t.Fatalf("TTL = %d want %d", got, tc.want)
			}
		})
	}
}

func TestStringGetters(t *testing.T) {
	r := Row{"s": "x", "n": 1, "list": []any{"A", 2, "NS"}, "slist": []string{"A"}, "b": true}
	if s, ok := r.String("s"); !ok || s != "x" {
		t.Error("String")
	}
	if _, ok := r.String("n"); ok {
		t.Error("String accepted a number")
	}
	if _, ok := r.String("missing"); ok {
		t.Error("String accepted a missing key")
	}
	if l, ok := r.Strings("list"); !ok || !reflect.DeepEqual(l, []string{"A", "NS"}) {
		t.Errorf("Strings []any = %v", l)
	}
	if l, ok := r.Strings("slist"); !ok || !reflect.DeepEqual(l, []string{"A"}) {
		t.Errorf("Strings []string = %v", l)
	}
	if _, ok := r.Strings("s"); ok {
		t.Error("Strings accepted a scalar")
	}
	if b, ok := r.Bool("b"); !ok || !b {
		t.Error("Bool")
	}
	if _, ok := r.Bool("s"); ok {
		t.Error("Bool accepted a string")
	}
}

func TestDecodeTypedFastPathReturnsSameSlice(t *testing.T) {
	typed := []types.MXRecord{{Host: "mx.", Priority: 10, TTL: 300}}
	got, ok := Decode(typed, MXRecord)
	if !ok {
		t.Fatal("not ok")
	}
	if &got[0] != &typed[0] {
		t.Fatal("Decode copied a typed slice; the fast path must return it as-is")
	}
}

func TestDecodeTypedFastPathAllocFree(t *testing.T) {
	// Boxed once here, as the store hands values out as any already; boxing a
	// slice header inside the loop would be the caller's allocation, not ours.
	var stored any = []types.MXRecord{{Host: "mx.", Priority: 10, TTL: 300}}
	allocs := testing.AllocsPerRun(1000, func() {
		if _, ok := Decode(stored, MXRecord); !ok {
			t.Fatal("not ok")
		}
	})
	if allocs != 0 {
		t.Fatalf("typed fast path allocates: %.1f allocs/op", allocs)
	}
}

func TestSingleAllocFree(t *testing.T) {
	var typed any = types.SOARecord{Ns: "ns.", Mbox: "m.", TTL: 1}
	var asMap any = map[string]any{"ns": "ns.", "mbox": "m.", "ttl": float64(1)}
	for name, in := range map[string]any{"typed": typed, "map": asMap} {
		allocs := testing.AllocsPerRun(1000, func() {
			if _, ok := Single(in, SOARecord); !ok {
				t.Fatal("not ok")
			}
		})
		if allocs != 0 {
			t.Errorf("Single(%s) allocates: %.1f allocs/op", name, allocs)
		}
	}
}

func TestDecodeShapes(t *testing.T) {
	want := []types.MXRecord{
		{Host: "mx1.example.", Priority: 10, TTL: 300},
		{Host: "mx2.example.", Priority: 20, TTL: 300},
	}
	asMaps := []map[string]any{
		{"host": "mx1.example.", "priority": float64(10), "ttl": float64(300)},
		{"host": "mx2.example.", "priority": float64(20), "ttl": float64(300)},
	}
	cases := []struct {
		name string
		in   any
	}{
		{"typed slice", want},
		{"[]map float64", asMaps},
		{"[]any of maps", []any{asMaps[0], asMaps[1]}},
		{"json round-trip of typed", jsonShape(t, want)},
		{"json round-trip of maps", jsonShape(t, asMaps)},
		{"[]any of typed values", []any{want[0], want[1]}},
		{"[]any of typed pointers", []any{&want[0], &want[1]}},
		{"uint32 ttl + int priority", []map[string]any{
			{"host": "mx1.example.", "priority": 10, "ttl": uint32(300)},
			{"host": "mx2.example.", "priority": 20, "ttl": uint32(300)},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Decode(tc.in, MXRecord)
			if !ok {
				t.Fatal("ok=false")
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got %+v want %+v", got, want)
			}
		})
	}
}

func TestDecodeSingleValues(t *testing.T) {
	rec := types.CNAMERecord{Target: "www.example.", TTL: 120}
	for name, in := range map[string]any{
		"typed value":   rec,
		"typed pointer": &rec,
		"map":           map[string]any{"target": "www.example.", "ttl": float64(120)},
		"json":          jsonShape(t, rec),
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := Single(in, CNAMERecord)
			if !ok || got != rec {
				t.Fatalf("got %+v,%v want %+v", got, ok, rec)
			}
		})
	}
}

func TestSingleShapes(t *testing.T) {
	rec := types.CNAMERecord{Target: "www.example.", TTL: 120}
	if got, ok := Single([]types.CNAMERecord{rec}, CNAMERecord); !ok || got != rec {
		t.Errorf("Single([]T) = %+v,%v", got, ok)
	}
	if _, ok := Single([]types.CNAMERecord{}, CNAMERecord); ok {
		t.Error("Single(empty []T) must be ok=false")
	}
	if got, ok := Single(Row{"target": "www.example.", "ttl": 120}, CNAMERecord); !ok || got != rec {
		t.Errorf("Single(Row) = %+v,%v", got, ok)
	}
	if got, ok := Single([]any{map[string]any{"target": "www.example.", "ttl": float64(120)}}, CNAMERecord); !ok || got != rec {
		t.Errorf("Single([]any of map) = %+v,%v", got, ok)
	}
}

func TestDecodeUnknownVsEmpty(t *testing.T) {
	if _, ok := Decode(nil, ARecord); ok {
		t.Error("nil must be unknown (ok=false)")
	}
	if _, ok := Decode("garbage", ARecord); ok {
		t.Error("a string must be unknown (ok=false)")
	}
	if _, ok := Decode([]types.MXRecord{{Host: "x"}}, ARecord); ok {
		t.Error("a typed slice of another type must be unknown (ok=false)")
	}
	var nilPtr *types.ARecord
	if _, ok := Decode(nilPtr, ARecord); ok {
		t.Error("a nil pointer must be unknown")
	}
	got, ok := Decode([]any{}, ARecord)
	if !ok || len(got) != 0 {
		t.Error("an empty list is known and empty (ok=true, len 0)")
	}
	got, ok = Decode([]map[string]any{{"ttl": float64(1)}}, ARecord)
	if !ok || len(got) != 0 {
		t.Error("rows the constructor rejects are skipped, shape still known")
	}
	if _, ok := Single([]any{}, CNAMERecord); ok {
		t.Error("Single on an empty list must be ok=false")
	}
}

func TestDecodeMixedTypedAndMapFallsBackToRows(t *testing.T) {
	// A []any holding one typed struct and one map: not all-typed, so the
	// typed rebuild bails and Rows handles the map. The struct is not a map
	// and is skipped — the documented limit of the fallback.
	in := []any{types.ARecord{IP: "192.0.2.1", TTL: 1}, map[string]any{"ip": "192.0.2.2", "ttl": float64(2)}}
	got, ok := Decode(in, ARecord)
	if !ok || len(got) != 1 || got[0].IP != "192.0.2.2" {
		t.Fatalf("got %+v,%v", got, ok)
	}
}

// roundTrip: typed → JSON → constructor must reproduce the struct (Chunks is
// json:"-" and stays empty), and the identifying field is required.
func roundTrip[T comparable](t *testing.T, name string, typed T, from func(Row) (T, bool), required string) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		got, ok := Single(jsonShape(t, typed), from)
		if !ok {
			t.Fatalf("json shape not decoded")
		}
		if !reflect.DeepEqual(got, typed) {
			t.Fatalf("round-trip\n got %+v\nwant %+v", got, typed)
		}
		if required != "" {
			m := jsonShape(t, typed).(map[string]any)
			delete(m, required)
			if _, ok := Single(m, from); ok {
				t.Fatalf("decoded without required field %q", required)
			}
		}
	})
}

// roundTripSlice is roundTrip for structs holding slices (not comparable).
func roundTripSlice[T any](t *testing.T, name string, typed T, from func(Row) (T, bool), required string) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		got, ok := Single(jsonShape(t, typed), from)
		if !ok {
			t.Fatalf("json shape not decoded")
		}
		if !reflect.DeepEqual(got, typed) {
			t.Fatalf("round-trip\n got %+v\nwant %+v", got, typed)
		}
		if required != "" {
			m := jsonShape(t, typed).(map[string]any)
			delete(m, required)
			if _, ok := Single(m, from); ok {
				t.Fatalf("decoded without required field %q", required)
			}
		}
	})
}

func TestConstructorsRoundTrip(t *testing.T) {
	roundTrip(t, "A", types.ARecord{IP: "192.0.2.1", TTL: 60}, ARecord, "ip")
	roundTrip(t, "AAAA", types.AAAARecord{IP: "2001:db8::1", TTL: 60}, AAAARecord, "ip")
	roundTrip(t, "NS", types.NSRecord{NS: "ns1.example.", TTL: 60}, NSRecord, "ns")
	roundTrip(t, "MX", types.MXRecord{Host: "mx.example.", Priority: 10, TTL: 60}, MXRecord, "host")
	roundTrip(t, "PTR", types.PTRRecord{Ptr: "www.example.", TTL: 60}, PTRRecord, "ptr")
	roundTripSlice(t, "TXT", types.TXTRecord{Text: "v=spf1 -all", TTL: 60}, TXTRecord, "text")
	roundTripSlice(t, "SPF", types.SPFRecord{Text: "v=spf1 -all", TTL: 60}, SPFRecord, "text")
	roundTrip(t, "SRV", types.SRVRecord{Priority: 1, Weight: 2, Port: 5060, Target: "sip.example.", TTL: 60}, SRVRecord, "target")
	roundTrip(t, "CNAME", types.CNAMERecord{Target: "www.example.", TTL: 60}, CNAMERecord, "target")
	roundTrip(t, "DNAME", types.DNAMERecord{Target: "new.example.", TTL: 60}, DNAMERecord, "target")
	roundTrip(t, "ALIAS", types.ALIASRecord{Target: "cdn.example.", TTL: 30}, ALIASRecord, "target")
	roundTrip(t, "CAA", types.CAARecord{Flag: 128, Tag: "issue", Value: "ca.example", TTL: 60}, CAARecord, "tag")
	roundTrip(t, "SOA", types.SOARecord{Ns: "ns1.example.", Mbox: "hostmaster.example.", Serial: 2026092901, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300, TTL: 3600}, SOARecord, "ns")
	roundTrip(t, "DNSKEY", types.DNSKEYRecord{Flags: 257, Protocol: 3, Algorithm: 13, PublicKey: "AAAA", TTL: 60}, DNSKEYRecord, "public_key")
	roundTrip(t, "CDNSKEY", types.CDNSKEYRecord{Flags: 257, Protocol: 3, Algorithm: 13, PublicKey: "AAAA", TTL: 60}, CDNSKEYRecord, "public_key")
	roundTrip(t, "DS", types.DSRecord{KeyTag: 12345, Algorithm: 13, DigestType: 2, Digest: "ABCDEF", TTL: 60}, DSRecord, "digest")
	roundTrip(t, "CDS", types.CDSRecord{KeyTag: 12345, Algorithm: 13, DigestType: 2, Digest: "ABCDEF", TTL: 60}, CDSRecord, "digest")
	roundTripSlice(t, "NSEC", types.NSECRecord{NextDomain: "b.example.", Types: []string{"A", "RRSIG", "NSEC"}, TTL: 60}, NSECRecord, "next_domain")
	roundTripSlice(t, "NSEC3", types.NSEC3Record{HashAlg: 1, Flags: 1, Iterations: 0, Salt: "AB", NextHashed: "P3ZQ", Types: []string{"A"}, TTL: 60}, NSEC3Record, "next_hashed")
	roundTrip(t, "NSEC3PARAM", types.NSEC3ParamRecord{HashAlgorithm: 1, Flags: 0, Iterations: 5, Salt: "AB", TTL: 60}, NSEC3ParamRecord, "")
}

func TestConstructorDefaults(t *testing.T) {
	if a, _ := ARecord(Row{"ip": "192.0.2.1"}); a.TTL != DefaultTTL {
		t.Errorf("A default ttl = %d", a.TTL)
	}
	if al, _ := ALIASRecord(Row{"target": "x."}); al.TTL != DefaultALIASTTL {
		t.Errorf("ALIAS default ttl = %d", al.TTL)
	}
	if k, _ := DNSKEYRecord(Row{"public_key": "AAAA"}); k.Protocol != 3 || k.TTL != DefaultTTL {
		t.Errorf("DNSKEY defaults = %+v", k)
	}
	if k, _ := DNSKEYRecord(Row{"public_key": "AAAA", "protocol": float64(0)}); k.Protocol != 0 {
		t.Error("explicit protocol 0 must win over the default")
	}
	if d, _ := DSRecord(Row{"digest": " abcdef "}); d.Digest != "ABCDEF" {
		t.Errorf("DS digest not normalised: %q", d.Digest)
	}
	// SOA: capitalised legacy keys, relative names made absolute, wide numerics.
	soa, ok := SOARecord(Row{"Ns": "ns1.example", "Mbox": "hostmaster.example", "Serial": uint32(7), "refresh": int64(1)})
	if !ok || soa.Ns != "ns1.example." || soa.Mbox != "hostmaster.example." || soa.Serial != 7 || soa.Refresh != 1 {
		t.Errorf("SOA legacy keys = %+v,%v", soa, ok)
	}
	if _, ok := SOARecord(Row{"ns": "ns1."}); ok {
		t.Error("SOA without mbox must be rejected")
	}
	// TXT with an empty text is still a record; TXT without text is not.
	if _, ok := TXTRecord(Row{"text": ""}); !ok {
		t.Error("TXT with empty text should decode")
	}
	if _, ok := TXTRecord(Row{"ttl": float64(1)}); ok {
		t.Error("TXT without text must be rejected")
	}
	// NSEC types from the JSON []any shape.
	n, _ := NSECRecord(Row{"next_domain": "b.", "types": []any{"A", "NS"}})
	if !reflect.DeepEqual(n.Types, []string{"A", "NS"}) {
		t.Errorf("NSEC types = %v", n.Types)
	}
}
