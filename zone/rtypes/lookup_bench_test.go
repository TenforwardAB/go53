package rtypes

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/miekg/dns"
	"go53/types"
)

// Baseline for #57/#40: the cost of Lookup per stored shape. The same records
// are stored typed (fresh Add), as []map (a.go Add, ALIAS flattener) and as the
// encoding/json shape every zone has after a restart or replication. A shape
// that the current Lookup does not serve is skipped rather than measured.

func jsonShape(b *testing.B, v any) any {
	b.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		b.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		b.Fatal(err)
	}
	return out
}

func mapSlice(b *testing.B, v any) []map[string]interface{} {
	b.Helper()
	items, ok := jsonShape(b, v).([]interface{})
	if !ok {
		b.Fatalf("expected a list, got %T", v)
	}
	out := make([]map[string]interface{}, 0, len(items))
	for _, it := range items {
		out = append(out, it.(map[string]interface{}))
	}
	return out
}

type benchShape struct {
	name  string
	value any
}

func benchShapes(b *testing.B, typed any) []benchShape {
	return []benchShape{
		{"typed", typed},
		{"json", jsonShape(b, typed)},
		{"mapslice", mapSlice(b, typed)},
	}
}

func benchLookup(b *testing.B, rrtype uint16, storeType types.RecordType, owner string, shapes []benchShape) {
	rr, ok := Get(rrtype)
	if !ok {
		b.Fatalf("rtype %d not registered", rrtype)
	}
	for i, s := range shapes {
		zone := fmt.Sprintf("bench-%s-%d.test.", dns.TypeToString[rrtype], i)
		if err := GetMemStore().AddRecord(zone, string(storeType), owner, s.value); err != nil {
			b.Fatalf("seed %s: %v", s.name, err)
		}
		GetMemStore().WaitForSigning()
		host := zone
		if owner != "@" {
			host = owner + "." + zone
		}
		b.Run(s.name, func(b *testing.B) {
			if _, ok := rr.Lookup(host); !ok {
				b.Skip("shape not served by the current Lookup")
			}
			b.ReportAllocs()
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				if _, ok := rr.Lookup(host); !ok {
					b.Fatal("lookup failed")
				}
			}
		})
	}
}

func BenchmarkLookupA(b *testing.B) {
	typed := []types.ARecord{{IP: "192.0.2.1", TTL: 300}, {IP: "192.0.2.2", TTL: 300}, {IP: "192.0.2.3", TTL: 300}}
	benchLookup(b, dns.TypeA, types.TypeA, "www", benchShapes(b, typed))
}

func BenchmarkLookupAAAA(b *testing.B) {
	typed := []types.AAAARecord{{IP: "2001:db8::1", TTL: 300}, {IP: "2001:db8::2", TTL: 300}}
	benchLookup(b, dns.TypeAAAA, types.TypeAAAA, "www", benchShapes(b, typed))
}

func BenchmarkLookupMX(b *testing.B) {
	typed := []types.MXRecord{{Host: "mx1.example.", Priority: 10, TTL: 300}, {Host: "mx2.example.", Priority: 20, TTL: 300}}
	benchLookup(b, dns.TypeMX, types.TypeMX, "@", benchShapes(b, typed))
}

func BenchmarkLookupTXT(b *testing.B) {
	typed := []types.TXTRecord{{Text: "v=spf1 -all", TTL: 300}, {Text: "go53 benchmark record", TTL: 300}}
	benchLookup(b, dns.TypeTXT, types.TypeTXT, "txt", benchShapes(b, typed))
}

func BenchmarkLookupSOA(b *testing.B) {
	typed := types.SOARecord{Ns: "ns1.example.", Mbox: "hostmaster.example.", Serial: 2026092901, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300, TTL: 3600}
	shapes := []benchShape{
		{"typed", typed},
		{"json", jsonShape(b, typed)},
	}
	benchLookup(b, dns.TypeSOA, types.TypeSOA, "@", shapes)
}
