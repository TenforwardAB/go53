package dns

import (
	"encoding/json"
	"fmt"
	"testing"

	mdns "github.com/miekg/dns"
	"go53/types"
	"go53/zone"
	"go53/zone/rtypes"
)

// Baseline for #40: the whole query path (handleRequest) per answer kind,
// with the zone's RRsets stored typed (fresh Add) and in the encoding/json
// shape every zone has after a restart or replication.

func benchZone(b *testing.B, zoneName string, jsonShape bool) {
	b.Helper()
	setupDNSHandlerTestStore(b)
	store := rtypes.GetMemStore()
	put := func(rrtype string, owner string, typed any) {
		v := typed
		if jsonShape {
			raw, err := json.Marshal(typed)
			if err != nil {
				b.Fatal(err)
			}
			var out any
			if err := json.Unmarshal(raw, &out); err != nil {
				b.Fatal(err)
			}
			v = out
		}
		if err := store.AddRecord(zoneName, rrtype, owner, v); err != nil {
			b.Fatalf("seed %s %s: %v", rrtype, owner, err)
		}
	}
	put("SOA", "@", types.SOARecord{Ns: "ns1." + zoneName, Mbox: "hostmaster." + zoneName, Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300, TTL: 3600})
	put("NS", "@", []types.NSRecord{{NS: "ns1." + zoneName, TTL: 3600}, {NS: "ns2." + zoneName, TTL: 3600}})
	put("A", "ns1", []types.ARecord{{IP: "192.0.2.1", TTL: 3600}})
	put("A", "ns2", []types.ARecord{{IP: "192.0.2.2", TTL: 3600}})
	put("A", "www", []types.ARecord{{IP: "192.0.2.10", TTL: 300}, {IP: "192.0.2.11", TTL: 300}, {IP: "192.0.2.12", TTL: 300}})
	put("AAAA", "www", []types.AAAARecord{{IP: "2001:db8::10", TTL: 300}})
	put("MX", "@", []types.MXRecord{{Host: "mx1." + zoneName, Priority: 10, TTL: 300}, {Host: "mx2." + zoneName, Priority: 20, TTL: 300}})
	put("CNAME", "alias", types.CNAMERecord{Target: "www." + zoneName, TTL: 300})
	put("TXT", "txt", []types.TXTRecord{{Text: "v=spf1 -all", TTL: 300}})
	store.WaitForSigning()
}

type benchQuery struct {
	name    string
	qname   string
	qtype   uint16
	rcode   int
	answers int
}

func benchQueries(zoneName string) []benchQuery {
	return []benchQuery{
		{"A", "www." + zoneName, mdns.TypeA, mdns.RcodeSuccess, 3},
		{"AAAA", "www." + zoneName, mdns.TypeAAAA, mdns.RcodeSuccess, 1},
		{"MX-apex", zoneName, mdns.TypeMX, mdns.RcodeSuccess, 2},
		{"CNAME-chain", "alias." + zoneName, mdns.TypeA, mdns.RcodeSuccess, 4},
		{"NODATA", "www." + zoneName, mdns.TypeTXT, mdns.RcodeSuccess, 0},
		{"NXDOMAIN", "missing." + zoneName, mdns.TypeA, mdns.RcodeNameError, 0},
	}
}

func benchHandle(b *testing.B, jsonShape bool) {
	zoneName := "bench.test."
	benchZone(b, zoneName, jsonShape)
	for _, q := range benchQueries(zoneName) {
		b.Run(q.name, func(b *testing.B) {
			req := new(mdns.Msg)
			req.SetQuestion(q.qname, q.qtype)
			w := &captureResponseWriter{}
			handleRequest(w, req)
			if w.msg == nil || w.msg.Rcode != q.rcode || len(w.msg.Answer) != q.answers {
				b.Fatalf("%s: rcode=%v answers=%d, want rcode=%v answers=%d", q.name, w.msg.Rcode, len(w.msg.Answer), q.rcode, q.answers)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				handleRequest(w, req)
			}
		})
	}
}

func BenchmarkHandleRequestTyped(b *testing.B) { benchHandle(b, false) }
func BenchmarkHandleRequestJSON(b *testing.B)  { benchHandle(b, true) }

// The CNAME chain and glue paths issue several Lookups per query; this
// measures a single zone.LookupRecord for reference against the rtypes
// micro-benchmark.
func BenchmarkZoneLookupRecordA(b *testing.B) {
	zoneName := "bench.test."
	benchZone(b, zoneName, true)
	name := fmt.Sprintf("www.%s", zoneName)
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if _, ok := zone.LookupRecord(mdns.TypeA, name); !ok {
			b.Fatal("miss")
		}
	}
}
