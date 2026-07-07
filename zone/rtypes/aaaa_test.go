package rtypes

import (
	"testing"

	"github.com/miekg/dns"
	"go53/types"
)

func TestAAAARecordLifecycle(t *testing.T) {
	zone := "go53.test"
	name := "api6"
	ipv6 := "2001:db8::1"

	value := map[string]interface{}{
		"ip": ipv6,
	}

	rr, ok := Get(dns.TypeAAAA)
	if !ok {
		t.Fatalf("AAAA record type not found")
	}

	err := rr.Add(zone, name, value, nil)
	if err != nil {
		t.Fatalf("failed to add AAAA record: %v", err)
	}

	results, ok := rr.Lookup(name + "." + zone + ".")
	if !ok || len(results) == 0 {
		t.Fatalf("expected AAAA record for %s, got none", name+"."+zone+".")
	}

	aaaa, ok := results[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("expected AAAA record type in response")
	}

	if aaaa.AAAA.String() != ipv6 {
		t.Errorf("expected IPv6 %s, got %s", ipv6, aaaa.AAAA.String())
	}

	err = rr.Delete(name+"."+zone+".", ipv6)
	if err != nil {
		t.Fatalf("failed to delete AAAA record: %v", err)
	}

	results, _ = rr.Lookup(name + "." + zone + ".")
	if len(results) != 0 {
		t.Errorf("expected no AAAA record after delete")
	}
}

func TestAAAARecordServesMapShapeImmediately(t *testing.T) {
	zone := "aaaamap.test"
	name := "www"

	if err := GetMemStore().AddRecord(zone, string(types.TypeAAAA), name, []map[string]interface{}{
		{"ip": "2001:db8::20", "ttl": float64(60)},
	}); err != nil {
		t.Fatalf("failed to store AAAA in map shape: %v", err)
	}

	rr, ok := Get(dns.TypeAAAA)
	if !ok {
		t.Fatalf("AAAA record type not found")
	}

	results, ok := rr.Lookup(name + "." + zone + ".")
	if !ok || len(results) != 1 {
		t.Fatalf("expected 1 AAAA record served from the map shape, got %#v ok=%v", results, ok)
	}
	aaaa, ok := results[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("expected *dns.AAAA, got %T", results[0])
	}
	if aaaa.AAAA.String() != "2001:db8::20" {
		t.Errorf("expected 2001:db8::20, got %s", aaaa.AAAA.String())
	}
	if aaaa.Hdr.Ttl != 60 {
		t.Errorf("expected TTL 60, got %d", aaaa.Hdr.Ttl)
	}
}
