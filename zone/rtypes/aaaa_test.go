package rtypes

import (
	"testing"

	"github.com/miekg/dns"
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
