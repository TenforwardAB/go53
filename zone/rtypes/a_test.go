package rtypes

import (
	"testing"

	"github.com/miekg/dns"
)

func TestARecordLifecycle(t *testing.T) {
	zone := "go53.test"
	name := "api"
	ip := "192.0.2.1"

	value := map[string]interface{}{
		"ip": ip,
	}

	rr, ok := Get(dns.TypeA)
	if !ok {
		t.Fatalf("A record type not found")
	}

	err := rr.Add(zone, name, value, nil)
	if err != nil {
		t.Fatalf("failed to add A record: %v", err)
	}

	results, ok := rr.Lookup(name + "." + zone + ".")
	if !ok || len(results) == 0 {
		t.Fatalf("expected A record for %s, got none", name+"."+zone+".")
	}

	a, ok := results[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A record type in response")
	}

	if a.A.String() != ip {
		t.Errorf("expected IP %s, got %s", ip, a.A.String())
	}

	err = rr.Delete(name+"."+zone+".", ip)
	if err != nil {
		t.Fatalf("failed to delete A record: %v", err)
	}

	results, _ = rr.Lookup(name + "." + zone + ".")
	if len(results) != 0 {
		t.Errorf("expected no A record after delete")
	}
}
