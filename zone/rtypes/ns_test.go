package rtypes

import (
	"testing"

	"github.com/miekg/dns"
)

func TestNSRecordLifecycle(t *testing.T) {
	zone := "go53.test"
	name := "@"
	ns := "ns1.go53.test."

	value := map[string]interface{}{
		"ns": ns,
	}

	rr, ok := Get(dns.TypeNS)
	if !ok {
		t.Fatalf("NS record type not found")
	}

	err := rr.Add(zone, name, value, nil)
	if err != nil {
		t.Fatalf("failed to add NS record: %v", err)
	}

	results, ok := rr.Lookup(zone + ".")
	if !ok || len(results) == 0 {
		t.Fatalf("expected NS record for %s, got none", zone+".")
	}

	nsrec, ok := results[0].(*dns.NS)
	if !ok {
		t.Fatalf("expected NS record type in response")
	}

	if nsrec.Ns != ns {
		t.Errorf("expected NS %s, got %s", ns, nsrec.Ns)
	}

	err = rr.Delete(zone+".", ns)
	if err != nil {
		t.Fatalf("failed to delete NS record: %v", err)
	}

	results, _ = rr.Lookup(zone + ".")
	if len(results) != 0 {
		t.Errorf("expected no NS record after delete")
	}
}
