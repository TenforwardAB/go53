package rtypes

import (
	"testing"

	"github.com/miekg/dns"
)

func TestSOARecordLifecycle(t *testing.T) {
	zone := "go33.test"
	name := "@"
	ns := "ns1.go33.test."
	mbox := "hostmaster.go33.test."

	value := map[string]interface{}{
		"Ns":      ns,
		"Mbox":    mbox,
		"Refresh": 3600,
		"Retry":   600,
		"Expire":  86400,
		"Minimum": 60,
	}

	rr, ok := Get(dns.TypeSOA)
	if !ok {
		t.Fatalf("SOA record type not found")
	}

	err := rr.Add(zone, name, value, nil)
	if err != nil {
		t.Fatalf("failed to add SOA record: %v", err)
	}

	results, ok := rr.Lookup(zone + ".")
	t.Logf("RR after Add: %+v", results[0])
	if !ok || len(results) == 0 {
		t.Fatalf("expected SOA record for %s, got none", zone+".")
	}

	soarec, ok := results[0].(*dns.SOA)
	if !ok {
		t.Fatalf("expected SOA record type in response")
	}

	if soarec.Ns != ns {
		t.Errorf("expected NS %s, got %s", ns, soarec.Ns)
	}
	if soarec.Mbox != mbox {
		t.Errorf("expected MBOX %s, got %s", mbox, soarec.Mbox)
	}

	err = rr.Delete(zone+".", ns)
	if err != nil {
		t.Fatalf("failed to delete SOA record: %v", err)
	}

	results, _ = rr.Lookup(zone + ".")
	if len(results) != 0 {
		t.Errorf("expected no SOA record after delete")
	}
}
