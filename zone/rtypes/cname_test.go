package rtypes

import (
	"testing"

	"github.com/miekg/dns"
)

func TestCNAMERecordLifecycle(t *testing.T) {
	zone := "go53.test"
	name := "alias"
	target := "real.go53.test."

	value := map[string]interface{}{
		"target": target,
	}

	rr, ok := Get(dns.TypeCNAME)
	if !ok {
		t.Fatalf("CNAME record type not found")
	}

	err := rr.Add(zone, name, value, nil)
	if err != nil {
		t.Fatalf("failed to add CNAME record: %v", err)
	}

	results, ok := rr.Lookup(name + "." + zone + ".")
	if !ok || len(results) == 0 {
		t.Fatalf("expected CNAME record for %s, got none", name+"."+zone+".")
	}

	cname, ok := results[0].(*dns.CNAME)
	if !ok {
		t.Fatalf("expected CNAME record type in response")
	}

	if cname.Target != target {
		t.Errorf("expected target %s, got %s", target, cname.Target)
	}

	err = rr.Delete(name+"."+zone+".", target)
	if err != nil {
		t.Fatalf("failed to delete CNAME record: %v", err)
	}

	results, _ = rr.Lookup(name + "." + zone + ".")
	if len(results) != 0 {
		t.Errorf("expected no CNAME record after delete")
	}
}
