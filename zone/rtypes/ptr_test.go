package rtypes

import (
	"testing"

	"github.com/miekg/dns"
)

func TestPTRRecordLifecycle(t *testing.T) {
	zone := "go53.test"
	name := "5.4.3.2.in-addr.arpa"
	ptr := "host.go53.test."
	fqdn := name + "." + zone + "."

	value := map[string]interface{}{
		"ptr": ptr,
	}

	rr, ok := Get(dns.TypePTR)
	if !ok {
		t.Fatalf("PTR record type not found")
	}

	err := rr.Add(zone, name, value, nil)
	if err != nil {
		t.Fatalf("failed to add PTR record: %v", err)
	}

	results, ok := rr.Lookup(fqdn)
	if !ok || len(results) == 0 {
		t.Fatalf("expected PTR record for %s, got none", fqdn)
	}

	ptrRec, ok := results[0].(*dns.PTR)
	if !ok {
		t.Fatalf("expected PTR record type in response")
	}

	if ptrRec.Ptr != ptr {
		t.Errorf("expected ptr %q, got %q", ptr, ptrRec.Ptr)
	}

	err = rr.Delete(fqdn, ptr)
	if err != nil {
		t.Fatalf("failed to delete PTR record: %v", err)
	}

	results, _ = rr.Lookup(fqdn)
	if len(results) != 0 {
		t.Errorf("expected no PTR record after delete, got: %+v", results)
	}
}
