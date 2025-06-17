package rtypes

import (
	"testing"

	"github.com/miekg/dns"
)

func TestSRVRecordLifecycle(t *testing.T) {
	zone := "go53.test"
	name := "_sip._tcp"
	target := "sipserver.go53.test."
	priority := 10
	weight := 5
	port := 5060

	value := map[string]interface{}{
		"priority": float64(priority),
		"weight":   float64(weight),
		"port":     float64(port),
		"target":   target,
	}

	rr, ok := Get(dns.TypeSRV)
	if !ok {
		t.Fatalf("SRV record type not found")
	}

	err := rr.Add(zone, name, value, nil)
	if err != nil {
		t.Fatalf("failed to add SRV record: %v", err)
	}

	fqdn := name + "." + zone + "."
	results, ok := rr.Lookup(fqdn)
	if !ok || len(results) == 0 {
		t.Fatalf("expected SRV record for %s, got none", fqdn)
	}

	srv, ok := results[0].(*dns.SRV)
	if !ok {
		t.Fatalf("expected SRV record type in response")
	}

	if srv.Target != target {
		t.Errorf("expected target %s, got %s", target, srv.Target)
	}
	if srv.Port != uint16(port) {
		t.Errorf("expected port %d, got %d", port, srv.Port)
	}
	if srv.Priority != uint16(priority) {
		t.Errorf("expected priority %d, got %d", priority, srv.Priority)
	}
	if srv.Weight != uint16(weight) {
		t.Errorf("expected weight %d, got %d", weight, srv.Weight)
	}

	err = rr.Delete(fqdn, map[string]interface{}{
		"target": target,
		"port":   float64(port),
	})
	if err != nil {
		t.Fatalf("failed to delete SRV record: %v", err)
	}

	results, _ = rr.Lookup(fqdn)
	if len(results) != 0 {
		t.Errorf("expected no SRV record after delete")
	}
}
