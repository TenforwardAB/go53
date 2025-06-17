package rtypes

import (
	"testing"

	"github.com/miekg/dns"
)

func TestMXRecordLifecycle(t *testing.T) {
	zone := "go53.test"
	name := "@"
	host := "mail.go53.test."
	priority := uint16(10)

	value := map[string]interface{}{
		"host":     host,
		"priority": float64(priority),
	}

	rr, ok := Get(dns.TypeMX)
	if !ok {
		t.Fatalf("MX record type not found")
	}

	err := rr.Add(zone, name, value, nil)
	if err != nil {
		t.Fatalf("failed to add MX record: %v", err)
	}

	results, ok := rr.Lookup(zone + ".")
	if !ok || len(results) == 0 {
		t.Fatalf("expected MX record for %s, got none", zone+".")
	}

	mx, ok := results[0].(*dns.MX)
	if !ok {
		t.Fatalf("expected MX record type in response")
	}

	if mx.Mx != host {
		t.Errorf("expected host %s, got %s", host, mx.Mx)
	}

	if mx.Preference != priority {
		t.Errorf("expected priority %d, got %d", priority, mx.Preference)
	}

	err = rr.Delete(zone+".", value)
	if err != nil {
		t.Fatalf("failed to delete MX record: %v", err)
	}

	results, _ = rr.Lookup(zone + ".")
	if len(results) != 0 {
		t.Errorf("expected no MX record after delete")
	}
}
