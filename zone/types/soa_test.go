package types

import (
	"testing"
)

func TestSOARecordLifecycle(t *testing.T) {
	name := "soa.go53.test."
	AddSOA(name, "ns1.go53.test.", "hostmaster.go53.test.", 1, 7200, 3600, 1209600, 3600)

	rec := LookupSOA(name)
	if rec == nil {
		t.Fatalf("expected SOA record for %s, got nil", name)
	}

	DeleteSOA(name)
	if LookupSOA(name) != nil {
		t.Errorf("expected record to be deleted")
	}
}
