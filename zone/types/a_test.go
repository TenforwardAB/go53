package types

import (
	"testing"
)

func TestARecordLifecycle(t *testing.T) {
	name := "go53.test."
	ip := "192.0.2.1"

	AddA(name, ip)

	rec := LookupA(name)
	if rec == nil {
		t.Fatalf("expected A record for %s, got nil", name)
	}
	if rec.A.String() != ip {
		t.Errorf("expected IP %s, got %s", ip, rec.A.String())
	}

	DeleteA(name)
	if LookupA(name) != nil {
		t.Errorf("expected record to be deleted")
	}
}
