package types

import (
	"testing"
)

func TestDNAMERecordLifecycle(t *testing.T) {
	name := "dname.go53.test."
	AddDNAME(name, "target.example.com.")

	rec := LookupDNAME(name)
	if rec == nil {
		t.Fatalf("expected DNAME record for %s, got nil", name)
	}

	DeleteDNAME(name)
	if LookupDNAME(name) != nil {
		t.Errorf("expected record to be deleted")
	}
}
