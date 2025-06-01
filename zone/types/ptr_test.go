package types

import (
	"testing"
)

func TestPTRRecordLifecycle(t *testing.T) {
	name := "1.2.0.192.in-addr.arpa."
	AddPTR(name, "ptr.go53.test.")

	rec := LookupPTR(name)
	if rec == nil {
		t.Fatalf("expected PTR record for %s, got nil", name)
	}

	DeletePTR(name)
	if LookupPTR(name) != nil {
		t.Errorf("expected record to be deleted")
	}
}
