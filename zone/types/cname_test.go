package types

import (
	"testing"
)

func TestCNAMERecordLifecycle(t *testing.T) {
	name := "alias.go53.test."
	AddCNAME(name, "target.example.com.")

	rec := LookupCNAME(name)
	if rec == nil {
		t.Fatalf("expected CNAME record, got nil")
	}

	DeleteCNAME(name)
	if LookupCNAME(name) != nil {
		t.Errorf("expected record to be deleted")
	}
}
