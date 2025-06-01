package types

import (
	"testing"
)

func TestNSRecordLifecycle(t *testing.T) {
	name := "go53.test."
	AddNS(name, "ns1.go53.test.")

	recs := LookupNS(name)
	if len(recs) != 1 {
		t.Fatalf("expected 1 NS record, got %d", len(recs))
	}

	DeleteNS(name)
	if len(LookupNS(name)) != 0 {
		t.Errorf("expected record to be deleted")
	}
}
