package types

import (
	"testing"
)

func TestTXTRecordLifecycle(t *testing.T) {
	name := "txt.go53.test."
	AddTXT(name, "Some text")

	recs := LookupTXT(name)
	if len(recs) != 1 {
		t.Fatalf("expected 1 TXT record, got %d", len(recs))
	}

	DeleteTXT(name)
	if len(LookupTXT(name)) != 0 {
		t.Errorf("expected record to be deleted")
	}
}
