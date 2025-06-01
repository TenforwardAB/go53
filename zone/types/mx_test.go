package types

import (
	"testing"
)

func TestMXRecordLifecycle(t *testing.T) {
	name := "mx.go53.test."
	AddMX(name, 10, "mx.go53.test.")

	recs := LookupMX(name)
	if len(recs) != 1 {
		t.Fatalf("expected 1 MX record, got %d", len(recs))
	}

	DeleteMX(name)
	if len(LookupMX(name)) != 0 {
		t.Errorf("expected record to be deleted")
	}
}
