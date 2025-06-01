package types

import (
	"testing"
)

func TestAAAARecordLifecycle(t *testing.T) {
	name := "aaaa.go53.test."
	AddAAAA(name, "2001:db8::1")

	rec := LookupAAAA(name)
	if rec == nil {
		t.Fatalf("expected AAAA record for %s, got nil", name)
	}

	DeleteAAAA(name)
	if LookupAAAA(name) != nil {
		t.Errorf("expected record to be deleted")
	}
}
