package errors

import "testing"

func TestNotImplemented(t *testing.T) {
	err := NotImplemented("feature")
	if err == nil || err.Error() != "not implemented: feature" {
		t.Fatalf("NotImplemented = %v", err)
	}
}
