package dnsutils

import (
	"testing"
)

func TestImportRecords_UnsupportedType(t *testing.T) {
	err := ImportRecords("A", "example.com.", 12345)
	if err == nil || err.Error() != "unsupported data type for import" {
		t.Errorf("expected unsupported data type error, got %v", err)
	}
}

func TestImportRecords_InvalidMultiType(t *testing.T) {
	data := map[string]interface{}{"invalid": "data"}
	err := ImportRecords("A", "example.com.", data)
	if err == nil || err.Error() != "expected 'multi' rrtype for JSON map input" {
		t.Errorf("expected 'multi' rrtype error, got %v", err)
	}
}
