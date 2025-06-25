package dnsutils

import (
	"go53/zone/rtypes"
	"testing"
)

func TestUpdateSOASerial_NoMemStore(t *testing.T) {
	rtypes.GetMemStore() // simulate uninitialized store

	err := UpdateSOASerial("example.com.")
	if err == nil || err.Error() != "memstore is not initialized" {
		t.Errorf("expected memstore error, got %v", err)
	}
}
