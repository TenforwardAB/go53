package security

import (
	"testing"

	"go53/storage"
	"go53/wal"
)

// TestDNSSECKeyMutationsWriteWAL verifies that DNSSEC key create/delete
// operations emit dnssec_key WAL events so point-in-time restore can replay
// them (regression guard for the backup/restore WAL coverage).
func TestDNSSECKeyMutationsWriteWAL(t *testing.T) {
	storage.Backend = &storage.MockStorage{Zones: map[string][]byte{}, Tables: map[string]map[string][]byte{}}
	if err := storage.Backend.Init(); err != nil {
		t.Fatalf("init storage: %v", err)
	}

	keyID, _, err := GenerateRolloverKey("example.com.", "ZSK", "ED25519", 0, 0)
	if err != nil {
		t.Fatalf("GenerateRolloverKey: %v", err)
	}

	events, err := wal.EventsAfter(0)
	if err != nil {
		t.Fatalf("EventsAfter: %v", err)
	}
	if !hasDNSSECEvent(events, wal.OpUpsert, keyID) {
		t.Fatalf("expected dnssec_key upsert WAL event for %s; got %d events", keyID, len(events))
	}

	if err := DeleteStoredKey(keyID); err != nil {
		t.Fatalf("DeleteStoredKey: %v", err)
	}
	events, err = wal.EventsAfter(0)
	if err != nil {
		t.Fatalf("EventsAfter: %v", err)
	}
	if !hasDNSSECEvent(events, wal.OpDelete, keyID) {
		t.Fatalf("expected dnssec_key delete WAL event for %s", keyID)
	}
}

func hasDNSSECEvent(events []wal.Event, op, keyID string) bool {
	for _, e := range events {
		if e.Kind == wal.KindDNSSECKey && e.Op == op && e.Key == keyID {
			return true
		}
	}
	return false
}
