package security

import (
	"sync/atomic"
	"testing"
	"time"

	"go53/storage"
)

type countingStorage struct {
	*storage.MockStorage
	loadTableCount atomic.Int64
}

func newCountingStorage() *countingStorage {
	return &countingStorage{
		MockStorage: &storage.MockStorage{
			Zones:  map[string][]byte{},
			Tables: map[string]map[string][]byte{},
		},
	}
}

func (s *countingStorage) LoadTable(table string) (map[string][]byte, error) {
	s.loadTableCount.Add(1)
	return s.MockStorage.LoadTable(table)
}

func TestDNSSECKeyReadsUseMemoryCache(t *testing.T) {
	st := newCountingStorage()
	storage.Backend = st
	if err := InitDNSSECKeyCache(); err != nil {
		t.Fatalf("InitDNSSECKeyCache: %v", err)
	}

	now := time.Now().Unix()
	keyID, _, err := GenerateRolloverKey("cache.test", "zsk", "ED25519", now-10, now-10)
	if err != nil {
		t.Fatalf("GenerateRolloverKey: %v", err)
	}
	st.loadTableCount.Store(0)

	if _, err := LoadPublishedKeysForZone("cache.test", now); err != nil {
		t.Fatalf("LoadPublishedKeysForZone: %v", err)
	}
	if _, err := ActiveSigningKeyIDs("cache.test", false, now); err != nil {
		t.Fatalf("ActiveSigningKeyIDs: %v", err)
	}
	if _, _, err := LoadPrivateKeyFromStorage(keyID); err != nil {
		t.Fatalf("LoadPrivateKeyFromStorage: %v", err)
	}
	if got := st.loadTableCount.Load(); got != 0 {
		t.Fatalf("DNSSEC key read path loaded storage %d times, want 0", got)
	}
}
