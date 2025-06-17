package rtypes

import (
	"github.com/miekg/dns"
	"go53/config"
	"go53/storage"
	"os"
	"testing"

	"go53/memory"
)

type DummyRR struct{}

func (DummyRR) Add(zone, name string, value interface{}, ttl *uint32) error { return nil }
func (DummyRR) Delete(host string, value interface{}) error                 { return nil }
func (DummyRR) Lookup(host string) ([]dns.RR, bool)                         { return nil, false }
func (DummyRR) Type() uint16                                                { return 9999 }

var store *memory.InMemoryZoneStore

func TestMain(m *testing.M) {
	config.LoadConfig()

	if err := storage.Init(config.AppConfig.StorageBackend); err != nil {
		panic("Storage init failed: " + err.Error())
	}

	var err error
	store, err = memory.NewZoneStore(storage.Backend)

	if err != nil {
		panic("Failed to init memory zone store: " + err.Error())
	}

	InitMemoryStore(store)

	os.Exit(m.Run())
}

func TestInitMemoryStoreAndGet(t *testing.T) {
	got := GetMemStore()
	if got != store {
		t.Errorf("expected store pointer to match, got different reference")
	}
}

func TestRegisterAndGet(t *testing.T) {
	dummy := DummyRR{}
	Register(dummy)

	v, ok := Get(9999)
	if !ok {
		t.Fatalf("expected to find DummyRR type after Register")
	}

	if v.Type() != 9999 {
		t.Errorf("expected Type to be 9999, got %d", v.Type())
	}
}

func TestGetRegistry(t *testing.T) {
	reg := GetRegistry()
	if reg == nil || len(reg) == 0 {
		t.Fatalf("expected registry to contain entries")
	}

	if _, ok := reg[9999]; !ok {
		t.Errorf("expected DummyRR type to be in registry")
	}
}
