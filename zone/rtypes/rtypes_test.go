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

type MockStorage struct {
	data map[string]map[string][]byte
}

func (m *MockStorage) ensure() {
	if m.data == nil {
		m.data = make(map[string]map[string][]byte)
	}
}

func (m *MockStorage) Init() error {
	m.ensure()
	return nil
}

func (m *MockStorage) SaveZone(name string, data []byte) error {
	return nil
}

func (m *MockStorage) LoadZone(name string) ([]byte, error) {
	return nil, nil
}

func (m *MockStorage) DeleteZone(name string) error {
	return nil
}

func (m *MockStorage) ListZones() ([]string, error) {
	return nil, nil
}

func (m *MockStorage) LoadAllZones() (map[string][]byte, error) {
	return nil, nil
}

func (m *MockStorage) LoadTable(table string) (map[string][]byte, error) {
	m.ensure()
	if tbl, ok := m.data[table]; ok {
		return tbl, nil
	}
	return map[string][]byte{}, nil
}

func (m *MockStorage) SaveTable(table, key string, value []byte) error {
	m.ensure()
	if _, ok := m.data[table]; !ok {
		m.data[table] = make(map[string][]byte)
	}
	m.data[table][key] = value
	return nil
}

func TestMain(m *testing.M) {
	config.AppConfig = &config.ConfigManager{}
	config.AppConfig.Base = config.BaseConfig{
		StorageBackend: "mock",
	}

	storage.Backend = &MockStorage{
		data: make(map[string]map[string][]byte),
	}
	config.AppConfig.InitLiveConfig()

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

//func TestInitSkipsIfBaseAlreadySet(t *testing.T) {
//	config.AppConfig = &config.ConfigManager{
//		Base: config.BaseConfig{
//			DNSPort: ":9999",
//		},
//	}
//	storage.Backend = &MockStorage{}
//
//	config.AppConfig.Init()
//
//	if config.AppConfig.Base.DNSPort != ":9999" {
//		t.Errorf("Expected DNSPort ':9999', got '%s'", config.AppConfig.Base.DNSPort)
//	}
//}
//
//func TestGetLive_WhenNil(t *testing.T) {
//	config.AppConfig = &config.ConfigManager{}
//	storage.Backend = &MockStorage{}
//
//	live := config.AppConfig.GetLive()
//	expected := config.DefaultLiveConfig
//
//	if live != expected {
//		t.Errorf("Expected default live config %+v, got %+v", expected, live)
//	}
//}
