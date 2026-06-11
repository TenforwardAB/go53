package config_test

import (
	"errors"
	"os"
	"testing"

	"go53/config"
	"go53/storage"
)

func TestDistributedAuthSyncEnabledDefault(t *testing.T) {
	if !(config.DistributedConfig{}).AuthSyncEnabled() {
		t.Fatal("auth sync should default to enabled when unset")
	}
	on := true
	if !(config.DistributedConfig{AuthSync: &on}).AuthSyncEnabled() {
		t.Fatal("auth sync should be enabled when set true")
	}
	off := false
	if (config.DistributedConfig{AuthSync: &off}).AuthSyncEnabled() {
		t.Fatal("auth sync should be disabled when set false")
	}
}

// mockStorage implements storage.Storage
type mockStorage struct {
	Zones  map[string][]byte
	Tables map[string]map[string][]byte
}

func (m *mockStorage) Init() error {
	if m.Zones == nil {
		m.Zones = make(map[string][]byte)
	}
	if m.Tables == nil {
		m.Tables = make(map[string]map[string][]byte)
	}
	return nil
}

func (m *mockStorage) SaveZone(name string, data []byte) error {
	m.Zones[name] = data
	return nil
}

func (m *mockStorage) LoadZone(name string) ([]byte, error) {
	if data, ok := m.Zones[name]; ok {
		return data, nil
	}
	return nil, nil
}

func (m *mockStorage) DeleteZone(name string) error {
	delete(m.Zones, name)
	return nil
}

func (m *mockStorage) ListZones() ([]string, error) {
	var keys []string
	for k := range m.Zones {
		keys = append(keys, k)
	}
	return keys, nil
}

func (m *mockStorage) LoadAllZones() (map[string][]byte, error) {
	return m.Zones, nil
}

func (m *mockStorage) LoadTable(table string) (map[string][]byte, error) {
	if data, ok := m.Tables[table]; ok {
		return data, nil
	}
	return map[string][]byte{}, nil
}

func (m *mockStorage) SaveTable(table, key string, value []byte) error {
	if _, ok := m.Tables[table]; !ok {
		m.Tables[table] = make(map[string][]byte)
	}
	m.Tables[table][key] = value
	return nil
}

func (m *mockStorage) DeleteFromTable(table, key string) error {
	if _, ok := m.Tables[table]; ok {
		delete(m.Tables[table], key)
	}
	return nil
}

// TESTS BELOW

func setupMockStorage() {
	mock := &mockStorage{}
	mock.Init()
	storage.Backend = mock
	mock.Tables["config"] = map[string][]byte{
		"log_level": []byte("debug"),
		"mode":      []byte("secondary"),
	}
}

func TestMustEnv(t *testing.T) {
	val := config.MustEnv("TEST_ENV", "default")
	if val != "default" {
		t.Errorf("Expected fallback 'default', got '%s'", val)
	}
	os.Setenv("TEST_ENV", "value123")
	defer os.Unsetenv("TEST_ENV")

	val = config.MustEnv("TEST_ENV", "default")
	if val != "value123" {
		t.Errorf("Expected 'value123', got '%s'", val)
	}
}

func TestInitBaseConfig(t *testing.T) {
	setupMockStorage()
	os.Setenv("DNS_PORT", ":5353")
	os.Setenv("BIND_HOST", "127.0.0.1")
	os.Setenv("API_PORT", ":9000")
	os.Setenv("STORAGE_BACKEND", "mock")
	os.Setenv("POSTGRES_DSN", "some_dsn")

	cfg := &config.ConfigManager{}
	cfg.Base = config.BaseConfig{
		DNSPort:        config.MustEnv("DNS_PORT", config.DefaultBaseConfig.DNSPort),
		BindHost:       config.MustEnv("BIND_HOST", config.DefaultBaseConfig.BindHost),
		APIPort:        config.MustEnv("API_PORT", config.DefaultBaseConfig.APIPort),
		StorageBackend: config.MustEnv("STORAGE_BACKEND", config.DefaultBaseConfig.StorageBackend),
		PostgresDSN:    config.MustEnv("POSTGRES_DSN", config.DefaultBaseConfig.PostgresDSN),
	}

	if cfg.Base.DNSPort != ":5353" {
		t.Errorf("Expected ':5353', got '%s'", cfg.Base.DNSPort)
	}
	if cfg.Base.BindHost != "127.0.0.1" {
		t.Errorf("Expected '127.0.0.1', got '%s'", cfg.Base.BindHost)
	}
}

func TestMergeUpdateLive(t *testing.T) {
	setupMockStorage()
	config.AppConfig = &config.ConfigManager{}
	config.AppConfig.MergeUpdateLive(config.LiveConfig{
		LogLevel: "debug",
		Mode:     "primary",
	})

	live := config.AppConfig.GetLive()
	if live.LogLevel != "debug" {
		t.Errorf("Expected 'debug', got '%s'", live.LogLevel)
	}
	if live.Mode != "primary" {
		t.Errorf("Expected 'primary', got '%s'", live.Mode)
	}
}

func TestGetBaseAndLive(t *testing.T) {
	cm := &config.ConfigManager{
		Base: config.BaseConfig{
			DNSPort: ":1234",
		},
	}
	live := config.LiveConfig{Mode: "secondary"}
	cm.MergeUpdateLive(live)

	if cm.GetBase().DNSPort != ":1234" {
		t.Errorf("Expected ':1234', got '%s'", cm.GetBase().DNSPort)
	}
	if cm.GetLive().Mode != "secondary" {
		t.Errorf("Expected 'secondary', got '%s'", cm.GetLive().Mode)
	}
}

func TestUpdateLive(t *testing.T) {
	mock := &mockStorage{
		Zones:  make(map[string][]byte),
		Tables: make(map[string]map[string][]byte),
	}
	storage.Backend = mock

	cm := &config.ConfigManager{}
	live := config.LiveConfig{LogLevel: "info", Mode: "primary"}
	cm.UpdateLive(live)

	got := cm.GetLive()
	if got.LogLevel != "info" || got.Mode != "primary" {
		t.Errorf("Expected updated live config, got %+v", got)
	}

	if _, ok := mock.Tables["config"]["log_level"]; !ok {
		t.Errorf("Expected 'log_level' to be persisted in mock storage")
	}
}

func TestPersistLiveConfig(t *testing.T) {
	mock := &mockStorage{
		Zones:  make(map[string][]byte),
		Tables: make(map[string]map[string][]byte),
	}
	storage.Backend = mock

	cm := &config.ConfigManager{}
	cm.MergeUpdateLive(config.LiveConfig{LogLevel: "warn", Mode: "secondary"})

	err := cm.PersistLiveConfig()
	if err != nil {
		t.Fatalf("PersistLiveConfig failed: %v", err)
	}

	if mock.Tables["config"]["log_level"] == nil || string(mock.Tables["config"]["log_level"]) != `"warn"` {
		t.Errorf("Expected log_level 'warn', got '%s'", mock.Tables["config"]["log_level"])
	}
}

type loadErrorMockStorage struct {
	mockStorage
}

func newLoadErrorMockStorage() *loadErrorMockStorage {
	return &loadErrorMockStorage{
		mockStorage{
			Zones:  make(map[string][]byte),
			Tables: make(map[string]map[string][]byte),
		},
	}
}

func (m *loadErrorMockStorage) LoadTable(table string) (map[string][]byte, error) {
	return nil, errors.New("forced LoadTable error")
}

func TestInitLiveConfig_LoadErrorFallback(t *testing.T) {
	storage.Backend = newLoadErrorMockStorage()

	config.AppConfig = &config.ConfigManager{}
	config.AppConfig.Base = config.DefaultBaseConfig

	config.AppConfig.InitLiveConfig()

	live := config.AppConfig.GetLive()
	if live.LogLevel != config.DefaultLiveConfig.LogLevel {
		t.Errorf("Expected fallback log level '%s', got '%s'", config.DefaultLiveConfig.LogLevel, live.LogLevel)
	}
}

type saveErrorMockStorage struct {
	mockStorage
}

func (m *saveErrorMockStorage) SaveTable(table, key string, value []byte) error {
	return errors.New("forced SaveTable error")
}

func TestPersistLiveConfig_SaveTableFails(t *testing.T) {
	storage.Backend = &saveErrorMockStorage{}
	cm := &config.ConfigManager{}
	cm.MergeUpdateLive(config.LiveConfig{LogLevel: "warn", Mode: "secondary"})

	err := cm.PersistLiveConfig()
	if err == nil || err.Error() != "config: SaveTable log_level: forced SaveTable error" {
		t.Errorf("config: SaveTable log_level: forced SaveTable error', got %v", err)
	}
}

func TestInitUsesDefaults(t *testing.T) {
	os.Clearenv()
	t.Setenv("BADGER_DIR", t.TempDir())
	cfg := &config.ConfigManager{}
	cfg.Init()

	base := cfg.GetBase()

	if base.DNSPort != config.DefaultBaseConfig.DNSPort {
		t.Errorf("Expected default DNS port '%s', got '%s'", config.DefaultBaseConfig.DNSPort, base.DNSPort)
	}
}

func TestMergeUpdateLiveJSONAppliesFalseAndEmpty(t *testing.T) {
	setupMockStorage()
	cm := &config.ConfigManager{}
	cm.UpdateLive(config.LiveConfig{
		Mode:       "distributed",
		EnableEDNS: true,
		NSID:       "node-a",
		DefaultTTL: 60,
	})

	// A struct-merge would drop the false bool and empty string; the JSON overlay must keep them.
	if err := cm.MergeUpdateLiveJSON([]byte(`{"enable_edns":false,"nsid":""}`)); err != nil {
		t.Fatalf("MergeUpdateLiveJSON: %v", err)
	}

	live := cm.GetLive()
	if live.EnableEDNS {
		t.Errorf("expected enable_edns=false, got true")
	}
	if live.NSID != "" {
		t.Errorf("expected nsid cleared, got %q", live.NSID)
	}
	// Fields absent from the patch must be left unchanged.
	if live.Mode != "distributed" {
		t.Errorf("expected mode unchanged 'distributed', got %q", live.Mode)
	}
	if live.DefaultTTL != 60 {
		t.Errorf("expected default_ttl unchanged 60, got %d", live.DefaultTTL)
	}
}

func TestMergeUpdateLiveJSONReplacesPeerPublicKeys(t *testing.T) {
	setupMockStorage()
	cm := &config.ConfigManager{}
	cm.UpdateLive(config.LiveConfig{
		Mode: "distributed",
		Distributed: config.DistributedConfig{
			Peers:          "tls://old:53530",
			PeerPublicKeys: map[string]string{"old-node": "old-key"},
		},
	})

	if err := cm.MergeUpdateLiveJSON([]byte(`{"distributed":{"peers":"","peer_public_keys":{}}}`)); err != nil {
		t.Fatalf("MergeUpdateLiveJSON clear: %v", err)
	}
	live := cm.GetLive()
	if live.Distributed.Peers != "" {
		t.Fatalf("expected peers cleared, got %q", live.Distributed.Peers)
	}
	if len(live.Distributed.PeerPublicKeys) != 0 {
		t.Fatalf("expected peer_public_keys cleared, got %#v", live.Distributed.PeerPublicKeys)
	}

	if err := cm.MergeUpdateLiveJSON([]byte(`{"distributed":{"peer_public_keys":{"new-node":"new-key"}}}`)); err != nil {
		t.Fatalf("MergeUpdateLiveJSON replace: %v", err)
	}
	live = cm.GetLive()
	if len(live.Distributed.PeerPublicKeys) != 1 || live.Distributed.PeerPublicKeys["new-node"] != "new-key" {
		t.Fatalf("expected peer_public_keys replaced, got %#v", live.Distributed.PeerPublicKeys)
	}
}

func TestMergeUpdateLiveJSONInvalidBody(t *testing.T) {
	setupMockStorage()
	cm := &config.ConfigManager{}
	if err := cm.MergeUpdateLiveJSON([]byte(`{not json`)); err == nil {
		t.Fatalf("expected error for invalid JSON body")
	}
}
