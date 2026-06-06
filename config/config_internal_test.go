package config

import (
	"encoding/json"
	"testing"

	"go53/storage"
)

func TestLoadLiveConfigParsesStoredValuesAndRepairsBadNestedJSON(t *testing.T) {
	backend := &storage.MockStorage{}
	if err := backend.Init(); err != nil {
		t.Fatalf("storage init: %v", err)
	}
	storage.Backend = backend
	backend.Tables["config"] = map[string][]byte{
		"log_level":       []byte(`"debug"`),
		"mode":            []byte(`"distributed"`),
		"default_ttl":     []byte(`600`),
		"dnssec_enabled":  []byte(`true`),
		"allow_recursion": []byte(`true`),
		"primary":         []byte(`{`),
		"secondary":       mustJSON(t, SecondaryConfig{FetchDebounceMs: 50, MinFetchIntervalSec: 2, MaxParallelFetches: 4}),
		"dnssec":          mustJSON(t, DNSSECSignaturePolicy{ValiditySeconds: 7200}),
		"distributed":     mustJSON(t, DistributedConfig{NodeID: "node-a", Transport: "tls"}),
	}

	cm := &ConfigManager{}
	if err := cm.loadLiveConfig(); err != nil {
		t.Fatalf("loadLiveConfig: %v", err)
	}
	live := cm.GetLive()
	if live.LogLevel != "debug" || live.Mode != "distributed" || live.DefaultTTL != 600 || !live.DNSSECEnabled || !live.AllowRecursion {
		t.Fatalf("loaded live config = %#v", live)
	}
	if live.Primary != DefaultLiveConfig.Primary {
		t.Fatalf("invalid nested primary was not reset to default: %#v", live.Primary)
	}
	if live.Secondary.MaxParallelFetches != 4 || live.DNSSEC.ValiditySeconds != 7200 || live.Distributed.NodeID != "node-a" {
		t.Fatalf("nested config not loaded: %#v", live)
	}
	if _, ok := backend.Tables["config"]["primary"]; !ok {
		t.Fatalf("repaired config was not persisted")
	}
}

func TestLoadLiveConfigErrorsAndInitLiveConfigDefaults(t *testing.T) {
	backend := &storage.MockStorage{}
	if err := backend.Init(); err != nil {
		t.Fatalf("storage init: %v", err)
	}
	storage.Backend = backend

	cm := &ConfigManager{}
	if err := cm.loadLiveConfig(); err == nil {
		t.Fatalf("loadLiveConfig succeeded with empty config table")
	}

	cm.InitLiveConfig()
	live := cm.GetLive()
	if live.LogLevel != DefaultLiveConfig.LogLevel || live.Mode != DefaultLiveConfig.Mode {
		t.Fatalf("InitLiveConfig defaults = %#v", live)
	}
	if len(backend.Tables["config"]) == 0 {
		t.Fatalf("InitLiveConfig did not persist defaults")
	}

	backend.Tables["config"]["log_level"] = []byte(`123`)
	backend.Tables["config"]["default_ttl"] = []byte(`"bad"`)
	backend.Tables["config"]["dnssec_enabled"] = []byte(`"bad"`)
	cm.InitLiveConfig()
	if cm.GetLive().LogLevel == "123" {
		t.Fatalf("InitLiveConfig accepted invalid log_level JSON")
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	return data
}
