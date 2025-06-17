package config

import (
	"fmt"
	"log"
	"os"
	"reflect"
	"sync"

	"go53/storage"

	"github.com/joho/godotenv"
)

type BaseConfig struct {
	BindHost       string
	DNSPort        string
	APIPort        string
	StorageBackend string
	PostgresDSN    string
}

type LiveConfig struct {
	LogLevel       string `json:"log_level"`       // debug/info/warn
	Mode           string `json:"mode"`            // primary/secondary/replication
	AllowTransfer  string `json:"allow_transfer"`  // comma-separated IPs
	AllowRecursion string `json:"allow_recursion"` // "true"/"false"
	DNSSECEnabled  string `json:"dnssec_enabled"`  // "true"/"false"
	DefaultTTL     string `json:"default_ttl"`     // seconds
	Version        string `json:"version"`         // CHAOS version.bind
	MaxUDPSize     string `json:"max_udp_size"`    // e.g. 1232
	EnableEDNS     string `json:"enable_edns"`     // "true"/"false"
	RateLimitQPS   string `json:"rate_limit_qps"`  // queries per second
	AllowAXFR      string `json:"allow_axfr"`      // "true"/"false"
	DefaultNS      string `json:"default_ns"`      // e.g. ns1.example.com
}

type ConfigManager struct {
	Base BaseConfig
	mu   sync.RWMutex
	live LiveConfig
}

var AppConfig = &ConfigManager{}

func (cm *ConfigManager) Init() {
	_ = godotenv.Load()

	cm.Base = BaseConfig{
		DNSPort:        MustEnv("DNS_PORT", DefaultBaseConfig.DNSPort),
		BindHost:       MustEnv("BIND_HOST", DefaultBaseConfig.BindHost),
		APIPort:        MustEnv("API_PORT", DefaultBaseConfig.APIPort),
		StorageBackend: MustEnv("STORAGE_BACKEND", DefaultBaseConfig.StorageBackend),
		PostgresDSN:    MustEnv("POSTGRES_DSN", DefaultBaseConfig.PostgresDSN),
	}

	if err := storage.Init(cm.Base.StorageBackend); err != nil {
		log.Fatalf("Failed to init storage: %v", err)
	}

	if err := cm.loadLiveConfig(); err != nil {
		log.Println("No live config found, using empty defaults")
	}
}

func (cm *ConfigManager) InitLiveConfig() {
	liveData, err := storage.Backend.LoadTable("config")
	if err != nil {
		log.Println("No live config found in storage, initializing with defaults")
		cm.MergeUpdateLive(DefaultLiveConfig)
		return
	}

	cfg := LiveConfig{}
	val := reflect.ValueOf(&cfg).Elem()
	typ := val.Type()

	log.Println("Reading live config from storage:")
	for i := 0; i < val.NumField(); i++ {
		field := typ.Field(i)
		key := field.Tag.Get("json")
		if v, ok := liveData[key]; ok {
			val.Field(i).SetString(string(v))
			log.Printf("  - Loaded %s = %s", key, string(v))
		} else {
			log.Printf("  - Missing %s in storage", key)
		}
	}

	defVal := reflect.ValueOf(DefaultLiveConfig)
	changed := false
	for i := 0; i < val.NumField(); i++ {
		fieldName := typ.Field(i).Name
		fieldValue := val.Field(i).String()

		if fieldValue == "" {
			defaultValue := defVal.Field(i).String()
			val.Field(i).SetString(defaultValue)
			log.Printf("  - %s was empty, set to default: %s", fieldName, defaultValue)
			changed = true
		}
	}

	cm.mu.Lock()
	cm.live = cfg
	cm.mu.Unlock()

	if changed {
		_ = cm.PersistLiveConfig()
		log.Println("Live config merged with defaults and persisted")
	} else {
		log.Println("Live config fully loaded from storage, no defaults applied")
	}
}

func (cm *ConfigManager) loadLiveConfig() error {
	data, err := storage.Backend.LoadTable("config")
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("no live config found")
	}

	live := LiveConfig{}
	t := reflect.TypeOf(live)
	v := reflect.ValueOf(&live).Elem()

	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		if val, ok := data[tag]; ok {
			v.Field(i).SetString(string(val))
		}
	}

	cm.mu.Lock()
	cm.live = live
	cm.mu.Unlock()
	return nil
}

func (cm *ConfigManager) PersistLiveConfig() error {
	cm.mu.RLock()
	live := cm.live
	cm.mu.RUnlock()

	v := reflect.ValueOf(live)
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		key := t.Field(i).Tag.Get("json")
		value := v.Field(i).String()
		if err := storage.Backend.SaveTable("config", key, []byte(value)); err != nil {
			return err
		}
	}
	return nil
}

func (cm *ConfigManager) GetBase() BaseConfig {
	return cm.Base
}

func (cm *ConfigManager) GetLive() LiveConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.live
}

func (cm *ConfigManager) UpdateLive(newConfig LiveConfig) {
	cm.mu.Lock()
	cm.live = newConfig
	cm.mu.Unlock()
	_ = cm.PersistLiveConfig()
}

func (cm *ConfigManager) MergeUpdateLive(partial LiveConfig) {
	cm.mu.Lock()
	v := reflect.ValueOf(&cm.live).Elem()
	p := reflect.ValueOf(partial)

	for i := 0; i < v.NumField(); i++ {
		val := p.Field(i).String()
		if val != "" {
			v.Field(i).SetString(val)
		}
	}
	cm.mu.Unlock()

	_ = cm.PersistLiveConfig()
	log.Println("Live config partially updated and persisted")
}

func MustEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
