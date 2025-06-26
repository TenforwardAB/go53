package config

import (
	"encoding/json"
	"fmt"
	"go53/internal"
	"log"
	"os"
	"reflect"
	"strconv"
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

type DevConfig struct {
	DualMode bool `json:"dual_mode"` // true/false if you want to use server as both Primary/Replictor and Secondary
}
type PrimaryConfig struct {
	NotifyDebounceMs int    `json:"notify_debounce_ms"` // delay before sending NOTIFY
	Ip               string `json:"ip"`                 //ip of primary DNS
	Port             int    `json:"port"`               //port of primary DNS
}

type SecondaryConfig struct {
	FetchDebounceMs     int `json:"fetch_debounce_ms"`      // delay before starting AXFR/IXFR
	MinFetchIntervalSec int `json:"min_fetch_interval_sec"` // rate limit per zone
	MaxParallelFetches  int `json:"max_parallel_fetches"`   // limit concurrent zone fetches
}
type LiveConfig struct {
	LogLevel       string `json:"log_level"`       // debug/info/warn
	Mode           string `json:"mode"`            // primary/secondary/replication
	AllowTransfer  string `json:"allow_transfer"`  // comma-separated IPs
	AllowRecursion bool   `json:"allow_recursion"` // "true"/"false"
	DNSSECEnabled  bool   `json:"dnssec_enabled"`  // "true"/"false"
	DefaultTTL     int    `json:"default_ttl"`     // seconds
	Version        string `json:"version"`         // CHAOS version.bind
	MaxUDPSize     int    `json:"max_udp_size"`    // e.g. 1232
	EnableEDNS     bool   `json:"enable_edns"`     // "true"/"false"
	RateLimitQPS   int    `json:"rate_limit_qps"`  // queries per second
	AllowAXFR      bool   `json:"allow_axfr"`      // "true"/"false"
	DefaultNS      string `json:"default_ns"`      // e.g. ns1.example.com

	Primary   PrimaryConfig   `json:"primary"`
	Secondary SecondaryConfig `json:"secondary"`
	Dev       DevConfig       `json:"dev"`
}

type ConfigManager struct {
	Base BaseConfig
	mu   sync.RWMutex
	Live LiveConfig
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
		log.Fatalf("[config] Failed to init storage: %v", err)
	}

	if err := cm.loadLiveConfig(); err != nil {
		log.Println("No live config found, using empty defaults")
	}
}

func (cm *ConfigManager) InitLiveConfig() {
	raw, err := storage.Backend.LoadTable("config")
	if err != nil || len(raw) == 0 {
		log.Println("No live config found, seeding with defaults")
		cm.MergeUpdateLive(DefaultLiveConfig) // sets & persists
		return
	}

	cfg := DefaultLiveConfig
	changed := false
	val := reflect.ValueOf(&cfg).Elem()
	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		meta := typ.Field(i)
		key := meta.Tag.Get("json")
		data, ok := raw[key]
		if !ok {
			log.Printf("  • %s missing → using default", key)
			changed = true
			continue
		}

		f := val.Field(i)
		if !f.CanSet() {
			continue
		}

		switch f.Kind() {
		case reflect.String:
			f.SetString(string(data))

		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			if x, err := strconv.ParseInt(string(data), 10, 64); err == nil {
				f.SetInt(x)
			} else {
				log.Printf("  • parse int %s: %v", key, err)
			}

		case reflect.Bool:
			if b, err := strconv.ParseBool(string(data)); err == nil {
				f.SetBool(b)
			} else {
				log.Printf("  • parse bool %s: %v", key, err)
			}

		case reflect.Struct:
			// unmarshal nested JSON into the struct field
			ptr := f.Addr().Interface()
			if err := json.Unmarshal(data, ptr); err != nil {
				log.Printf("  • unmarshal struct %s: %v", key, err)
			}

		default:
			// skip the rests
		}
	}

	cm.mu.Lock()
	cm.Live = cfg
	cm.mu.Unlock()

	if changed {
		if err := cm.persistLiveConfigUnlocked(cfg); err != nil {
			log.Println("Failed to persist merged defaults:", err)
		} else {
			log.Println("Merged defaults persisted")
		}
	} else {
		log.Println("Config loaded from storage; no defaults applied")
	}
}

func (cm *ConfigManager) loadLiveConfig() error {
	raw, err := storage.Backend.LoadTable("config")
	if err != nil {
		return fmt.Errorf("config: LoadTable failed: %w", err)
	}
	if len(raw) == 0 {
		return fmt.Errorf("config: no live config found")
	}

	var cfg LiveConfig
	val := reflect.ValueOf(&cfg).Elem()
	typ := val.Type()

	changed := false

	for i := 0; i < typ.NumField(); i++ {
		meta := typ.Field(i)
		key := meta.Tag.Get("json")

		data, ok := raw[key]
		if !ok {
			continue
		}

		field := val.Field(i)
		if !field.CanSet() {
			log.Printf("config: cannot set field %s", meta.Name)
			continue
		}

		switch field.Kind() {
		case reflect.String:
			field.SetString(string(data))

		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			var (
				i64 int64
				err error
			)

			if err = json.Unmarshal(data, &i64); err != nil {
				i64, err = strconv.ParseInt(string(data), 10, 64)
			}
			if err == nil {
				field.SetInt(i64)
			} else {
				log.Printf("config: failed to parse int for %s: %v", key, err)
			}

		case reflect.Bool:
			var b bool
			if err := json.Unmarshal(data, &b); err == nil {
				field.SetBool(b)
			} else if parsed, err2 := strconv.ParseBool(string(data)); err2 == nil {
				field.SetBool(parsed)
			} else {
				log.Printf("config: failed to parse bool for %s: %v", key, err)
			}

		case reflect.Struct:
			ptr := field.Addr().Interface()
			if err := json.Unmarshal(data, ptr); err != nil {
				log.Printf("config: invalid JSON for %s: %v; using default", key, err)

				defField := reflect.ValueOf(DefaultLiveConfig).FieldByName(meta.Name)
				field.Set(defField)
				changed = true
			}

		default:
			// skip slices, maps, pointers, and wahtever.
		}
	}

	cm.mu.Lock()
	cm.Live = cfg
	cm.mu.Unlock()

	if changed {
		if err := cm.persistLiveConfigUnlocked(cfg); err != nil {
			log.Printf("config: failed to re-persist after cleaning defaults: %v", err)
		} else {
			log.Println("config: cleaned up invalid nested JSON and re-persisted defaults")
		}
	}

	return nil
}

func (cm *ConfigManager) persistLiveConfigUnlocked(live LiveConfig) error {
	v := reflect.ValueOf(live)
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		meta := t.Field(i)
		key := meta.Tag.Get("json")
		field := v.Field(i)

		var data []byte
		var err error

		switch field.Kind() {
		case reflect.String:
			data = []byte(field.String())

		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			data = []byte(fmt.Sprintf("%d", field.Int()))

		case reflect.Bool:
			data = []byte(fmt.Sprintf("%t", field.Bool()))

		case reflect.Struct:
			// marshal nested struct to JSON
			data, err = json.Marshal(field.Interface())
			if err != nil {
				return fmt.Errorf("config: failed to marshal %s: %w", key, err)
			}

		default:
			// skip slices, maps, pointers, etc.
			continue
		}

		if err := storage.Backend.SaveTable("config", key, data); err != nil {
			return fmt.Errorf("config: SaveTable %s: %w", key, err)
		}
	}

	return nil
}

// PersistLiveConfig is the public version: it locks, then calls the unlocked writer.
func (cm *ConfigManager) PersistLiveConfig() error {
	cm.mu.RLock()
	liveCopy := cm.Live
	cm.mu.RUnlock()

	return cm.persistLiveConfigUnlocked(liveCopy)
}

func (cm *ConfigManager) GetBase() BaseConfig {
	return cm.Base
}

func (cm *ConfigManager) GetLive() LiveConfig {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.Live
}

func (cm *ConfigManager) UpdateLive(newConfig LiveConfig) {
	cm.mu.Lock()
	cm.Live = newConfig
	_ = cm.persistLiveConfigUnlocked(cm.Live)
	cm.mu.Unlock()
}

func (cm *ConfigManager) MergeUpdateLive(partial LiveConfig) {
	cm.mu.Lock()
	internal.MergeStructs(&cm.Live, &partial)

	// take a snapshot to persist
	toPersist := cm.Live
	cm.mu.Unlock()

	if err := cm.persistLiveConfigUnlocked(toPersist); err != nil {
		log.Println("MergeUpdateLive: failed to persist:", err)
	}
}

func MustEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
