package config

import (
	"encoding/json"
	"fmt"
	"go53/internal"
	"log"
	"os"
	"reflect"
	"regexp"
	"sync"

	"go53/storage"

	"github.com/joho/godotenv"
)

var xAuthKeyRe = regexp.MustCompile(`^[A-Za-z0-9]{48,}$`)

type BaseConfig struct {
	BindHost       string
	DNSPort        string
	APIPort        string
	StorageBackend string
	PostgresDSN    string
	// AdminSocket is the path to the local admin Unix domain socket. It serves the
	// full admin API gated by filesystem permissions instead of API tokens, acting as
	// the break-glass local administration path when the external IdP is unreachable.
	// Empty disables the socket.
	AdminSocket string
	// AdminSocketGroup is the OS group granted access to the admin socket (mode 0660).
	// When the group does not exist the socket falls back to owner-only access.
	AdminSocketGroup string
}

type PrimaryConfig struct {
	NotifyDebounceMs int    `json:"notify_debounce_ms"` // delay before sending NOTIFY
	Ip               string `json:"ip"`                 //ip of primary DNS
	Port             int    `json:"port"`               //port of primary DNS
}

type SecondaryConfig struct {
	FetchDebounceMs     int      `json:"fetch_debounce_ms"`      // delay before starting AXFR/IXFR
	MinFetchIntervalSec int      `json:"min_fetch_interval_sec"` // rate limit per zone
	MaxParallelFetches  int      `json:"max_parallel_fetches"`   // limit concurrent zone fetches
	Zones               []string `json:"zones"`                  // bootstrap zone list for cold-start secondaries
	RefreshIntervalSec  int      `json:"refresh_interval_sec"`   // periodic sweep cadence; 0 disables periodic refresh
	RefreshJitterSec    int      `json:"refresh_jitter_sec"`     // max random per-zone delay each sweep
	CatalogEnabled      bool     `json:"catalog_enabled"`        // maintain/follow RFC 9432 catalog zone
	CatalogZone         string   `json:"catalog_zone"`           // bootstrap catalog zone name
}

type DNSSECSignaturePolicy struct {
	ValiditySeconds       int `json:"validity_seconds"`
	DNSKEYValiditySeconds int `json:"dnskey_validity_seconds"`
	RefreshBeforeSeconds  int `json:"refresh_before_seconds"`
	JitterSeconds         int `json:"jitter_seconds"`
	InceptionSkewSeconds  int `json:"inception_skew_seconds"`
}

type DistributedConfig struct {
	NodeID          string            `json:"node_id"`
	Peers           string            `json:"peers"`
	Transport       string            `json:"transport"` // http/tcp/tls/mtls
	SyncBindHost    string            `json:"sync_bind_host"`
	SyncPort        string            `json:"sync_port"`
	PrivateKey      string            `json:"private_key"`
	PeerPublicKeys  map[string]string `json:"peer_public_keys"`
	PushTimeoutMs   int               `json:"push_timeout_ms"`
	ResyncIntervalS int               `json:"resync_interval_s"`
}

type AuthConfig struct {
	Mode         string `json:"mode"`          // none/x-auth-key/oidc
	XAuthKey     string `json:"x_auth_key"`    // base62, minimum 48 characters when enabled
	OIDCIssuer   string `json:"oidc_issuer"`   // future OIDC issuer URL
	OIDCAudience string `json:"oidc_audience"` // future OIDC audience/client id
	OIDCJWKSURL  string `json:"oidc_jwks_url"` // future JWKS endpoint override
}

type LiveConfig struct {
	LogLevel          string `json:"log_level"`       // debug/info/warn
	Mode              string `json:"mode"`            // primary/secondary/distributed
	AllowTransfer     string `json:"allow_transfer"`  // comma-separated IPs
	AllowRecursion    bool   `json:"allow_recursion"` // "true"/"false"
	DNSSECEnabled     bool   `json:"dnssec_enabled"`  // "true"/"false"
	DefaultTTL        int    `json:"default_ttl"`     // seconds
	Version           string `json:"version"`         // CHAOS version.bind
	MaxUDPSize        int    `json:"max_udp_size"`    // e.g. 1232
	EnableEDNS        bool   `json:"enable_edns"`     // "true"/"false"
	NSID              string `json:"nsid"`            // EDNS0 NSID (RFC 5001); empty = disabled
	RateLimitQPS      int    `json:"rate_limit_qps"`  // queries per second
	AllowAXFR         bool   `json:"allow_axfr"`      // "true"/"false"
	DefaultNS         string `json:"default_ns"`      // e.g. ns1.example.com
	EnforceTSIG       bool   `json:"enforce_tsig"`
	AnyQueryPolicy    string `json:"any_query_policy"`    // hinfo/refuse
	UnknownZonePolicy string `json:"unknown_zone_policy"` // refused

	Primary     PrimaryConfig         `json:"primary"`
	Secondary   SecondaryConfig       `json:"secondary"`
	DNSSEC      DNSSECSignaturePolicy `json:"dnssec"`
	Distributed DistributedConfig     `json:"distributed"`
	Auth        AuthConfig            `json:"auth"`
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
		DNSPort:          MustEnv("DNS_PORT", DefaultBaseConfig.DNSPort),
		BindHost:         MustEnv("BIND_HOST", DefaultBaseConfig.BindHost),
		APIPort:          MustEnv("API_PORT", DefaultBaseConfig.APIPort),
		StorageBackend:   MustEnv("STORAGE_BACKEND", DefaultBaseConfig.StorageBackend),
		PostgresDSN:      MustEnv("POSTGRES_DSN", DefaultBaseConfig.PostgresDSN),
		AdminSocket:      MustEnv("ADMIN_SOCKET", DefaultBaseConfig.AdminSocket),
		AdminSocketGroup: MustEnv("ADMIN_SOCKET_GROUP", DefaultBaseConfig.AdminSocketGroup),
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
			var s string
			if err := json.Unmarshal(data, &s); err != nil {
				log.Printf("  • unmarshal string %s: %v", key, err)
				continue
			}
			f.SetString(s)

		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			var x int64
			if err := json.Unmarshal(data, &x); err != nil {
				log.Printf("  • unmarshal int %s: %v", key, err)
				continue
			}
			f.SetInt(x)

		case reflect.Bool:
			var b bool
			if err := json.Unmarshal(data, &b); err != nil {
				log.Printf("  • unmarshal bool %s: %v", key, err)
				continue
			}
			f.SetBool(b)

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
			var s string
			if err := json.Unmarshal(data, &s); err != nil {
				log.Printf("config: invalid JSON string for %s: %v", key, err)
				continue
			}
			field.SetString(s)

		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			var i64 int64
			if err := json.Unmarshal(data, &i64); err != nil {
				log.Printf("config: invalid JSON int for %s: %v", key, err)
				continue
			}
			field.SetInt(i64)

		case reflect.Bool:
			var b bool
			if err := json.Unmarshal(data, &b); err != nil {
				log.Printf("config: invalid JSON bool for %s: %v", key, err)
				continue
			}
			field.SetBool(b)

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
		case reflect.String, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Bool, reflect.Struct:
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

// MergeUpdateLiveJSON overlays a partial config JSON document onto the current live
// config and persists the result. Unlike MergeUpdateLive/MergeStructs (which skip
// zero-valued source fields), only the JSON keys actually present in raw are changed —
// so a present false bool or empty string IS applied, while fields absent from the
// document keep their current values. json.Unmarshal recurses into nested structs,
// setting only the sub-fields present in the document.
func (cm *ConfigManager) MergeUpdateLiveJSON(raw []byte) error {
	cm.mu.Lock()
	merged := cm.Live
	// Clone nested maps so an in-place unmarshal cannot mutate the live config before commit.
	merged.Distributed.PeerPublicKeys = clonePeerPublicKeys(cm.Live.Distributed.PeerPublicKeys)
	prepareReplaceOnlyMapFields(raw, &merged)
	if err := json.Unmarshal(raw, &merged); err != nil {
		cm.mu.Unlock()
		return err
	}
	cm.Live = merged
	toPersist := cm.Live
	cm.mu.Unlock()

	if err := cm.persistLiveConfigUnlocked(toPersist); err != nil {
		log.Println("MergeUpdateLiveJSON: failed to persist:", err)
		return err
	}
	return nil
}

func prepareReplaceOnlyMapFields(raw []byte, cfg *LiveConfig) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return
	}
	distRaw, ok := root["distributed"]
	if !ok {
		return
	}
	var dist map[string]json.RawMessage
	if err := json.Unmarshal(distRaw, &dist); err != nil {
		return
	}
	if _, ok := dist["peer_public_keys"]; ok {
		cfg.Distributed.PeerPublicKeys = nil
	}
}

func clonePeerPublicKeys(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func ValidXAuthKey(key string) bool {
	return xAuthKeyRe.MatchString(key)
}

func MustEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
