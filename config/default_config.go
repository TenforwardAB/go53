package config

var DefaultLiveConfig = LiveConfig{
	LogLevel:       "info",
	Mode:           "primary",
	AllowTransfer:  "127.0.0.1",
	AllowRecursion: false,
	DefaultTTL:     3600,
	Version:        "go53 1.0.1",
	MaxUDPSize:     1232,
	EnableEDNS:     true,
	RateLimitQPS:   0, // 0 = no rate limiting
	AllowAXFR:      false,
	DefaultNS:      "ns1.go53.local.",
	EnforceTSIG:    false,
	DNSSECEnabled:  true,

	Primary: PrimaryConfig{
		NotifyDebounceMs: 2000,
		Ip:               "127.0.0.1",
		Port:             53,
	},

	Secondary: SecondaryConfig{
		FetchDebounceMs:     3000,
		MinFetchIntervalSec: 10,
		MaxParallelFetches:  5,
	},

	Dev: DevConfig{
		DualMode: false,
	},
}

var DefaultBaseConfig = BaseConfig{
	DNSPort:        ":53",
	BindHost:       "0.0.0.0",
	APIPort:        ":8053",
	StorageBackend: "badger",
	PostgresDSN:    "host=localhost port=5432 user=postgres password=postgres dbname=go53 sslmode=disable",
}
