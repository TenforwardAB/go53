package config

var DefaultLiveConfig = LiveConfig{
	LogLevel:       "info",
	Mode:           "primary",
	AllowTransfer:  "",
	AllowRecursion: "false",
	DefaultTTL:     "3600",
	Version:        "go53 1.0.0",
	MaxUDPSize:     "1232",
	EnableEDNS:     "true",
	RateLimitQPS:   "0", // 0 = no rate limiting
	AllowAXFR:      "false",
	DefaultNS:      "ns1.go53.local.",
}

var DefaultBaseConfig = BaseConfig{
	DNSPort:        ":53",
	BindHost:       "0.0.0.0",
	APIPort:        ":8053",
	StorageBackend: "badger",
	PostgresDSN:    "host=localhost port=5432 user=postgres password=postgres dbname=go53 sslmode=disable",
}
