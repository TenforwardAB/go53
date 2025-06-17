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
