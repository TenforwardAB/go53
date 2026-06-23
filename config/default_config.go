package config

var DefaultLiveConfig = LiveConfig{
	LogLevel:          "info",
	Mode:              "primary",
	AllowTransfer:     "127.0.0.1",
	AllowRecursion:    false,
	DefaultTTL:        3600,
	Version:           "go53 v0.79.0",
	MaxUDPSize:        1232,
	EnableEDNS:        true,
	NSID:              "", // empty = NSID disabled, avoids leaking node identity by default
	RateLimitQPS:      0,  // 0 = no rate limiting
	WALRetentionDays:  14,
	MaxRestoreBytes:   1 << 30, // 1 GiB; raise via config for larger backups, 0 = unlimited
	AllowAXFR:         false,
	DefaultNS:         "ns1.go53.local.",
	EnforceTSIG:       false,
	DNSSECEnabled:     true,
	AnyQueryPolicy:    "hinfo",
	UnknownZonePolicy: "refused",

	Primary: PrimaryConfig{
		NotifyDebounceMs: 2000,
		Ip:               "127.0.0.1",
		Port:             53,
	},

	Secondary: SecondaryConfig{
		FetchDebounceMs:     3000,
		MinFetchIntervalSec: 10,
		MaxParallelFetches:  5,
		Zones:               []string{},
		RefreshIntervalSec:  3600, // hourly self-heal, BIND-like
		RefreshJitterSec:    60,
		CatalogEnabled:      false,
		CatalogZone:         "_catalog.go53.",
	},

	DNSSEC: DNSSECSignaturePolicy{
		ValiditySeconds:       7 * 24 * 3600,
		DNSKEYValiditySeconds: 14 * 24 * 3600,
		RefreshBeforeSeconds:  24 * 3600,
		JitterSeconds:         3600,
		InceptionSkewSeconds:  3600,
	},

	Distributed: DistributedConfig{
		NodeID:          "",
		Peers:           "",
		Transport:       "http",
		SyncBindHost:    "0.0.0.0",
		SyncPort:        ":53530",
		PrivateKey:      "",
		PeerPublicKeys:  map[string]string{},
		PushTimeoutMs:   2000,
		ResyncIntervalS: 30,
	},

	Auth: AuthConfig{
		Mode:         "disabled",
		XAuthKey:     "",
		OIDCIssuer:   "",
		OIDCAudience: "",
		OIDCJWKSURL:  "",
	},
}

var DefaultBaseConfig = BaseConfig{
	DNSPort:          ":2053",
	BindHost:         "0.0.0.0",
	APIPort:          ":8053",
	StorageBackend:   "badger",
	PostgresDSN:      "host=localhost port=5432 user=postgres password=postgres dbname=go53 sslmode=disable",
	AdminSocket:      "/run/go53/admin.sock",
	AdminSocketGroup: "go53_admin",
}
