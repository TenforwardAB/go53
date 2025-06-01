package config

type Config struct {
    DNSPort  string
    APIPort  string
}

func Load() *Config {
    return &Config{
        DNSPort: ":53",
        APIPort: ":8080",
    }
}
