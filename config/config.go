package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	DNSPort        string // default :53
	APIPort        string // default :8053
	StorageBackend string // "badger" or "postgres"
	PostgresDSN    string // used only if StorageBackend is postgres
}

var AppConfig Config

func LoadConfig() {
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found, falling back to env variables")
	}

	AppConfig = Config{
		DNSPort:        getEnv("DNS_PORT", ":53"),
		APIPort:        getEnv("API_PORT", ":8053"),
		StorageBackend: getEnv("STORAGE_BACKEND", "badger"),
		PostgresDSN:    getEnv("POSTGRES_DSN", "host=localhost port=5432 user=postgres password=postgres dbname=go53 sslmode=disable"),
	}
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
