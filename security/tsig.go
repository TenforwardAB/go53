package security

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go53/storage"
	"log"
)

var TSIGSecrets map[string]TSIGKey

type TSIGKey struct {
	Algorithm string `json:"algorithm"`
	Secret    string `json:"secret"`
}

func LoadTSIGKeysFromStorage() error {
	tableData, err := storage.Backend.LoadTable("tsig-keys")
	if err != nil {
		return fmt.Errorf("failed to load TSIG keys from storage: %w", err)
	}

	log.Printf("TSIG raw data loaded: %+v", tableData)

	TSIGSecrets = make(map[string]TSIGKey)

	for name, raw := range tableData {
		var key TSIGKey
		if err := json.Unmarshal(raw, &key); err != nil {
			return fmt.Errorf("failed to unmarshal TSIG key %s: %w", name, err)
		}

		TSIGSecrets[name+"."] = key
	}
	log.Printf("TSIGSecrets loaded: %+v", TSIGSecrets)
	return nil
}

func GenerateTSIGSecret() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}
