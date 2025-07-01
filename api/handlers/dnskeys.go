package handlers

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"go53/security"
	"go53/storage"
	"go53/types"
	"net/http"
)

func ListDNSKeysHandler(w http.ResponseWriter, r *http.Request) {
	table, err := storage.Backend.LoadTable("dnssec_keys")
	if err != nil {
		http.Error(w, "Failed to load dnssec_keys table", http.StatusInternalServerError)
		return
	}

	response := make(map[string]types.StoredKey)

	for _, raw := range table {
		var key types.StoredKey
		if err := json.Unmarshal(raw, &key); err != nil {
			continue
		}

		prefix := "zsk"
		if key.Flags == 257 {
			prefix = "ksk"
		}

		// If keyID is not already prefixed correctly, reformat it
		responseKey := fmt.Sprintf("%s_%s_%s", prefix, key.Zone, key.Algorithm)
		response[responseKey] = key
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func GetDNSKeyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	zone := vars["keyid"]

	table, err := storage.Backend.LoadTable("dnssec_keys")
	if err != nil {
		http.Error(w, "Failed to load dnssec_keys table", http.StatusInternalServerError)
		return
	}

	response := make(map[string]types.StoredKey)

	for _, raw := range table {
		var key types.StoredKey
		if err := json.Unmarshal(raw, &key); err != nil {
			continue
		}

		if key.Zone != zone {
			continue
		}

		prefix := "zsk"
		if key.Flags == 257 {
			prefix = "ksk"
		}

		responseKey := fmt.Sprintf("%s_%s_%s", prefix, key.Zone, key.Algorithm)
		response[responseKey] = key
	}

	if len(response) == 0 {
		http.Error(w, fmt.Sprintf("No DNSSEC keys found for zone %s", zone), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func CreateDNSKeyHandler(w http.ResponseWriter, r *http.Request) {
	zone := r.URL.Query().Get("zone")
	if zone == "" {
		http.Error(w, "Missing zone", http.StatusBadRequest)
		return
	}

	if err := security.GenerateAndStoreAllKeys(zone); err != nil {
		http.Error(w, "Key generation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("Keys generated for zone: %s", zone),
	})
}

func DeleteDNSKeyHandler(w http.ResponseWriter, r *http.Request) {
	keyID := mux.Vars(r)["keyid"]

	if err := storage.Backend.DeleteFromTable("dnssec_keys", keyID); err != nil {
		http.Error(w, "Failed to delete key", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
