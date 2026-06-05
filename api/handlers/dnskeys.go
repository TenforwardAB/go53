package handlers

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"go53/security"
	"go53/storage"
	"go53/types"
	"net/http"
	"strconv"
	"time"
)

func ListDNSKeysHandler(w http.ResponseWriter, r *http.Request) {
	table, err := storage.Backend.LoadTable("dnssec_keys")
	if err != nil {
		http.Error(w, "Failed to load dnssec_keys table", http.StatusInternalServerError)
		return
	}

	response := make(map[string]types.StoredKey)

	for keyID, raw := range table {
		var key types.StoredKey
		if err := json.Unmarshal(raw, &key); err != nil {
			continue
		}

		response[keyID] = key
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

	for keyID, raw := range table {
		var key types.StoredKey
		if err := json.Unmarshal(raw, &key); err != nil {
			continue
		}

		if key.Zone != zone {
			continue
		}

		response[keyID] = key
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

func CreateRolloverDNSKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Zone       string `json:"zone"`
		Role       string `json:"role"`
		Algorithm  string `json:"algorithm"`
		PublishAt  int64  `json:"publish_at"`
		ActivateAt int64  `json:"activate_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Zone == "" {
		req.Zone = r.URL.Query().Get("zone")
	}
	if req.Role == "" {
		req.Role = r.URL.Query().Get("role")
	}
	if req.Algorithm == "" {
		req.Algorithm = r.URL.Query().Get("algorithm")
	}
	if req.Algorithm == "" {
		req.Algorithm = "ED25519"
	}
	keyID, key, err := security.GenerateRolloverKey(req.Zone, req.Role, req.Algorithm, req.PublishAt, req.ActivateAt)
	if err != nil {
		http.Error(w, "Rollover key generation failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"keyid": keyID,
		"key":   key,
	})
}

func UpdateDNSKeyLifecycleHandler(w http.ResponseWriter, r *http.Request) {
	keyID := mux.Vars(r)["keyid"]
	var update types.StoredKey
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	key, err := security.UpdateKeyLifecycle(keyID, update)
	if err != nil {
		http.Error(w, "Failed to update key lifecycle: "+err.Error(), http.StatusBadRequest)
		return
	}
	_ = json.NewEncoder(w).Encode(key)
}

func RetireDNSKeyHandler(w http.ResponseWriter, r *http.Request) {
	keyID := mux.Vars(r)["keyid"]
	key, err := security.RetireKey(keyID, removeAfter(r))
	if err != nil {
		http.Error(w, "Failed to retire key: "+err.Error(), http.StatusBadRequest)
		return
	}
	_ = json.NewEncoder(w).Encode(key)
}

func RevokeDNSKeyHandler(w http.ResponseWriter, r *http.Request) {
	keyID := mux.Vars(r)["keyid"]
	key, err := security.RevokeKey(keyID, removeAfter(r))
	if err != nil {
		http.Error(w, "Failed to revoke key: "+err.Error(), http.StatusBadRequest)
		return
	}
	_ = json.NewEncoder(w).Encode(key)
}

func DeleteDNSKeyHandler(w http.ResponseWriter, r *http.Request) {
	keyID := mux.Vars(r)["keyid"]

	if err := storage.Backend.DeleteFromTable("dnssec_keys", keyID); err != nil {
		http.Error(w, "Failed to delete key", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func removeAfter(r *http.Request) time.Duration {
	days, err := strconv.Atoi(r.URL.Query().Get("remove_after_days"))
	if err != nil || days <= 0 {
		return 30 * 24 * time.Hour
	}
	return time.Duration(days) * 24 * time.Hour
}
