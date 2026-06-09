package handlers

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"go53/distributed"
	"go53/security"
	"go53/types"
	zonepkg "go53/zone"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func ListDNSKeysHandler(w http.ResponseWriter, r *http.Request) {
	response, err := security.ListStoredKeys()
	if err != nil {
		http.Error(w, "Failed to load dnssec_keys table", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func GetDNSKeyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	zone := vars["keyid"]

	table, err := security.ListStoredKeys()
	if err != nil {
		http.Error(w, "Failed to load dnssec_keys table", http.StatusInternalServerError)
		return
	}

	response := make(map[string]types.StoredKey)

	for keyID, key := range table {
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
	if err := zonepkg.RefreshDNSSECKeyMaterial(zone); err != nil {
		http.Error(w, "Key generation succeeded but DNSSEC refresh failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := publishDNSSECKeysForZone(zone); err != nil {
		http.Error(w, "Key generation succeeded but distributed event failed: "+err.Error(), http.StatusInternalServerError)
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
	if err := zonepkg.RefreshDNSSECKeyMaterial(req.Zone); err != nil {
		http.Error(w, "Rollover key generated but DNSSEC refresh failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if distributed.Default != nil && key != nil {
		if err := distributed.Default.PublishDNSSECKey(keyID, *key); err != nil {
			http.Error(w, "Rollover key generated but distributed event failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"keyid": keyID,
		"key":   key,
	})
}

func ImportPrivateDNSKeysHandler(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
	if err != nil {
		http.Error(w, "failed to read key import body: "+err.Error(), http.StatusBadRequest)
		return
	}
	result, err := security.ImportPrivateKeys(data)
	if err != nil {
		http.Error(w, "private key import failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	var zones = map[string]struct{}{}
	keys, err := security.ListStoredKeys()
	if err != nil {
		http.Error(w, "private keys imported but list failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	for _, keyID := range result.Imported {
		key := keys[keyID]
		zones[key.Zone] = struct{}{}
		if distributed.Default != nil {
			if err := distributed.Default.PublishDNSSECKey(keyID, key); err != nil {
				http.Error(w, "private keys imported but distributed event failed: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}
	for zone := range zones {
		if err := zonepkg.RefreshDNSSECKeyMaterial(zone); err != nil {
			http.Error(w, "private keys imported but DNSSEC refresh failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(result)
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
	if err := zonepkg.RefreshDNSSECKeyMaterial(key.Zone); err != nil {
		http.Error(w, "Key lifecycle updated but DNSSEC refresh failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if distributed.Default != nil && key != nil {
		if err := distributed.Default.PublishDNSSECKey(keyID, *key); err != nil {
			http.Error(w, "Key lifecycle updated but distributed event failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
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
	if err := zonepkg.RefreshDNSSECKeyMaterial(key.Zone); err != nil {
		http.Error(w, "Key retired but DNSSEC refresh failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if distributed.Default != nil && key != nil {
		if err := distributed.Default.PublishDNSSECKey(keyID, *key); err != nil {
			http.Error(w, "Key retired but distributed event failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
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
	if err := zonepkg.RefreshDNSSECKeyMaterial(key.Zone); err != nil {
		http.Error(w, "Key revoked but DNSSEC refresh failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if distributed.Default != nil && key != nil {
		if err := distributed.Default.PublishDNSSECKey(keyID, *key); err != nil {
			http.Error(w, "Key revoked but distributed event failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	_ = json.NewEncoder(w).Encode(key)
}

func DeleteDNSKeyHandler(w http.ResponseWriter, r *http.Request) {
	keyID := mux.Vars(r)["keyid"]
	storedKey, _ := security.LoadStoredKey(keyID)

	if err := security.DeleteStoredKey(keyID); err != nil {
		http.Error(w, "Failed to delete key", http.StatusInternalServerError)
		return
	}
	if storedKey != nil {
		if err := zonepkg.RefreshDNSSECKeyMaterial(storedKey.Zone); err != nil {
			http.Error(w, "Key deleted but DNSSEC refresh failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if distributed.Default != nil {
		if err := distributed.Default.PublishDNSSECKeyDelete(keyID); err != nil {
			http.Error(w, "Key deleted but distributed event failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
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

func publishDNSSECKeysForZone(zone string) error {
	if distributed.Default == nil {
		return nil
	}
	keys, err := security.ListStoredKeys()
	if err != nil {
		return err
	}
	for keyID, key := range keys {
		if key.Zone != zone && key.Zone != strings.TrimSuffix(zone, ".") {
			continue
		}
		if err := distributed.Default.PublishDNSSECKey(keyID, key); err != nil {
			return err
		}
	}
	return nil
}
