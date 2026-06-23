package handlers

import (
	"encoding/json"
	"go53/config"
	"go53/distributed"
	"go53/wal"
	"io"
	"net/http"
)

func UpdateLiveConfigHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	if patchContainsXAuthKey(body) {
		http.Error(w, "x_auth_key must be managed through the local admin auth-key endpoint", http.StatusForbidden)
		return
	}

	// Validate the patch parses as a LiveConfig, but apply it as a raw JSON overlay so
	// that present false bools / empty strings are honored (a struct-merge would drop
	// zero values). Absent fields are left unchanged.
	var validate config.LiveConfig
	if err := json.Unmarshal(body, &validate); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if err := config.AppConfig.MergeUpdateLiveJSON(body); err != nil {
		http.Error(w, "failed to apply config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := wal.Append(wal.KindConfig, wal.OpUpsert, "", "", "", "config", "live", body); err != nil {
		http.Error(w, "config updated but WAL append failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if distributed.Default != nil {
		if err := distributed.Default.PublishConfig(body); err != nil {
			http.Error(w, "config updated but distributed event failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

func GetLiveConfigHandler(w http.ResponseWriter, r *http.Request) {
	live := config.AppConfig.GetLive()
	live.Auth.XAuthKey = ""
	err := json.NewEncoder(w).Encode(live)
	if err != nil {
		return
	}
}

type xAuthKeyRequest struct {
	XAuthKey string `json:"x_auth_key"`
}

type xAuthKeyResponse struct {
	XAuthKey   string `json:"x_auth_key"`
	Configured bool   `json:"configured"`
}

func GetXAuthKeyHandler(w http.ResponseWriter, r *http.Request) {
	key := config.AppConfig.GetLive().Auth.XAuthKey
	_ = json.NewEncoder(w).Encode(xAuthKeyResponse{
		XAuthKey:   key,
		Configured: config.ValidXAuthKey(key),
	})
}

func SetXAuthKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req xAuthKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if !config.ValidXAuthKey(req.XAuthKey) {
		http.Error(w, "x_auth_key must be base62 and at least 48 characters", http.StatusBadRequest)
		return
	}

	body, err := json.Marshal(map[string]any{
		"auth": map[string]string{"x_auth_key": req.XAuthKey},
	})
	if err != nil {
		http.Error(w, "failed to build config patch", http.StatusInternalServerError)
		return
	}
	if err := config.AppConfig.MergeUpdateLiveJSON(body); err != nil {
		http.Error(w, "failed to apply config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := wal.Append(wal.KindConfig, wal.OpUpsert, "", "", "", "config", "live", body); err != nil {
		http.Error(w, "x_auth_key updated but WAL append failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if distributed.Default != nil && config.AppConfig.GetLive().Distributed.AuthSyncEnabled() {
		if err := distributed.Default.PublishConfig(body); err != nil {
			http.Error(w, "x_auth_key updated but distributed event failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

func patchContainsXAuthKey(body []byte) bool {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil {
		return false
	}
	authRaw, ok := root["auth"]
	if !ok {
		return false
	}
	var auth map[string]json.RawMessage
	if err := json.Unmarshal(authRaw, &auth); err != nil {
		return false
	}
	_, ok = auth["x_auth_key"]
	return ok
}
