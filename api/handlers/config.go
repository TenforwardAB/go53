package handlers

import (
	"encoding/json"
	"go53/config"
	"go53/distributed"
	"io"
	"net/http"
)

func UpdateLiveConfigHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
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
	err := json.NewEncoder(w).Encode(live)
	if err != nil {
		return
	}
}
