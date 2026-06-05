package handlers

import (
	"encoding/json"
	"go53/config"
	"go53/distributed"
	"net/http"
)

func UpdateLiveConfigHandler(w http.ResponseWriter, r *http.Request) {
	var partial config.LiveConfig

	if err := json.NewDecoder(r.Body).Decode(&partial); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	config.AppConfig.MergeUpdateLive(partial)
	if distributed.Default != nil {
		if err := distributed.Default.PublishConfig(partial); err != nil {
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
