package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"go53/distributed"
)

func GetDistributedStatusHandler(w http.ResponseWriter, r *http.Request) {
	status := map[string]any{
		"enabled": distributed.Enabled(),
	}
	if distributed.Default != nil {
		if pub, err := distributed.Default.PublicKey(); err == nil {
			status["public_key"] = pub
		}
		if vector, err := distributed.Default.Vector(); err == nil {
			status["vector"] = vector
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

func GenerateDistributedKeyPairHandler(w http.ResponseWriter, r *http.Request) {
	privateKey, publicKey, err := distributed.GenerateKeyPair()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"private_key": privateKey,
		"public_key":  publicKey,
	})
}

func GetDistributedVectorHandler(w http.ResponseWriter, r *http.Request) {
	vector := map[string]uint64{}
	if distributed.Default != nil {
		var err error
		vector, err = distributed.Default.Vector()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(vector)
}

func GetDistributedEventsHandler(w http.ResponseWriter, r *http.Request) {
	if distributed.Default == nil {
		http.Error(w, "distributed service is not initialized", http.StatusServiceUnavailable)
		return
	}
	after, err := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	if err != nil && r.URL.Query().Get("after") != "" {
		http.Error(w, "invalid after", http.StatusBadRequest)
		return
	}
	events, err := distributed.Default.Events(r.URL.Query().Get("origin"), after)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(events)
}

func PostDistributedEventHandler(w http.ResponseWriter, r *http.Request) {
	if distributed.Default == nil {
		http.Error(w, "distributed service is not initialized", http.StatusServiceUnavailable)
		return
	}
	var event distributed.Event
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	applied, err := distributed.Default.ReceiveEvent(r.Context(), event)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"applied": applied,
	})
}
