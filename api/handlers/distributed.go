package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"go53/distributed"

	"github.com/gorilla/mux"
)

func GetDistributedStatusHandler(w http.ResponseWriter, r *http.Request) {
	status := map[string]any{
		"enabled":       distributed.Enabled(),
		"tcp_transport": distributed.TCPTransportEnabled(),
		"tls_transport": distributed.TLSTransportEnabled(),
	}
	if distributed.Default != nil {
		if pub, err := distributed.Default.PublicKey(); err == nil {
			status["public_key"] = pub
			status["fingerprint"] = distributed.PublicKeyFingerprint(pub)
		}
		if vector, err := distributed.Default.Vector(); err == nil {
			status["vector"] = vector
		}
		if nodeInfo, err := distributed.Default.NodeInfo(); err == nil {
			status["node"] = nodeInfo
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

func GetWellKnownNodeHandler(w http.ResponseWriter, r *http.Request) {
	if distributed.Default == nil {
		http.Error(w, "distributed service is not initialized", http.StatusServiceUnavailable)
		return
	}
	info, err := distributed.Default.NodeInfo()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
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
	if distributed.TCPTransportEnabled() && r.URL.Query().Get("resync") != "true" {
		http.Error(w, "HTTP event ingest is disabled when distributed transport uses socket mode; use ?resync=true for manual recovery only", http.StatusConflict)
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

func GetDistributedMerkleRootsHandler(w http.ResponseWriter, r *http.Request) {
	if distributed.Default == nil {
		http.Error(w, "distributed service is not initialized", http.StatusServiceUnavailable)
		return
	}
	roots, err := distributed.Default.MerkleZoneRoots()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(roots)
}

func GetDistributedMerkleBranchesHandler(w http.ResponseWriter, r *http.Request) {
	if distributed.Default == nil {
		http.Error(w, "distributed service is not initialized", http.StatusServiceUnavailable)
		return
	}
	zone := r.URL.Query().Get("zone")
	if zone == "" {
		http.Error(w, "missing zone", http.StatusBadRequest)
		return
	}
	branches, err := distributed.Default.MerkleZoneBranches(zone)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(branches)
}

func PostDistributedMerkleLeavesHandler(w http.ResponseWriter, r *http.Request) {
	if distributed.Default == nil {
		http.Error(w, "distributed service is not initialized", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Zone     string   `json:"zone"`
		Prefixes []string `json:"prefixes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Zone == "" {
		http.Error(w, "missing zone", http.StatusBadRequest)
		return
	}
	leaves, err := distributed.Default.MerkleZoneLeaves(req.Zone, req.Prefixes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(leaves)
}

func PostDistributedMerkleRepairEventsHandler(w http.ResponseWriter, r *http.Request) {
	if distributed.Default == nil {
		http.Error(w, "distributed service is not initialized", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Entities []string `json:"entities"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	events, err := distributed.Default.LatestEventsForEntities(req.Entities)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(events)
}

func PostDistributedInviteHandler(w http.ResponseWriter, r *http.Request) {
	if distributed.Default == nil {
		http.Error(w, "distributed service is not initialized", http.StatusServiceUnavailable)
		return
	}
	var record distributed.InviteRecord
	if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if err := distributed.Default.SaveInvite(record); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func PostDistributedInviteConsumeHandler(w http.ResponseWriter, r *http.Request) {
	if distributed.Default == nil {
		http.Error(w, "distributed service is not initialized", http.StatusServiceUnavailable)
		return
	}
	record, err := distributed.Default.ConsumeInvite(mux.Vars(r)["jti"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(record)
}
