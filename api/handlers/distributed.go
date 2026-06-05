package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"go53/distributed"

	"github.com/gorilla/mux"
)

func writeDistributedJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func distributedServiceReady(w http.ResponseWriter) bool {
	if distributed.Default != nil {
		return true
	}
	http.Error(w, "distributed service is not initialized", http.StatusServiceUnavailable)
	return false
}

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
	writeDistributedJSON(w, status)
}

func GetWellKnownNodeHandler(w http.ResponseWriter, r *http.Request) {
	if !distributedServiceReady(w) {
		return
	}
	info, err := distributed.Default.NodeInfo()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	writeDistributedJSON(w, info)
}

func GenerateDistributedKeyPairHandler(w http.ResponseWriter, r *http.Request) {
	privateKey, publicKey, err := distributed.GenerateKeyPair()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeDistributedJSON(w, map[string]string{
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
	writeDistributedJSON(w, vector)
}

func GetDistributedEventsHandler(w http.ResponseWriter, r *http.Request) {
	if !distributedServiceReady(w) {
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
	writeDistributedJSON(w, events)
}

func PostDistributedEventHandler(w http.ResponseWriter, r *http.Request) {
	if !distributedServiceReady(w) {
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
	writeDistributedJSON(w, map[string]any{
		"applied": applied,
	})
}

func GetDistributedMerkleRootsHandler(w http.ResponseWriter, r *http.Request) {
	if !distributedServiceReady(w) {
		return
	}
	roots, err := distributed.Default.MerkleZoneRoots()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeDistributedJSON(w, roots)
}

func GetDistributedMerkleBranchesHandler(w http.ResponseWriter, r *http.Request) {
	if !distributedServiceReady(w) {
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
	writeDistributedJSON(w, branches)
}

func PostDistributedMerkleLeavesHandler(w http.ResponseWriter, r *http.Request) {
	if !distributedServiceReady(w) {
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
	writeDistributedJSON(w, leaves)
}

func PostDistributedMerkleRepairEventsHandler(w http.ResponseWriter, r *http.Request) {
	if !distributedServiceReady(w) {
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
	writeDistributedJSON(w, events)
}

func PostDistributedInviteHandler(w http.ResponseWriter, r *http.Request) {
	if !distributedServiceReady(w) {
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
	if !distributedServiceReady(w) {
		return
	}
	record, err := distributed.Default.ConsumeInvite(mux.Vars(r)["jti"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeDistributedJSON(w, record)
}
