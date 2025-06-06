package api

import (
	"encoding/json"
	"go53/zone"
	"net/http"
)

func addARecordHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Zone string `json:"zone"`
		Name string `json:"name"`
		IP   string `json:"ip"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	zone.AddARecord(req.Zone, req.Name, req.IP)
	w.WriteHeader(http.StatusCreated)
}

func GetZonesHandler(w http.ResponseWriter, r *http.Request) {
	payload := r.Context().Value("user").(map[string]interface{})
	json.NewEncoder(w).Encode(map[string]any{
		"message": "Authorized",
		"user":    payload,
	})
}
