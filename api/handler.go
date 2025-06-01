package api

import (
    "encoding/json"
    "net/http"
    "go53/zone"
)

func addARecordHandler(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Name string `json:"name"`
        IP   string `json:"ip"`
    }
    json.NewDecoder(r.Body).Decode(&req)
    zone.AddARecord(req.Name, req.IP)
    w.WriteHeader(http.StatusCreated)
}
