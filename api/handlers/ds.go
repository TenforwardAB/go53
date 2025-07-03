package handlers

import (
	"encoding/json"
	"fmt"
	"go53/security"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/miekg/dns"
)

func GetDSHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	zone := vars["zone"]

	if zone == "" {
		http.Error(w, "missing zone parameter", http.StatusBadRequest)
		return
	}

	dsList, err := security.GetDS(zone)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get DS: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	jsonList := make([]map[string]interface{}, 0, len(dsList))
	for _, ds := range dsList {
		jsonList = append(jsonList, map[string]interface{}{
			"name":       ds.Hdr.Name,
			"type":       dns.TypeToString[ds.Hdr.Rrtype],
			"class":      dns.ClassToString[ds.Hdr.Class],
			"ttl":        ds.Hdr.Ttl,
			"keytag":     ds.KeyTag,
			"algorithm":  ds.Algorithm,
			"digestType": ds.DigestType,
			"digest":     ds.Digest,
		})
	}

	_ = json.NewEncoder(w).Encode(jsonList)
}
