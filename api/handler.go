package api

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/miekg/dns"
	"go53/internal"
	"go53/zone"
	"io"
	"log"
	"net/http"
	"strings"
)

type addRecordRequest struct {
	Name  string  `json:"name"`
	Value string  `json:"value"`
	TTL   *uint32 `json:"ttl,omitempty"`
}

// POST /api/zones/{zone}/records/{rrtype}
func addRecordHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	zoneName := vars["zone"]
	rrtypeStr := vars["rrtype"]

	rrtype, err := internal.RRTypeStringToUint16(rrtypeStr)
	if err != nil {
		http.Error(w, "Unknown RR type", http.StatusBadRequest)
		return
	}

	var body map[string]interface{}
	var name string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	switch rrtype {
	case dns.TypeSOA:
		name = zoneName

	default:
		rawName, ok := body["name"]
		if !ok {
			http.Error(w, "Missing field: name", http.StatusBadRequest)
			return
		}
		name, ok = rawName.(string)
		if !ok || strings.TrimSpace(name) == "" {
			http.Error(w, "Field 'name' must be a non-empty string", http.StatusBadRequest)
			return
		}
		delete(body, "name")
	}

	var ttlPtr *uint32
	if rawTTL, ok := body["ttl"]; ok {
		switch v := rawTTL.(type) {
		case float64:
			t := uint32(v)
			ttlPtr = &t
		case int:
			t := uint32(v)
			ttlPtr = &t
		default:
			http.Error(w, "Field 'ttl' must be a number", http.StatusBadRequest)
			return
		}
		delete(body, "ttl")
	}

	value := body
	log.Printf("body: %+v\n", value)
	if err := zone.AddRecord(rrtype, zoneName, name, value, ttlPtr); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// GET /api/zones/{zone}/records/{rrtype}/{name}
func getRecordHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	//zoneName := vars["zone"]
	rrtypeStr := vars["rrtype"]
	name := vars["name"]

	rrtype, err := internal.RRTypeStringToUint16(rrtypeStr)
	if err != nil {
		http.Error(w, "Unknown RR type", http.StatusBadRequest)
		return
	}

	rec, found := zone.LookupRecord(rrtype, name)
	if !found {
		http.Error(w, "Record not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rec)
}

// DELETE /api/zones/{zone}/records/{rrtype}/{name}
func deleteRecordHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	rrtypeStr := vars["rrtype"]
	name := vars["name"]

	rrtype, err := internal.RRTypeStringToUint16(rrtypeStr)
	if err != nil {
		http.Error(w, "Unknown RR type", http.StatusBadRequest)
		return
	}

	// Default to nil value
	var value interface{}

	// Only try to decode body if there *is* one
	if r.ContentLength > 0 {
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&value); err != nil && err != io.EOF {
			http.Error(w, "Invalid JSON in request body", http.StatusBadRequest)
			return
		}
	}

	err = zone.DeleteRecord(rrtype, name, value)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GET
func GetZonesHandler(w http.ResponseWriter, r *http.Request) {
	payload := r.Context().Value("user").(map[string]interface{})
	json.NewEncoder(w).Encode(map[string]any{
		"message": "Authorized",
		"user":    payload,
	})
}
