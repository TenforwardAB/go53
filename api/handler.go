package api

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/miekg/dns"
	"go53/config"
	"go53/internal"
	"go53/zone"
	"io"
	"log"
	"net/http"
	"strings"
)

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

	if rrtype != dns.TypeSOA {
		if err := UpdateSOASerial(zoneName); err != nil {
			log.Printf("warning: failed to update SOA serial: %v", err)
		}
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
	err = json.NewEncoder(w).Encode(rec)
	if err != nil {
		return
	}
}

// DELETE /api/zones/{zone}/records/{rrtype}/{name}
func deleteRecordHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	zoneName := vars["zone"]
	rrtypeStr := vars["rrtype"]
	name := vars["name"]

	rrtype, err := internal.RRTypeStringToUint16(rrtypeStr)
	if err != nil {
		http.Error(w, "Unknown RR type", http.StatusBadRequest)
		return
	}

	var value interface{}

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

	if rrtype != dns.TypeSOA {
		if err := UpdateSOASerial(zoneName); err != nil {
			log.Printf("Failed to update SOA serial: %v", err)
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// GET
func GetZonesHandler(w http.ResponseWriter, r *http.Request) {
	payload := r.Context().Value("user").(map[string]interface{})
	err := json.NewEncoder(w).Encode(map[string]any{
		"message": "Authorized",
		"user":    payload,
	})
	if err != nil {
		return
	}
}

func updateLiveConfigHandler(w http.ResponseWriter, r *http.Request) {
	var partial config.LiveConfig

	if err := json.NewDecoder(r.Body).Decode(&partial); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	config.AppConfig.MergeUpdateLive(partial)

	w.WriteHeader(http.StatusNoContent)
}

func getLiveConfigHandler(w http.ResponseWriter, r *http.Request) {
	live := config.AppConfig.GetLive()
	err := json.NewEncoder(w).Encode(live)
	if err != nil {
		return
	}
}
