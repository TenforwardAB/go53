package handlers

import (
	"encoding/json"
	"github.com/gorilla/mux"
	"github.com/miekg/dns"
	"go53/config"
	"go53/dns/dnsutils"
	"go53/internal"
	"go53/zone"
	"io"
	"log"
	"net/http"
	"strings"
)

// POST /api/zones/{zone}/records/{rrtype}
func AddRecordHandler(w http.ResponseWriter, r *http.Request) {
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
	log.Printf("zoneName: %+v\n", zoneName)
	log.Printf("name: %+v\n", name)

	if err := zone.AddRecord(rrtype, zoneName, name, value, ttlPtr); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if rrtype != dns.TypeSOA {
		if err := dnsutils.UpdateSOASerial(zoneName); err != nil {
			log.Printf("warning: failed to update SOA serial: %v", err)
		} else if config.AppConfig.GetLive().Mode != "secondary" {
			go dnsutils.ScheduleNotify(zoneName)
		}
	}

	w.WriteHeader(http.StatusCreated)
}

// GET /api/zones/{zone}/records/{rrtype}/{name}
func GetRecordHandler(w http.ResponseWriter, r *http.Request) {
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
func DeleteRecordHandler(w http.ResponseWriter, r *http.Request) {
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
		if err := dnsutils.UpdateSOASerial(zoneName); err != nil {
			log.Printf("warning: failed to update SOA serial: %v", err)
		} else if config.AppConfig.GetLive().Mode != "secondary" {
			go dnsutils.ScheduleNotify(zoneName)
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// GET
func GetZonesHandler(w http.ResponseWriter, r *http.Request) {
	userRaw := r.Context().Value("user")
	payload, ok := userRaw.(map[string]interface{})
	if !ok {
		http.Error(w, "unauthorized or missing user context", http.StatusUnauthorized)
		return
	}

	err := json.NewEncoder(w).Encode(map[string]any{
		"message": "Authorized",
		"user":    payload,
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}
