package handlers

import (
	"encoding/json"
	"fmt"
	"go53/security"
	"net/http"
	"strconv"
	"strings"

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

	dsList, err := security.GetDSWithDigestTypes(zone, digestTypesFromQuery(r))
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

func GetCDSHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	zone := vars["zone"]
	if zone == "" {
		http.Error(w, "missing zone parameter", http.StatusBadRequest)
		return
	}
	if deleteSignal(r) {
		writeRRList(w, []dns.RR{security.DeleteDSCDS(zone, ttlFromQuery(r))})
		return
	}
	dsList, err := security.GetDSWithDigestTypes(zone, digestTypesFromQuery(r))
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get CDS: %v", err), http.StatusInternalServerError)
		return
	}
	rrs := make([]dns.RR, 0, len(dsList))
	for _, ds := range dsList {
		rrs = append(rrs, ds.ToCDS())
	}
	writeRRList(w, rrs)
}

func GetCDNSKEYHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	zone := vars["zone"]
	if zone == "" {
		http.Error(w, "missing zone parameter", http.StatusBadRequest)
		return
	}
	if deleteSignal(r) {
		writeRRList(w, []dns.RR{security.DeleteDSCDNSKEY(zone, ttlFromQuery(r))})
		return
	}
	cdnskeys, err := security.GetCDNSKEY(zone)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get CDNSKEY: %v", err), http.StatusInternalServerError)
		return
	}
	rrs := make([]dns.RR, 0, len(cdnskeys))
	for _, cdnskey := range cdnskeys {
		rrs = append(rrs, cdnskey)
	}
	writeRRList(w, rrs)
}

func writeRRList(w http.ResponseWriter, rrs []dns.RR) {
	w.Header().Set("Content-Type", "application/json")
	jsonList := make([]map[string]interface{}, 0, len(rrs))
	for _, rr := range rrs {
		h := rr.Header()
		item := map[string]interface{}{
			"name":  h.Name,
			"type":  dns.TypeToString[h.Rrtype],
			"class": dns.ClassToString[h.Class],
			"ttl":   h.Ttl,
		}
		switch v := rr.(type) {
		case *dns.DS:
			item["keytag"] = v.KeyTag
			item["algorithm"] = v.Algorithm
			item["digestType"] = v.DigestType
			item["digest"] = v.Digest
		case *dns.CDS:
			item["keytag"] = v.KeyTag
			item["algorithm"] = v.Algorithm
			item["digestType"] = v.DigestType
			item["digest"] = v.Digest
		case *dns.CDNSKEY:
			item["flags"] = v.Flags
			item["protocol"] = v.Protocol
			item["algorithm"] = v.Algorithm
			item["publicKey"] = v.PublicKey
		}
		jsonList = append(jsonList, item)
	}
	_ = json.NewEncoder(w).Encode(jsonList)
}

func digestTypesFromQuery(r *http.Request) []uint8 {
	raw := strings.TrimSpace(r.URL.Query().Get("digest"))
	if raw == "" {
		raw = strings.TrimSpace(r.URL.Query().Get("digest_type"))
	}
	if raw == "" {
		return []uint8{dns.SHA256}
	}
	var out []uint8
	for _, part := range strings.Split(raw, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || n <= 0 || n > 255 {
			continue
		}
		out = append(out, uint8(n))
	}
	if len(out) == 0 {
		return []uint8{dns.SHA256}
	}
	return out
}

func deleteSignal(r *http.Request) bool {
	v := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("delete")))
	return v == "1" || v == "true" || v == "yes"
}

func ttlFromQuery(r *http.Request) uint32 {
	n, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("ttl")))
	if err != nil || n <= 0 {
		return 3600
	}
	return uint32(n)
}
