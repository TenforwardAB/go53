package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/miekg/dns"

	"go53/config"
	"go53/distributed"
	"go53/dns/dnsutils"
	"go53/internal"
	"go53/security"
	"go53/zone"
	"go53/zone/rtypes"
)

type addRecordRequest struct {
	name   string
	value  map[string]interface{}
	ttlPtr *uint32
}

type addRecordError struct {
	message string
	status  int
}

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

	req, reqErr := newAddRecordRequest(r.Body, zoneName, rrtype)
	if reqErr != nil {
		http.Error(w, reqErr.message, reqErr.status)
		return
	}
	log.Printf("record add request accepted: rrtype=%s zone_status=present", rrtypeStr)

	if err := zone.AddRecord(rrtype, zoneName, req.name, req.value, req.ttlPtr); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := afterRecordUpsert(zoneName, rrtypeStr, rrtype, req.name); err != nil {
		http.Error(w, "record stored but distributed event failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func newAddRecordRequest(body io.Reader, zoneName string, rrtype uint16) (addRecordRequest, *addRecordError) {
	payload, err := decodeRecordPayload(body)
	if err != nil {
		return addRecordRequest{}, err
	}

	req, err := recordRequestFromPayload(zoneName, rrtype, payload)
	if err != nil {
		return addRecordRequest{}, err
	}

	ttlPtr, err := extractTTL(payload)
	if err != nil {
		return addRecordRequest{}, err
	}
	req.ttlPtr = ttlPtr
	return req, nil
}

func decodeRecordPayload(body io.Reader) (map[string]interface{}, *addRecordError) {
	var payload map[string]interface{}
	if err := json.NewDecoder(body).Decode(&payload); err != nil {
		return nil, badRecordRequest("Invalid JSON")
	}
	return payload, nil
}

func recordRequestFromPayload(zoneName string, rrtype uint16, payload map[string]interface{}) (addRecordRequest, *addRecordError) {
	switch rrtype {
	case dns.TypeSOA:
		return addRecordRequest{name: zoneName, value: payload}, nil
	case dns.TypeDNSKEY:
		return dnskeyRecordRequest(zoneName, payload)
	default:
		return namedRecordRequest(payload)
	}
}

func dnskeyRecordRequest(zoneName string, payload map[string]interface{}) (addRecordRequest, *addRecordError) {
	keyid, err := requiredStringField(payload, "keyid")
	if err != nil {
		return addRecordRequest{}, err
	}

	_, storedKey, loadErr := security.LoadPrivateKeyFromStorage(keyid)
	if loadErr != nil {
		return addRecordRequest{}, &addRecordError{
			message: fmt.Sprintf("Key not found: %v", loadErr),
			status:  http.StatusNotFound,
		}
	}

	value := map[string]interface{}{
		"flags":      security.DNSKEYFlags(storedKey),
		"protocol":   3,
		"algorithm":  security.AlgorithmNumberFromName(storedKey.Algorithm),
		"public_key": storedKey.PublicKey,
	}
	if ttl, ok, err := optionalTTL(payload); err != nil {
		return addRecordRequest{}, err
	} else if ok {
		value["ttl"] = ttl
	}

	name, _ := internal.SanitizeFQDN(zoneName)
	delete(payload, "name")
	return addRecordRequest{name: name, value: value}, nil
}

func namedRecordRequest(payload map[string]interface{}) (addRecordRequest, *addRecordError) {
	name, err := requiredStringField(payload, "name")
	if err != nil {
		return addRecordRequest{}, err
	}
	delete(payload, "name")
	return addRecordRequest{name: name, value: payload}, nil
}

func requiredStringField(payload map[string]interface{}, field string) (string, *addRecordError) {
	raw, ok := payload[field]
	if !ok {
		return "", badRecordRequest("Missing field: " + field)
	}
	value, ok := raw.(string)
	if !ok || strings.TrimSpace(value) == "" {
		return "", badRecordRequest(fmt.Sprintf("Field '%s' must be a non-empty string", field))
	}
	return value, nil
}

func extractTTL(payload map[string]interface{}) (*uint32, *addRecordError) {
	ttl, ok, err := optionalTTL(payload)
	if err != nil || !ok {
		return nil, err
	}
	delete(payload, "ttl")
	return &ttl, nil
}

func optionalTTL(payload map[string]interface{}) (uint32, bool, *addRecordError) {
	raw, ok := payload["ttl"]
	if !ok {
		return 0, false, nil
	}
	ttl, err := ttlUint32(raw)
	if err != nil {
		return 0, false, err
	}
	return ttl, true, nil
}

func ttlUint32(raw interface{}) (uint32, *addRecordError) {
	switch value := raw.(type) {
	case float64:
		return uint32(value), nil
	case int:
		return uint32(value), nil
	default:
		return 0, badRecordRequest("Field 'ttl' must be a number")
	}
}

func badRecordRequest(message string) *addRecordError {
	return &addRecordError{message: message, status: http.StatusBadRequest}
}

func afterRecordUpsert(zoneName, rrtypeStr string, rrtype uint16, name string) error {
	if rrtype != dns.TypeSOA {
		updateSOAAfterRecordChange(zoneName)
	}
	if err := publishDistributedUpsert(zoneName, rrtypeStr, name); err != nil {
		return err
	}
	if rrtype == dns.TypeSOA {
		return nil
	}
	return publishDistributedUpsert(zoneName, "SOA", "@")
}

func updateSOAAfterRecordChange(zoneName string) {
	if err := dnsutils.UpdateSOASerial(zoneName); err != nil {
		log.Printf("warning: failed to update SOA serial: %v", err)
		return
	}
	if config.AppConfig.GetLive().Mode != "secondary" {
		go dnsutils.ScheduleNotify(zoneName)
	}
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
	if err := publishDistributedDelete(zoneName, rrtypeStr, name); err != nil {
		http.Error(w, "record deleted but distributed event failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if rrtype != dns.TypeSOA {
		if err := publishDistributedUpsert(zoneName, "SOA", "@"); err != nil {
			http.Error(w, "record deleted but distributed SOA event failed: "+err.Error(), http.StatusInternalServerError)
			return
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

func publishDistributedUpsert(zoneName, rrtypeStr, name string) error {
	if distributed.Default == nil || !distributed.Enabled() {
		return nil
	}
	mem := rtypes.GetMemStore()
	if mem == nil {
		return fmt.Errorf("memory store is not initialized")
	}
	recordName := canonicalRecordName(zoneName, rrtypeStr, name)
	zoneKey, typeKey, value, ok := mem.GetRecord(zoneName, strings.ToUpper(rrtypeStr), recordName)
	if !ok && recordName != name {
		zoneKey, typeKey, value, ok = mem.GetRecord(zoneName, strings.ToUpper(rrtypeStr), name)
	}
	if !ok {
		return fmt.Errorf("stored record not found after add")
	}
	return distributed.Default.PublishUpsert(zoneKey, typeKey, recordName, value)
}

func publishDistributedDelete(zoneName, rrtypeStr, name string) error {
	if distributed.Default == nil || !distributed.Enabled() {
		return nil
	}
	return distributed.Default.PublishDelete(zoneName, strings.ToUpper(rrtypeStr), canonicalRecordName(zoneName, rrtypeStr, name))
}

func canonicalRecordName(zoneName, rrtypeStr, name string) string {
	if strings.EqualFold(rrtypeStr, "SOA") {
		return "@"
	}
	if strings.TrimSpace(name) == "" {
		return "@"
	}
	sanitizedZone, err := internal.SanitizeFQDN(zoneName)
	if err == nil && dns.IsFqdn(name) {
		fqdnName := dns.Fqdn(name)
		if strings.EqualFold(fqdnName, sanitizedZone) {
			return "@"
		}
		suffix := "." + sanitizedZone
		if strings.HasSuffix(strings.ToLower(fqdnName), strings.ToLower(suffix)) {
			return strings.TrimSuffix(fqdnName[:len(fqdnName)-len(suffix)], ".")
		}
	}
	return name
}
