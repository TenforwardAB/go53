package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/miekg/dns"

	"go53/config"
	"go53/distributed"
	"go53/dns/dnsutils"
	"go53/internal"
	"go53/security"
	"go53/wal"
	"go53/zone"
	"go53/zone/rtypes"
	"go53/zonemeta"
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

type recordListItem struct {
	Zone    string `json:"zone"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Records any    `json:"records"`
}

type pageResult struct {
	Items  any `json:"items"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
	Total  int `json:"total"`
}

// POST /api/zones/{zone}/records/{rrtype}
func AddRecordHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	zoneName := vars["zone"]
	rrtypeStr := vars["rrtype"]
	if rejectReadOnlyZone(w, zoneName) {
		return
	}

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
	if err := appendWALRecord(wal.OpUpsert, zoneName, rrtypeStr, req.name, req.value); err != nil {
		http.Error(w, "record stored but WAL append failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := afterRecordUpsert(zoneName, rrtypeStr, rrtype, req.name, req.value); err != nil {
		http.Error(w, "record stored but distributed event failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := dnsutils.EnsureCatalogMember(zoneName); err != nil {
		http.Error(w, "record stored but catalog update failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func UpdateRecordHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	zoneName := vars["zone"]
	rrtypeStr := vars["rrtype"]
	name := vars["name"]
	if rejectReadOnlyZone(w, zoneName) {
		return
	}

	rrtype, err := internal.RRTypeStringToUint16(rrtypeStr)
	if err != nil {
		http.Error(w, "Unknown RR type", http.StatusBadRequest)
		return
	}
	payload, reqErr := decodeRecordPayload(r.Body)
	if reqErr != nil {
		http.Error(w, reqErr.message, reqErr.status)
		return
	}
	payload["name"] = name
	req, reqErr := newAddRecordRequestFromPayload(zoneName, rrtype, payload)
	if reqErr != nil {
		http.Error(w, reqErr.message, reqErr.status)
		return
	}

	if err := zone.DeleteRecord(rrtype, name, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := zone.AddRecord(rrtype, zoneName, req.name, req.value, req.ttlPtr); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := appendWALRecord(wal.OpUpsert, zoneName, rrtypeStr, req.name, req.value); err != nil {
		http.Error(w, "record updated but WAL append failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := afterRecordUpsert(zoneName, rrtypeStr, rrtype, req.name, req.value); err != nil {
		http.Error(w, "record updated but distributed event failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func newAddRecordRequest(body io.Reader, zoneName string, rrtype uint16) (addRecordRequest, *addRecordError) {
	payload, err := decodeRecordPayload(body)
	if err != nil {
		return addRecordRequest{}, err
	}
	return newAddRecordRequestFromPayload(zoneName, rrtype, payload)
}

func newAddRecordRequestFromPayload(zoneName string, rrtype uint16, payload map[string]interface{}) (addRecordRequest, *addRecordError) {
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

func afterRecordUpsert(zoneName, rrtypeStr string, rrtype uint16, name string, payload map[string]interface{}) error {
	if rrtype != dns.TypeSOA {
		updateSOAAfterRecordChange(zoneName)
	}
	if err := publishDistributedUpsert(zoneName, rrtypeStr, name, payload); err != nil {
		return err
	}
	if rrtype == dns.TypeSOA {
		return nil
	}
	return publishDistributedUpsert(zoneName, "SOA", "@", map[string]interface{}{})
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

func ListZoneRecordsHandler(w http.ResponseWriter, r *http.Request) {
	writeZoneRecords(w, r, "")
}

func ListZoneRecordsByTypeHandler(w http.ResponseWriter, r *http.Request) {
	rrtypeStr := mux.Vars(r)["rrtype"]
	if _, err := internal.RRTypeStringToUint16(rrtypeStr); err != nil {
		http.Error(w, "Unknown RR type", http.StatusBadRequest)
		return
	}
	writeZoneRecords(w, r, strings.ToUpper(rrtypeStr))
}

func writeZoneRecords(w http.ResponseWriter, r *http.Request, onlyType string) {
	zoneName, err := internal.SanitizeFQDN(mux.Vars(r)["zone"])
	if err != nil {
		http.Error(w, "invalid zone", http.StatusBadRequest)
		return
	}
	store := rtypes.GetMemStore()
	if store == nil {
		http.Error(w, "memory store is not initialized", http.StatusInternalServerError)
		return
	}
	if !zoneExists(store.ZoneNamesSnapshot(), zoneName) {
		http.Error(w, "zone not found", http.StatusNotFound)
		return
	}
	items := flattenZoneRecords(zoneName, store.ZoneRecordsSnapshot(zoneName), onlyType)
	limit, offset := pageParams(r)
	writeJSON(w, pageResult{
		Items:  pageSlice(items, limit, offset),
		Limit:  limit,
		Offset: offset,
		Total:  len(items),
	})
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
	if rejectReadOnlyZone(w, zoneName) {
		return
	}

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
	if err := appendWALRecord(wal.OpDelete, zoneName, rrtypeStr, name, nil); err != nil {
		http.Error(w, "record deleted but WAL append failed: "+err.Error(), http.StatusInternalServerError)
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
		if err := publishDistributedUpsert(zoneName, "SOA", "@", map[string]interface{}{}); err != nil {
			http.Error(w, "record deleted but distributed SOA event failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// GET
func GetZonesHandler(w http.ResponseWriter, r *http.Request) {
	store := rtypes.GetMemStore()
	if store == nil {
		http.Error(w, "memory store is not initialized", http.StatusInternalServerError)
		return
	}
	zones := store.ZoneNamesSnapshot()
	limit, offset := pageParams(r)
	writeJSON(w, pageResult{
		Items:  pageSlice(zones, limit, offset),
		Limit:  limit,
		Offset: offset,
		Total:  len(zones),
	})
}

func DeleteZoneHandler(w http.ResponseWriter, r *http.Request) {
	zoneName, err := internal.SanitizeFQDN(mux.Vars(r)["zone"])
	if err != nil {
		http.Error(w, "invalid zone", http.StatusBadRequest)
		return
	}
	if rejectReadOnlyZone(w, zoneName) {
		return
	}

	// Snapshot the zone's records before deleting so the deletion can be
	// replicated: a per-record delete for each (repair-safe tombstone) plus a
	// zone-level delete event that clears the empty zone shell on peers.
	var snapshot map[string]map[string]any
	if store := rtypes.GetMemStore(); store != nil {
		snapshot = store.ZoneRecordsSnapshot(zoneName)
	}

	if err := zone.DeleteZone(zoneName); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := wal.Append(wal.KindZone, wal.OpDelete, zoneName, "", "", "", "", nil); err != nil {
		http.Error(w, "zone deleted but WAL append failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := publishDistributedZoneDelete(zoneName, snapshot); err != nil {
		http.Error(w, "zone deleted but distributed event failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// publishDistributedZoneDelete replicates a whole-zone deletion. It first emits a
// per-record delete for every record (those are the repair-safe tombstones that
// stop Merkle anti-entropy from pulling records back from peers), then a single
// zone-level delete event that removes the now-empty zone shell on peers.
func publishDistributedZoneDelete(zoneName string, snapshot map[string]map[string]any) error {
	if distributed.Default == nil || !distributed.Enabled() {
		return nil
	}
	for rrtype, names := range snapshot {
		for name := range names {
			if err := distributed.Default.PublishDelete(zoneName, strings.ToUpper(rrtype), name); err != nil {
				return err
			}
		}
	}
	return distributed.Default.PublishZoneDelete(zoneName)
}

func TriggerSecondaryFetchHandler(w http.ResponseWriter, r *http.Request) {
	if config.AppConfig.GetLive().Mode != "secondary" {
		http.Error(w, "secondary fetch is only available in secondary mode", http.StatusConflict)
		return
	}
	zoneName, err := internal.SanitizeFQDN(mux.Vars(r)["zone"])
	if err != nil {
		http.Error(w, "invalid zone", http.StatusBadRequest)
		return
	}
	if !dnsutils.EnqueueZoneFetch(zoneName) {
		http.Error(w, "fetch already pending, rate-limited, or queue full", http.StatusTooManyRequests)
		return
	}
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"zone": zoneName, "status": "queued"})
}

func TriggerNotifyHandler(w http.ResponseWriter, r *http.Request) {
	zoneName, err := internal.SanitizeFQDN(mux.Vars(r)["zone"])
	if err != nil {
		http.Error(w, "invalid zone", http.StatusBadRequest)
		return
	}
	dnsutils.ScheduleNotify(zoneName)
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"zone": zoneName, "status": "scheduled"})
}

func GetCatalogStatusHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, dnsutils.CatalogStatus())
}

func GetCatalogMembersHandler(w http.ResponseWriter, r *http.Request) {
	members := dnsutils.CatalogMembers()
	limit, offset := pageParams(r)
	writeJSON(w, pageResult{
		Items:  pageSlice(members, limit, offset),
		Limit:  limit,
		Offset: offset,
		Total:  len(members),
	})
}

func ExportZoneHandler(w http.ResponseWriter, r *http.Request) {
	zoneName, err := internal.SanitizeFQDN(mux.Vars(r)["zone"])
	if err != nil {
		http.Error(w, "invalid zone", http.StatusBadRequest)
		return
	}
	rrs, ok := zone.LookupRecord(dns.TypeAXFR, zoneName)
	if !ok {
		http.Error(w, "zone not found", http.StatusNotFound)
		return
	}
	if len(rrs) > 1 && rrs[0].String() == rrs[len(rrs)-1].String() {
		rrs = rrs[:len(rrs)-1]
	}
	w.Header().Set("Content-Type", "text/dns; charset=utf-8")
	for _, rr := range rrs {
		_, _ = io.WriteString(w, rr.String()+"\n")
	}
}

func ImportZoneHandler(w http.ResponseWriter, r *http.Request) {
	zoneName, err := internal.SanitizeFQDN(mux.Vars(r)["zone"])
	if err != nil {
		http.Error(w, "invalid zone", http.StatusBadRequest)
		return
	}
	dnssecMode := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("dnssec")))
	if dnssecMode == "" {
		dnssecMode = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("dnssec_mode")))
	}
	if dnssecMode != "" && dnssecMode != "preserve" {
		http.Error(w, "unsupported dnssec import mode", http.StatusBadRequest)
		return
	}
	if dnssecMode != "preserve" && rejectReadOnlyZone(w, zoneName) {
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 10<<20))
	if err != nil {
		http.Error(w, "failed to read zone file: "+err.Error(), http.StatusBadRequest)
		return
	}
	parser := dns.NewZoneParser(strings.NewReader(string(body)), zoneName, "")
	records := []dns.RR{}
	hasSOA := false
	for rr, ok := parser.Next(); ok; rr, ok = parser.Next() {
		if rr.Header().Rrtype == dns.TypeSOA {
			hasSOA = true
		}
		records = append(records, rr)
	}
	if err := parser.Err(); err != nil {
		http.Error(w, "invalid zone file: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !hasSOA {
		http.Error(w, "zone file must contain an SOA record", http.StatusBadRequest)
		return
	}
	if err := dnsutils.ImportRecords("", zoneName, records); err != nil {
		http.Error(w, "zone import failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := wal.Append(wal.KindZone, wal.OpImport, zoneName, "", "", "", "", body); err != nil {
		http.Error(w, "zone imported but WAL append failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if dnssecMode == "preserve" {
		if err := zonemeta.SetPreserveReadOnly(zoneName, len(records)); err != nil {
			http.Error(w, "zone imported but read-only metadata failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if err := dnsutils.EnsureCatalogMember(zoneName); err != nil {
		http.Error(w, "zone imported but catalog update failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if config.AppConfig.GetLive().Mode != "secondary" {
		go dnsutils.ScheduleNotify(zoneName)
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"zone": zoneName, "records": len(records), "dnssec_mode": dnssecMode})
}

func rejectReadOnlyZone(w http.ResponseWriter, zoneName string) bool {
	meta, readOnly := zonemeta.ReadOnly(zoneName)
	if !readOnly {
		return false
	}
	http.Error(w, "zone is read-only: "+meta.ReadOnlyReason, http.StatusConflict)
	return true
}

func publishDistributedUpsert(zoneName, rrtypeStr, name string, payload map[string]interface{}) error {
	if distributed.Default == nil || !distributed.Enabled() {
		return nil
	}
	mem := rtypes.GetMemStore()
	if mem == nil {
		return fmt.Errorf("memory store is not initialized")
	}
	// Storage and Merkle keys use the FQDN-sanitized zone (trailing dot), but the
	// HTTP layer hands us the raw URL segment (no trailing dot). Canonicalize
	// before touching the store or emitting the event, otherwise the read-back
	// misses ("stored record not found after add") and the replicated event is
	// keyed under a zone that peers store/tombstone inconsistently.
	if sz, err := internal.SanitizeFQDN(zoneName); err == nil {
		zoneName = sz
	}
	recordName := canonicalRecordName(zoneName, rrtypeStr, name)
	if strings.EqualFold(rrtypeStr, "RRSIG") {
		covered, _ := payload["type_covered"].(string)
		recordName = strings.ToUpper(strings.TrimSpace(covered))
	}
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
	// Match the storage/Merkle zone key (FQDN) so the delete tombstone lines up
	// with the record it removes; otherwise Merkle anti-entropy resurrects it.
	if sz, err := internal.SanitizeFQDN(zoneName); err == nil {
		zoneName = sz
	}
	return distributed.Default.PublishDelete(zoneName, strings.ToUpper(rrtypeStr), canonicalRecordName(zoneName, rrtypeStr, name))
}

func appendWALRecord(op, zoneName, rrtypeStr, name string, value any) error {
	var raw []byte
	var err error
	if value != nil {
		raw, err = json.Marshal(value)
		if err != nil {
			return err
		}
	}
	_, err = wal.Append(wal.KindZoneRecord, op, zoneName, rrtypeStr, name, "", "", raw)
	return err
}

func pageParams(r *http.Request) (int, int) {
	limit := intQuery(r, "limit", 100)
	offset := intQuery(r, "offset", 0)
	if limit < 1 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func intQuery(r *http.Request, key string, fallback int) int {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func pageSlice[T any](items []T, limit, offset int) []T {
	if offset >= len(items) {
		return []T{}
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	return items[offset:end]
}

func flattenZoneRecords(zoneName string, snapshot map[string]map[string]any, onlyType string) []recordListItem {
	types := make([]string, 0, len(snapshot))
	for rrtype := range snapshot {
		if onlyType == "" || strings.EqualFold(rrtype, onlyType) {
			types = append(types, rrtype)
		}
	}
	sort.Strings(types)
	items := []recordListItem{}
	for _, rrtype := range types {
		names := make([]string, 0, len(snapshot[rrtype]))
		for name := range snapshot[rrtype] {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			items = append(items, recordListItem{
				Zone:    zoneName,
				Type:    rrtype,
				Name:    name,
				Records: snapshot[rrtype][name],
			})
		}
	}
	return items
}

func zoneExists(zones []string, zoneName string) bool {
	for _, z := range zones {
		if strings.EqualFold(z, zoneName) {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
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
