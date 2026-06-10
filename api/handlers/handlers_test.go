package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/miekg/dns"

	"go53/config"
	"go53/distributed"
	"go53/memory"
	"go53/security"
	"go53/storage"
	"go53/types"
	"go53/zone/rtypes"
	"go53/zonemeta"
)

func TestRecordRequestParsing(t *testing.T) {
	req, err := newAddRecordRequest(strings.NewReader(`{"name":"www","ip":"192.0.2.1","ttl":300}`), "example.test.", dns.TypeA)
	if err != nil {
		t.Fatalf("newAddRecordRequest A: %v", err)
	}
	if req.name != "www" || req.ttlPtr == nil || *req.ttlPtr != 300 {
		t.Fatalf("unexpected A request: %#v", req)
	}
	if _, ok := req.value["name"]; ok {
		t.Fatalf("name was not removed from record value")
	}
	if _, ok := req.value["ttl"]; ok {
		t.Fatalf("ttl was not removed from record value")
	}

	soa, err := newAddRecordRequest(strings.NewReader(`{"mname":"ns1.example.test.","rname":"hostmaster.example.test."}`), "example.test.", dns.TypeSOA)
	if err != nil {
		t.Fatalf("newAddRecordRequest SOA: %v", err)
	}
	if soa.name != "example.test." {
		t.Fatalf("SOA name = %q, want zone apex", soa.name)
	}

	if _, err := newAddRecordRequest(strings.NewReader(`{"ip":"192.0.2.1"}`), "example.test.", dns.TypeA); err == nil || err.status != http.StatusBadRequest {
		t.Fatalf("missing name error = %#v, want bad request", err)
	}
	if _, err := newAddRecordRequest(strings.NewReader(`{"name":"www","ttl":"bad"}`), "example.test.", dns.TypeA); err == nil || err.message != "Field 'ttl' must be a number" {
		t.Fatalf("bad ttl error = %#v", err)
	}
	if _, err := decodeRecordPayload(strings.NewReader(`{`)); err == nil {
		t.Fatalf("invalid JSON decoded successfully")
	}
}

func TestConfigHandlers(t *testing.T) {
	setupHandlerTestStore(t)
	distributed.Default = nil
	t.Cleanup(func() { distributed.Default = nil })

	updateReq := httptest.NewRequest(http.MethodPatch, "/api/config", strings.NewReader(`{"mode":"secondary","default_ttl":123}`))
	updateRec := httptest.NewRecorder()
	UpdateLiveConfigHandler(updateRec, updateReq)
	if updateRec.Code != http.StatusNoContent {
		t.Fatalf("UpdateLiveConfigHandler status = %d body=%q", updateRec.Code, updateRec.Body.String())
	}
	live := config.AppConfig.GetLive()
	if live.Mode != "secondary" || live.DefaultTTL != 123 {
		t.Fatalf("live config = %#v", live)
	}
	config.AppConfig.Live.Auth.XAuthKey = strings.Repeat("z", 48)

	getReq := httptest.NewRequest(http.MethodGet, "/api/config", nil)
	getRec := httptest.NewRecorder()
	GetLiveConfigHandler(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GetLiveConfigHandler status = %d", getRec.Code)
	}
	var decoded config.LiveConfig
	if err := json.NewDecoder(getRec.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode live config: %v", err)
	}
	if decoded.Mode != "secondary" || decoded.DefaultTTL != 123 {
		t.Fatalf("decoded live config = %#v", decoded)
	}
	if decoded.Auth.XAuthKey != "" {
		t.Fatalf("GetLiveConfigHandler exposed x_auth_key = %q", decoded.Auth.XAuthKey)
	}

	// A present false bool must be applied (a struct-merge would silently drop it).
	if !config.AppConfig.GetLive().EnableEDNS {
		t.Fatalf("precondition: expected enable_edns true by default")
	}
	offReq := httptest.NewRequest(http.MethodPatch, "/api/config", strings.NewReader(`{"enable_edns":false}`))
	offRec := httptest.NewRecorder()
	UpdateLiveConfigHandler(offRec, offReq)
	if offRec.Code != http.StatusNoContent {
		t.Fatalf("disable enable_edns status = %d body=%q", offRec.Code, offRec.Body.String())
	}
	after := config.AppConfig.GetLive()
	if after.EnableEDNS {
		t.Fatalf("expected enable_edns=false after patch")
	}
	// Unrelated fields set earlier must be untouched.
	if after.Mode != "secondary" || after.DefaultTTL != 123 {
		t.Fatalf("patch clobbered unrelated fields: %#v", after)
	}

	badReq := httptest.NewRequest(http.MethodPatch, "/api/config", strings.NewReader(`{`))
	badRec := httptest.NewRecorder()
	UpdateLiveConfigHandler(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("bad config status = %d", badRec.Code)
	}

	keyReq := httptest.NewRequest(http.MethodPatch, "/api/config", strings.NewReader(`{"auth":{"x_auth_key":"`+strings.Repeat("a", 48)+`"}}`))
	keyRec := httptest.NewRecorder()
	UpdateLiveConfigHandler(keyRec, keyReq)
	if keyRec.Code != http.StatusForbidden {
		t.Fatalf("x_auth_key config patch status = %d, want 403", keyRec.Code)
	}
}

func TestImportZonePreserveMarksReadOnly(t *testing.T) {
	setupHandlerTestStore(t)
	zoneText := `preserve.test. 300 IN SOA ns1.preserve.test. hostmaster.preserve.test. 1 3600 600 86400 300
preserve.test. 300 IN NS ns1.preserve.test.
ns1.preserve.test. 300 IN A 192.0.2.53
www.preserve.test. 300 IN A 192.0.2.10
`
	req := httptest.NewRequest(http.MethodPost, "/api/zones/preserve.test./import?dnssec=preserve", strings.NewReader(zoneText))
	req = mux.SetURLVars(req, map[string]string{"zone": "preserve.test."})
	rec := httptest.NewRecorder()
	ImportZoneHandler(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("ImportZoneHandler status = %d body=%q", rec.Code, rec.Body.String())
	}
	meta, readOnly := zonemeta.ReadOnly("preserve.test.")
	if !readOnly || meta.DNSSECMode != "preserve" {
		t.Fatalf("zone meta = %#v readOnly=%v", meta, readOnly)
	}

	addReq := httptest.NewRequest(http.MethodPost, "/api/zones/preserve.test./records/A", strings.NewReader(`{"name":"new","ip":"192.0.2.11"}`))
	addReq = mux.SetURLVars(addReq, map[string]string{"zone": "preserve.test.", "rrtype": "A"})
	addRec := httptest.NewRecorder()
	AddRecordHandler(addRec, addReq)
	if addRec.Code != http.StatusConflict {
		t.Fatalf("AddRecordHandler status = %d body=%q", addRec.Code, addRec.Body.String())
	}
}

func TestTSIGHandlersLifecycle(t *testing.T) {
	setupHandlerTestStore(t)
	distributed.Default = nil
	security.TSIGSecrets = map[string]security.TSIGKey{}
	t.Cleanup(func() {
		distributed.Default = nil
		security.TSIGSecrets = nil
	})

	addReq := httptest.NewRequest(http.MethodPost, "/api/tsig/xfr-key", strings.NewReader(`{"algorithm":"hmac-sha256.","secret":"YWJjMTIz"}`))
	addReq = mux.SetURLVars(addReq, map[string]string{"name": "xfr-key"})
	addRec := httptest.NewRecorder()
	AddTSIGKeyHandler(addRec, addReq)
	if addRec.Code != http.StatusCreated {
		t.Fatalf("AddTSIGKeyHandler status = %d body=%q", addRec.Code, addRec.Body.String())
	}
	if key, ok := security.GetTSIGKey("xfr-key."); !ok || key.Secret != "YWJjMTIz" {
		t.Fatalf("TSIG cache after add = %#v ok=%v", key, ok)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/tsig", nil)
	listRec := httptest.NewRecorder()
	ListTSIGKeysHandler(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("ListTSIGKeysHandler status = %d", listRec.Code)
	}
	var listed []map[string]string
	if err := json.NewDecoder(listRec.Body).Decode(&listed); err != nil {
		t.Fatalf("decode TSIG list: %v", err)
	}
	if len(listed) != 1 || listed[0]["name"] != "xfr-key." {
		t.Fatalf("listed TSIG keys = %#v", listed)
	}

	delReq := httptest.NewRequest(http.MethodDelete, "/api/tsig/xfr-key", nil)
	delReq = mux.SetURLVars(delReq, map[string]string{"name": "xfr-key"})
	delRec := httptest.NewRecorder()
	DeleteTSIGKeyHandler(delRec, delReq)
	if delRec.Code != http.StatusNoContent {
		t.Fatalf("DeleteTSIGKeyHandler status = %d body=%q", delRec.Code, delRec.Body.String())
	}
	if _, ok := security.GetTSIGKey("xfr-key."); ok {
		t.Fatalf("TSIG key remained after delete")
	}
}

func TestZoneHandlersBasicResponses(t *testing.T) {
	setupHandlerTestStore(t)
	distributed.Default = nil
	t.Cleanup(func() { distributed.Default = nil })

	addReq := httptest.NewRequest(http.MethodPost, "/api/zones/example.test./records/A", strings.NewReader(`{"name":"www","ip":"192.0.2.5","ttl":120}`))
	addReq = mux.SetURLVars(addReq, map[string]string{"zone": "example.test.", "rrtype": "A"})
	addRec := httptest.NewRecorder()
	AddRecordHandler(addRec, addReq)
	if addRec.Code != http.StatusCreated {
		t.Fatalf("AddRecordHandler status = %d body=%q", addRec.Code, addRec.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/zones/example.test./records/A/www.example.test.", nil)
	getReq = mux.SetURLVars(getReq, map[string]string{"zone": "example.test.", "rrtype": "A", "name": "www.example.test."})
	getRec := httptest.NewRecorder()
	GetRecordHandler(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GetRecordHandler status = %d body=%q", getRec.Code, getRec.Body.String())
	}

	zonesReq := httptest.NewRequest(http.MethodGet, "/api/zones", nil)
	zonesRec := httptest.NewRecorder()
	GetZonesHandler(zonesRec, zonesReq)
	if zonesRec.Code != http.StatusOK {
		t.Fatalf("GetZonesHandler status = %d body=%q", zonesRec.Code, zonesRec.Body.String())
	}

	badReq := httptest.NewRequest(http.MethodPost, "/api/zones/example.test./records/NOPE", strings.NewReader(`{}`))
	badReq = mux.SetURLVars(badReq, map[string]string{"zone": "example.test.", "rrtype": "NOPE"})
	badRec := httptest.NewRecorder()
	AddRecordHandler(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("unknown RR type status = %d", badRec.Code)
	}
}

func TestZoneManagementHandlers(t *testing.T) {
	setupHandlerTestStore(t)
	distributed.Default = nil
	t.Cleanup(func() { distributed.Default = nil })

	addTestRecord(t, "manage.test.", "SOA", `{"ttl":300,"ns":"ns1.manage.test.","mbox":"hostmaster.manage.test.","refresh":3600,"retry":600,"expire":86400,"minimum":300}`)
	addTestRecord(t, "manage.test.", "A", `{"name":"www","ip":"192.0.2.5","ttl":120}`)

	listReq := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/api/zones/manage.test./records?limit=1", nil), map[string]string{"zone": "manage.test."})
	listRec := httptest.NewRecorder()
	ListZoneRecordsHandler(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("ListZoneRecordsHandler status = %d body=%q", listRec.Code, listRec.Body.String())
	}

	typeReq := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/api/zones/manage.test./records/A", nil), map[string]string{"zone": "manage.test.", "rrtype": "A"})
	typeRec := httptest.NewRecorder()
	ListZoneRecordsByTypeHandler(typeRec, typeReq)
	if typeRec.Code != http.StatusOK || !strings.Contains(typeRec.Body.String(), `"type":"A"`) {
		t.Fatalf("ListZoneRecordsByTypeHandler status = %d body=%q", typeRec.Code, typeRec.Body.String())
	}

	updateReq := mux.SetURLVars(httptest.NewRequest(http.MethodPatch, "/api/zones/manage.test./records/A/www.manage.test.", strings.NewReader(`{"ip":"192.0.2.6","ttl":120}`)), map[string]string{"zone": "manage.test.", "rrtype": "A", "name": "www.manage.test."})
	updateRec := httptest.NewRecorder()
	UpdateRecordHandler(updateRec, updateReq)
	if updateRec.Code != http.StatusNoContent {
		t.Fatalf("UpdateRecordHandler status = %d body=%q", updateRec.Code, updateRec.Body.String())
	}

	exportReq := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/api/zones/manage.test./export", nil), map[string]string{"zone": "manage.test."})
	exportRec := httptest.NewRecorder()
	ExportZoneHandler(exportRec, exportReq)
	if exportRec.Code != http.StatusOK || !strings.Contains(exportRec.Body.String(), "SOA") {
		t.Fatalf("ExportZoneHandler status = %d body=%q", exportRec.Code, exportRec.Body.String())
	}

	deleteReq := mux.SetURLVars(httptest.NewRequest(http.MethodDelete, "/api/zones/manage.test.", nil), map[string]string{"zone": "manage.test."})
	deleteRec := httptest.NewRecorder()
	DeleteZoneHandler(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusNoContent {
		t.Fatalf("DeleteZoneHandler status = %d body=%q", deleteRec.Code, deleteRec.Body.String())
	}
}

func addTestRecord(t *testing.T, zoneName, rrtype, body string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/zones/"+zoneName+"/records/"+rrtype, strings.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"zone": zoneName, "rrtype": rrtype})
	rec := httptest.NewRecorder()
	AddRecordHandler(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("AddRecordHandler %s status = %d body=%q", rrtype, rec.Code, rec.Body.String())
	}
}

func TestAddRecordUpdatesCatalogZone(t *testing.T) {
	setupHandlerTestStore(t)
	config.AppConfig.Live.Mode = "primary"
	config.AppConfig.Live.Secondary.CatalogEnabled = true
	config.AppConfig.Live.Secondary.CatalogZone = "_catalog.go53."
	distributed.Default = nil
	t.Cleanup(func() { distributed.Default = nil })

	addReq := httptest.NewRequest(http.MethodPost, "/api/zones/member.test./records/SOA", strings.NewReader(`{"ttl":300,"ns":"ns1.member.test.","mbox":"hostmaster.member.test.","refresh":3600,"retry":600,"expire":86400,"minimum":300}`))
	addReq = mux.SetURLVars(addReq, map[string]string{"zone": "member.test.", "rrtype": "SOA"})
	addRec := httptest.NewRecorder()
	AddRecordHandler(addRec, addReq)
	if addRec.Code != http.StatusCreated {
		t.Fatalf("AddRecordHandler status = %d body=%q", addRec.Code, addRec.Body.String())
	}

	store := rtypes.GetMemStore()
	ptrs := store.ZoneRecordsSnapshot("_catalog.go53.")["PTR"]
	found := false
	for _, raw := range ptrs {
		if records, ok := raw.([]types.PTRRecord); ok {
			for _, rec := range records {
				if rec.Ptr == "member.test." {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatalf("catalog member PTR for member.test. not found: %#v", ptrs)
	}
}

func setupHandlerTestStore(t *testing.T) *storage.MockStorage {
	t.Helper()
	backend := &storage.MockStorage{}
	if err := backend.Init(); err != nil {
		t.Fatalf("init mock storage: %v", err)
	}
	storage.Backend = backend
	config.AppConfig = &config.ConfigManager{}
	config.AppConfig.Live = config.DefaultLiveConfig
	config.AppConfig.Live.Mode = "secondary"
	config.AppConfig.Live.DNSSECEnabled = false

	mem, err := memory.NewZoneStore(backend)
	if err != nil {
		t.Fatalf("new memory store: %v", err)
	}
	rtypes.InitMemoryStore(mem)
	return backend
}
