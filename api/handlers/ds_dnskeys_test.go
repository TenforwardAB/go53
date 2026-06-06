package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/miekg/dns"

	"go53/distributed"
	"go53/security"
)

func TestDSHandlerHelpersAndDeleteSignals(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/ds/example.test?digest=1,2,bad,999", nil)
	got := digestTypesFromQuery(req)
	if len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("digestTypesFromQuery = %#v", got)
	}
	if got := digestTypesFromQuery(httptest.NewRequest(http.MethodGet, "/api/ds/example.test?digest=bad", nil)); len(got) != 1 || got[0] != dns.SHA256 {
		t.Fatalf("default digestTypesFromQuery = %#v", got)
	}
	if !deleteSignal(httptest.NewRequest(http.MethodGet, "/api/cds/example.test?delete=yes", nil)) {
		t.Fatalf("deleteSignal did not accept yes")
	}
	if ttl := ttlFromQuery(httptest.NewRequest(http.MethodGet, "/api/cds/example.test?ttl=7200", nil)); ttl != 7200 {
		t.Fatalf("ttlFromQuery = %d", ttl)
	}
	if ttl := ttlFromQuery(httptest.NewRequest(http.MethodGet, "/api/cds/example.test?ttl=bad", nil)); ttl != 3600 {
		t.Fatalf("ttlFromQuery default = %d", ttl)
	}

	rec := httptest.NewRecorder()
	writeRRList(rec, []dns.RR{
		security.DeleteDSCDS("example.test.", 300),
		security.DeleteDSCDNSKEY("example.test.", 300),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("writeRRList status = %d", rec.Code)
	}
	var body []map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode writeRRList: %v", err)
	}
	if len(body) != 2 || body[0]["type"] != "CDS" || body[1]["type"] != "CDNSKEY" {
		t.Fatalf("writeRRList body = %#v", body)
	}
}

func TestDSHandlersMissingZoneAndDeleteResponses(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"DS":      GetDSHandler,
		"CDS":     GetCDSHandler,
		"CDNSKEY": GetCDNSKEYHandler,
	} {
		t.Run(name+" missing zone", func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler(rec, httptest.NewRequest(http.MethodGet, "/api", nil))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d", rec.Code)
			}
		})
	}

	cdsReq := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/api/cds/example.test?delete=true&ttl=600", nil), map[string]string{"zone": "example.test."})
	cdsRec := httptest.NewRecorder()
	GetCDSHandler(cdsRec, cdsReq)
	if cdsRec.Code != http.StatusOK {
		t.Fatalf("GetCDSHandler delete status = %d", cdsRec.Code)
	}

	cdnskeyReq := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/api/cdnskey/example.test?delete=1&ttl=600", nil), map[string]string{"zone": "example.test."})
	cdnskeyRec := httptest.NewRecorder()
	GetCDNSKEYHandler(cdnskeyRec, cdnskeyReq)
	if cdnskeyRec.Code != http.StatusOK {
		t.Fatalf("GetCDNSKEYHandler delete status = %d", cdnskeyRec.Code)
	}
}

func TestDNSKeyHandlerHelpers(t *testing.T) {
	if got := removeAfter(httptest.NewRequest(http.MethodPost, "/api/dnskeys/key/retire?remove_after_days=7", nil)); got != 7*24*time.Hour {
		t.Fatalf("removeAfter = %v", got)
	}
	if got := removeAfter(httptest.NewRequest(http.MethodPost, "/api/dnskeys/key/retire?remove_after_days=bad", nil)); got != 30*24*time.Hour {
		t.Fatalf("removeAfter default = %v", got)
	}

	setupHandlerTestStore(t)
	rec := httptest.NewRecorder()
	ListDNSKeysHandler(rec, httptest.NewRequest(http.MethodGet, "/api/dnskeys", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("ListDNSKeysHandler status = %d body=%q", rec.Code, rec.Body.String())
	}
	getReq := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/api/dnskeys/example.test", nil), map[string]string{"keyid": "example.test"})
	getRec := httptest.NewRecorder()
	GetDNSKeyHandler(getRec, getReq)
	if getRec.Code != http.StatusNotFound {
		t.Fatalf("GetDNSKeyHandler empty status = %d", getRec.Code)
	}
}

func TestDNSKeyLifecycleHandlers(t *testing.T) {
	setupHandlerTestStore(t)
	distributed.Default = nil
	t.Cleanup(func() { distributed.Default = nil })

	createReq := httptest.NewRequest(http.MethodPost, "/api/dnskeys/rollover", strings.NewReader(`{"zone":"handler.test.","role":"ksk","algorithm":"ED25519"}`))
	createRec := httptest.NewRecorder()
	CreateRolloverDNSKeyHandler(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("CreateRolloverDNSKeyHandler status = %d body=%q", createRec.Code, createRec.Body.String())
	}
	var created struct {
		KeyID string `json:"keyid"`
	}
	if err := json.NewDecoder(createRec.Body).Decode(&created); err != nil {
		t.Fatalf("decode created key: %v", err)
	}
	if created.KeyID == "" {
		t.Fatalf("created keyid is empty")
	}

	updateReq := mux.SetURLVars(httptest.NewRequest(http.MethodPatch, "/api/dnskeys/"+created.KeyID, strings.NewReader(`{"state":"active"}`)), map[string]string{"keyid": created.KeyID})
	updateRec := httptest.NewRecorder()
	UpdateDNSKeyLifecycleHandler(updateRec, updateReq)
	if updateRec.Code != http.StatusOK {
		t.Fatalf("UpdateDNSKeyLifecycleHandler status = %d body=%q", updateRec.Code, updateRec.Body.String())
	}

	retireReq := mux.SetURLVars(httptest.NewRequest(http.MethodPost, "/api/dnskeys/"+created.KeyID+"/retire?remove_after_days=1", nil), map[string]string{"keyid": created.KeyID})
	retireRec := httptest.NewRecorder()
	RetireDNSKeyHandler(retireRec, retireReq)
	if retireRec.Code != http.StatusOK {
		t.Fatalf("RetireDNSKeyHandler status = %d body=%q", retireRec.Code, retireRec.Body.String())
	}

	revokeReq := mux.SetURLVars(httptest.NewRequest(http.MethodPost, "/api/dnskeys/"+created.KeyID+"/revoke?remove_after_days=1", nil), map[string]string{"keyid": created.KeyID})
	revokeRec := httptest.NewRecorder()
	RevokeDNSKeyHandler(revokeRec, revokeReq)
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("RevokeDNSKeyHandler status = %d body=%q", revokeRec.Code, revokeRec.Body.String())
	}

	getReq := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/api/dnskeys/handler.test", nil), map[string]string{"keyid": "handler.test"})
	getRec := httptest.NewRecorder()
	GetDNSKeyHandler(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GetDNSKeyHandler status = %d body=%q", getRec.Code, getRec.Body.String())
	}

	deleteReq := mux.SetURLVars(httptest.NewRequest(http.MethodDelete, "/api/dnskeys/"+created.KeyID, nil), map[string]string{"keyid": created.KeyID})
	deleteRec := httptest.NewRecorder()
	DeleteDNSKeyHandler(deleteRec, deleteReq)
	if deleteRec.Code != http.StatusNoContent {
		t.Fatalf("DeleteDNSKeyHandler status = %d body=%q", deleteRec.Code, deleteRec.Body.String())
	}
}
