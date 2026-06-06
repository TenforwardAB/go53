package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	"go53/config"
	"go53/distributed"
	"go53/zone/rtypes"
)

func TestDistributedHandlersWithInitializedService(t *testing.T) {
	setupHandlerTestStore(t)
	priv, pub, err := distributed.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	config.AppConfig.Live.Mode = "distributed"
	config.AppConfig.Live.Version = "test-version"
	config.AppConfig.Live.Distributed.NodeID = "node-a"
	config.AppConfig.Live.Distributed.PrivateKey = priv
	config.AppConfig.Live.Distributed.PeerPublicKeys = map[string]string{"node-a": pub}
	config.AppConfig.Live.Distributed.SyncBindHost = "127.0.0.1"
	config.AppConfig.Live.Distributed.SyncPort = ":53530"
	mem := rtypes.GetMemStore()
	distributed.Init(mem)
	t.Cleanup(func() { distributed.Default = nil })

	if err := mem.PutRecordRaw("example.test.", "A", "www", []any{map[string]any{"ip": "192.0.2.1", "ttl": float64(300)}}); err != nil {
		t.Fatalf("PutRecordRaw: %v", err)
	}
	if err := distributed.Default.PublishUpsert("example.test.", "A", "www", []any{map[string]any{"ip": "192.0.2.1", "ttl": float64(300)}}); err != nil {
		t.Fatalf("PublishUpsert: %v", err)
	}

	for name, handler := range map[string]http.HandlerFunc{
		"status":     GetDistributedStatusHandler,
		"well-known": GetWellKnownNodeHandler,
		"keys":       GenerateDistributedKeyPairHandler,
		"vector":     GetDistributedVectorHandler,
		"events":     GetDistributedEventsHandler,
		"roots":      GetDistributedMerkleRootsHandler,
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler(rec, httptest.NewRequest(http.MethodGet, "/api/distributed", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("%s status = %d body=%q", name, rec.Code, rec.Body.String())
			}
			var decoded any
			if err := json.NewDecoder(rec.Body).Decode(&decoded); err != nil {
				t.Fatalf("%s did not return JSON: %v", name, err)
			}
		})
	}

	branchesRec := httptest.NewRecorder()
	GetDistributedMerkleBranchesHandler(branchesRec, httptest.NewRequest(http.MethodGet, "/api/distributed/merkle/branches?zone=example.test.", nil))
	if branchesRec.Code != http.StatusOK {
		t.Fatalf("branches status = %d body=%q", branchesRec.Code, branchesRec.Body.String())
	}
	missingBranchesRec := httptest.NewRecorder()
	GetDistributedMerkleBranchesHandler(missingBranchesRec, httptest.NewRequest(http.MethodGet, "/api/distributed/merkle/branches", nil))
	if missingBranchesRec.Code != http.StatusBadRequest {
		t.Fatalf("missing branches status = %d", missingBranchesRec.Code)
	}

	leavesReq := httptest.NewRequest(http.MethodPost, "/api/distributed/merkle/leaves", strings.NewReader(`{"zone":"example.test.","prefixes":[]}`))
	leavesRec := httptest.NewRecorder()
	PostDistributedMerkleLeavesHandler(leavesRec, leavesReq)
	if leavesRec.Code != http.StatusOK {
		t.Fatalf("leaves status = %d body=%q", leavesRec.Code, leavesRec.Body.String())
	}
	badLeavesRec := httptest.NewRecorder()
	PostDistributedMerkleLeavesHandler(badLeavesRec, httptest.NewRequest(http.MethodPost, "/api/distributed/merkle/leaves", strings.NewReader(`{"prefixes":[]}`)))
	if badLeavesRec.Code != http.StatusBadRequest {
		t.Fatalf("bad leaves status = %d", badLeavesRec.Code)
	}

	repairReq := httptest.NewRequest(http.MethodPost, "/api/distributed/merkle/repair-events", strings.NewReader(`{"entities":["example.test.|A|www"]}`))
	repairRec := httptest.NewRecorder()
	PostDistributedMerkleRepairEventsHandler(repairRec, repairReq)
	if repairRec.Code != http.StatusOK {
		t.Fatalf("repair status = %d body=%q", repairRec.Code, repairRec.Body.String())
	}

	inviteReq := httptest.NewRequest(http.MethodPost, "/api/distributed/invites", strings.NewReader(`{"jti":"invite-1","usage_count":1}`))
	inviteRec := httptest.NewRecorder()
	PostDistributedInviteHandler(inviteRec, inviteReq)
	if inviteRec.Code != http.StatusNoContent {
		t.Fatalf("invite save status = %d body=%q", inviteRec.Code, inviteRec.Body.String())
	}
	consumeReq := mux.SetURLVars(httptest.NewRequest(http.MethodPost, "/api/distributed/invites/invite-1/consume", nil), map[string]string{"jti": "invite-1"})
	consumeRec := httptest.NewRecorder()
	PostDistributedInviteConsumeHandler(consumeRec, consumeReq)
	if consumeRec.Code != http.StatusOK {
		t.Fatalf("invite consume status = %d body=%q", consumeRec.Code, consumeRec.Body.String())
	}

	badEventRec := httptest.NewRecorder()
	PostDistributedEventHandler(badEventRec, httptest.NewRequest(http.MethodPost, "/api/distributed/events?resync=true", strings.NewReader(`{`)))
	if badEventRec.Code != http.StatusBadRequest {
		t.Fatalf("bad event status = %d", badEventRec.Code)
	}
}

func TestDistributedHandlersServiceUnavailable(t *testing.T) {
	distributed.Default = nil
	t.Cleanup(func() { distributed.Default = nil })
	for name, handler := range map[string]http.HandlerFunc{
		"well-known": GetWellKnownNodeHandler,
		"events":     GetDistributedEventsHandler,
		"roots":      GetDistributedMerkleRootsHandler,
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler(rec, httptest.NewRequest(http.MethodGet, "/api/distributed", nil))
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("%s status = %d", name, rec.Code)
			}
		})
	}
}
