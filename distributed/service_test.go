package distributed

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go53/config"
	"go53/memory"
	"go53/security"
	"go53/storage"
	"go53/types"
	"go53/zone/rtypes"
)

func TestInitSetsDefaultService(t *testing.T) {
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	mock := &storage.MockStorage{}
	if err := mock.Init(); err != nil {
		t.Fatalf("mock init: %v", err)
	}
	storage.Backend = mock
	config.AppConfig.SetLive(config.DefaultLiveConfig)
	config.AppConfig.LiveForTest().Mode = "distributed"
	config.AppConfig.LiveForTest().Distributed.NodeID = "node-init"
	config.AppConfig.LiveForTest().Distributed.PrivateKey = priv
	config.AppConfig.LiveForTest().Distributed.PushTimeoutMs = 25
	mem, err := memory.NewZoneStore(mock)
	if err != nil {
		t.Fatalf("NewZoneStore: %v", err)
	}
	t.Cleanup(func() {
		Default = nil
	})

	svc := Init(mem)
	if svc == nil || Default != svc {
		t.Fatalf("Init did not set Default service")
	}
	if svc.store != mem || svc.storage != mock || svc.client == nil || svc.peerQueues == nil {
		t.Fatalf("initialized service is incomplete: %#v", svc)
	}
}

func TestStartAndPeerWorkersReturnOnCanceledContext(t *testing.T) {
	Start(context.Background())

	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	svc := newTestService(t, "node-a", priv, nil)
	Default = svc
	t.Cleanup(func() {
		Default = nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	Start(ctx)
	svc.SyncAllPeers(ctx)
	svc.StartPeerWorkers(ctx)
}

func TestReceiveSignedEventAppliesRawRecord(t *testing.T) {
	aPriv, aPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair A: %v", err)
	}
	bPriv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair B: %v", err)
	}

	aStore := newTestService(t, "node-a", aPriv, map[string]string{"node-b": ""})
	if err := aStore.PublishUpsert("example.com.", "A", "www", map[string]any{
		"ip":  "192.0.2.10",
		"ttl": float64(300),
	}); err != nil {
		t.Fatalf("PublishUpsert: %v", err)
	}
	events, err := aStore.Events("node-a", 0)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events len = %d, want 1", len(events))
	}

	bService := newTestService(t, "node-b", bPriv, map[string]string{"node-a": aPub})
	applied, err := bService.ReceiveEvent(context.Background(), events[0])
	if err != nil {
		t.Fatalf("ReceiveEvent: %v", err)
	}
	if !applied {
		t.Fatalf("event was not applied")
	}

	_, _, raw, ok := bService.store.GetRecord("example.com.", "A", "www")
	if !ok {
		t.Fatalf("replicated record not found")
	}
	data, _ := json.Marshal(raw)
	if string(data) != `{"ip":"192.0.2.10","ttl":300}` {
		t.Fatalf("raw record = %s", string(data))
	}
	vector, err := bService.Vector()
	if err != nil {
		t.Fatalf("Vector: %v", err)
	}
	if vector["node-a"] != 1 {
		t.Fatalf("vector[node-a] = %d, want 1", vector["node-a"])
	}
}

func TestPublishMetadataEventsAndInviteLifecycle(t *testing.T) {
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	svc := newTestService(t, "node-a", priv, nil)

	if err := svc.PublishConfig([]byte(`{"default_ttl":600}`)); err != nil {
		t.Fatalf("PublishConfig: %v", err)
	}
	if err := svc.PublishTSIGKey("xfr-key.", map[string]any{"algorithm": "hmac-sha256.", "secret": "abc"}); err != nil {
		t.Fatalf("PublishTSIGKey: %v", err)
	}
	if err := svc.PublishTSIGKeyDelete("xfr-key."); err != nil {
		t.Fatalf("PublishTSIGKeyDelete: %v", err)
	}
	if err := svc.PublishDNSSECKey("key-1", types.StoredKey{Zone: "example.test.", Algorithm: "ED25519", PublicKey: "pub"}); err != nil {
		t.Fatalf("PublishDNSSECKey: %v", err)
	}
	if err := svc.PublishDNSSECKeyDelete("key-1"); err != nil {
		t.Fatalf("PublishDNSSECKeyDelete: %v", err)
	}
	if err := svc.PublishDelete("example.test.", "A", "www"); err != nil {
		t.Fatalf("PublishDelete: %v", err)
	}
	events, err := svc.Events("node-a", 0)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	if len(events) != 6 {
		t.Fatalf("events len = %d, want 6", len(events))
	}

	record := InviteRecord{TokenID: "invite-1", UsageCount: 1, ExpiresAt: time.Now().Add(time.Hour).Unix()}
	if err := svc.SaveInvite(record); err != nil {
		t.Fatalf("SaveInvite: %v", err)
	}
	consumed, err := svc.ConsumeInvite("invite-1")
	if err != nil {
		t.Fatalf("ConsumeInvite: %v", err)
	}
	if consumed.UsedCount != 1 || consumed.LastUsedAt == 0 {
		t.Fatalf("consumed invite = %#v", consumed)
	}
	if _, err := svc.ConsumeInvite("invite-1"); err == nil {
		t.Fatalf("ConsumeInvite allowed second use")
	}
	if err := svc.SaveInvite(InviteRecord{TokenID: "bad"}); err == nil {
		t.Fatalf("SaveInvite accepted zero usage count")
	}
}

func TestSubmitJoinRequestStoresPendingAndApproveAddsPinnedPeer(t *testing.T) {
	issuerPriv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair issuer: %v", err)
	}
	joinPriv, joinPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair join: %v", err)
	}
	svc := newTestService(t, "node-a", issuerPriv, map[string]string{"node-a": mustPublicKeyFromPrivate(t, issuerPriv)})
	if err := svc.SaveInvite(InviteRecord{
		TokenID:    "invite-1",
		Token:      "token-1",
		UsageCount: 1,
		ExpiresAt:  time.Now().Add(time.Hour).Unix(),
	}); err != nil {
		t.Fatalf("SaveInvite: %v", err)
	}

	req := JoinRequest{
		TokenID:          "invite-1",
		Token:            "token-1",
		JoinNodeID:       "node-b",
		JoinSyncEndpoint: "tls://10.0.0.11:53530",
		JoinPublicKey:    joinPub,
	}
	priv, err := privateKey(joinPriv)
	if err != nil {
		t.Fatalf("privateKey: %v", err)
	}
	req.Proof = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, JoinRequestPayload(req)))
	applied, err := svc.SubmitJoinRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("SubmitJoinRequest: %v", err)
	}
	if applied {
		t.Fatal("SubmitJoinRequest auto-applied pending request")
	}
	pending, err := svc.ListJoinRequests()
	if err != nil {
		t.Fatalf("ListJoinRequests: %v", err)
	}
	if len(pending) != 1 || pending[0].JoinNodeID != "node-b" {
		t.Fatalf("pending = %#v", pending)
	}
	if _, err := svc.ApproveJoinRequest(context.Background(), "node-b"); err != nil {
		t.Fatalf("ApproveJoinRequest: %v", err)
	}

	live := config.AppConfig.GetLive()
	if live.Distributed.Peers != "tls://10.0.0.11:53530" {
		t.Fatalf("peers = %q", live.Distributed.Peers)
	}
	if live.Distributed.PeerPublicKeys["node-b"] != joinPub {
		t.Fatalf("node-b public key not pinned: %#v", live.Distributed.PeerPublicKeys)
	}
	consumed, err := svc.loadInvite("invite-1")
	if err != nil {
		t.Fatalf("loadInvite: %v", err)
	}
	if consumed.UsedCount != 1 {
		t.Fatalf("UsedCount = %d, want 1", consumed.UsedCount)
	}
	pending, err = svc.ListJoinRequests()
	if err != nil {
		t.Fatalf("ListJoinRequests after approve: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending after approve = %#v", pending)
	}
}

func TestApplyConfigEventAppliesFalseAndProtectsIdentity(t *testing.T) {
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	svc := newTestService(t, "node-a", priv, nil)
	if !config.AppConfig.GetLive().EnableEDNS {
		t.Fatalf("precondition: expected enable_edns true by default")
	}

	// A replicated config event carrying a false bool must turn it off (struct-merge could not).
	if err := svc.applyConfigEvent(Event{Operation: OperationUpsert, Value: []byte(`{"enable_edns":false}`)}); err != nil {
		t.Fatalf("applyConfigEvent: %v", err)
	}
	if config.AppConfig.GetLive().EnableEDNS {
		t.Fatalf("expected enable_edns=false after config event")
	}

	// A config event must never overwrite the node's own distributed identity.
	if err := svc.applyConfigEvent(Event{Operation: OperationUpsert, Value: []byte(`{"distributed":{"node_id":"evil"}}`)}); err != nil {
		t.Fatalf("applyConfigEvent (distributed-only): %v", err)
	}
	if got := config.AppConfig.GetLive().Distributed.NodeID; got != "node-a" {
		t.Fatalf("config event clobbered node identity: %q", got)
	}
}

func TestApplyConfigEventMergesDistributedMembership(t *testing.T) {
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	svc := newTestService(t, "node-b", priv, map[string]string{"node-a": "pub-a"})
	config.AppConfig.LiveForTest().Distributed.Transport = "tls"
	config.AppConfig.LiveForTest().Distributed.SyncBindHost = "127.0.0.1"
	config.AppConfig.LiveForTest().Distributed.SyncPort = ":53531"
	config.AppConfig.LiveForTest().Distributed.Peers = "tls://127.0.0.1:53530"

	event := Event{Operation: OperationUpsert, Value: []byte(`{"distributed":{"peers":"tls://127.0.0.1:53531,tls://127.0.0.1:53532","peer_public_keys":{"node-c":"pub-c"}}}`)}
	if err := svc.applyConfigEvent(event); err != nil {
		t.Fatalf("applyConfigEvent: %v", err)
	}
	live := config.AppConfig.GetLive()
	if live.Distributed.Peers != "tls://127.0.0.1:53530,tls://127.0.0.1:53532" {
		t.Fatalf("peers = %q", live.Distributed.Peers)
	}
	if live.Distributed.PeerPublicKeys["node-a"] != "pub-a" || live.Distributed.PeerPublicKeys["node-c"] != "pub-c" {
		t.Fatalf("peer_public_keys = %#v", live.Distributed.PeerPublicKeys)
	}
}

func mustPublicKeyFromPrivate(t *testing.T, privateKeyB64 string) string {
	t.Helper()
	priv, err := privateKey(privateKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
}

func TestStripDistributedKey(t *testing.T) {
	out, has, err := stripDistributedKey([]byte(`{"enable_edns":false,"distributed":{"node_id":"x","peers":"tls://10.0.0.11:53530","peer_public_keys":{"node-b":"pub-b"}}}`))
	if err != nil {
		t.Fatalf("stripDistributedKey: %v", err)
	}
	if !has {
		t.Fatalf("expected remaining keys after stripping distributed")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(out, &fields); err != nil {
		t.Fatalf("unmarshal stripped: %v", err)
	}
	var dist map[string]json.RawMessage
	if err := json.Unmarshal(fields["distributed"], &dist); err != nil {
		t.Fatalf("distributed membership not retained: %s", out)
	}
	if _, ok := dist["node_id"]; ok {
		t.Fatalf("node-local distributed field not stripped: %s", out)
	}
	if _, ok := dist["peers"]; !ok {
		t.Fatalf("distributed peers dropped: %s", out)
	}
	if _, ok := dist["peer_public_keys"]; !ok {
		t.Fatalf("distributed peer_public_keys dropped: %s", out)
	}
	if _, ok := fields["enable_edns"]; !ok {
		t.Fatalf("non-distributed field dropped: %s", out)
	}

	if _, has, err := stripDistributedKey([]byte(`{"distributed":{"node_id":"x"}}`)); err != nil || has {
		t.Fatalf("expected no remaining keys for distributed-only patch (has=%v err=%v)", has, err)
	}
}

func TestDistributedTransportAndReadinessHelpers(t *testing.T) {
	t.Cleanup(func() {
		config.AppConfig.LiveForTest().Distributed.Peers = ""
		config.AppConfig.LiveForTest().Distributed.Transport = ""
	})
	config.AppConfig.SetLive(config.DefaultLiveConfig)
	config.AppConfig.LiveForTest().Mode = "distributed"
	config.AppConfig.LiveForTest().Distributed.NodeID = "node-a"
	config.AppConfig.LiveForTest().Distributed.PrivateKey = "priv"
	config.AppConfig.LiveForTest().Distributed.Transport = "tls"
	config.AppConfig.LiveForTest().Distributed.Peers = " http://a.local/ , tls://b.local:53530 , "

	if !Enabled() || !TCPTransportEnabled() || !TLSTransportEnabled() || !readyToPublish() {
		t.Fatalf("distributed readiness helpers returned false")
	}
	gotPeers := peers()
	if len(gotPeers) != 2 || gotPeers[0] != "http://a.local" || gotPeers[1] != "tls://b.local:53530" {
		t.Fatalf("peers = %#v", gotPeers)
	}
	if peerURL("http://a.local/", "/api") != "http://a.local/api" {
		t.Fatalf("peerURL did not trim slash")
	}
	if !useTCPTransport("tls://b.local:53530") || useTCPTransport("https://b.local") {
		t.Fatalf("useTCPTransport returned unexpected values")
	}

	config.AppConfig.LiveForTest().Distributed.Transport = "http"
	if TCPTransportEnabled() || TLSTransportEnabled() {
		t.Fatalf("socket helpers true for http transport")
	}
}

func TestHTTPPeerFetchPushAndRepairPaths(t *testing.T) {
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	svc := newTestService(t, "node-a", priv, nil)
	config.AppConfig.LiveForTest().Distributed.Transport = "http"
	if err := svc.store.PutRecordRaw("example.test.", "A", "www", []any{map[string]any{"ip": "192.0.2.1"}}); err != nil {
		t.Fatalf("PutRecordRaw: %v", err)
	}

	event := Event{
		EventID:   "event-1",
		Origin:    "node-b",
		Seq:       1,
		Entity:    entityKey("example.test.", "A", "www"),
		Zone:      "example.test.",
		RRType:    "A",
		Name:      "www",
		Operation: OperationUpsert,
		Value:     json.RawMessage(`{"ip":"192.0.2.1"}`),
		Vector:    map[string]uint64{"node-b": 1},
	}
	branch := MerkleBranch{Prefix: "aa", Hash: "branch", LeafCount: 1}
	leaf := MerkleLeaf{Entity: event.Entity, Hash: "leaf"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/distributed/events":
			if r.Method == http.MethodPost {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			_ = json.NewEncoder(w).Encode([]Event{event})
		case "/api/distributed/vector":
			_ = json.NewEncoder(w).Encode(map[string]uint64{"node-b": 1})
		case "/api/distributed/merkle/roots":
			roots, _ := svc.merkleZoneRoots()
			_ = json.NewEncoder(w).Encode(roots)
		case "/api/distributed/merkle/branches":
			_ = json.NewEncoder(w).Encode(map[string]MerkleBranch{"aa": branch})
		case "/api/distributed/merkle/leaves":
			_ = json.NewEncoder(w).Encode(map[string]MerkleLeaf{event.Entity: leaf})
		case "/api/distributed/merkle/repair-events":
			_ = json.NewEncoder(w).Encode([]Event{event})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	ctx := context.Background()
	if err := svc.pushEvent(ctx, server.URL, event); err != nil {
		t.Fatalf("pushEvent: %v", err)
	}
	if vector, err := svc.fetchPeerVector(ctx, server.URL); err != nil || vector["node-b"] != 1 {
		t.Fatalf("fetchPeerVector = %#v err=%v", vector, err)
	}
	if events, err := svc.fetchPeerEvents(ctx, server.URL, "node-b", 0); err != nil || len(events) != 1 {
		t.Fatalf("fetchPeerEvents len=%d err=%v", len(events), err)
	}
	if roots, err := svc.fetchPeerMerkleRoots(ctx, server.URL); err != nil || roots["example.test."].Root == "" {
		t.Fatalf("fetchPeerMerkleRoots = %#v err=%v", roots, err)
	}
	if branches, err := svc.fetchPeerMerkleBranches(ctx, server.URL, "example.test."); err != nil || branches["aa"].Hash != "branch" {
		t.Fatalf("fetchPeerMerkleBranches = %#v err=%v", branches, err)
	}
	if leaves, err := svc.fetchPeerMerkleLeaves(ctx, server.URL, "example.test.", []string{"aa"}); err != nil || leaves[event.Entity].Hash != "leaf" {
		t.Fatalf("fetchPeerMerkleLeaves = %#v err=%v", leaves, err)
	}
	if repairEvents, err := svc.fetchPeerMerkleRepairEvents(ctx, server.URL, []string{event.Entity}); err != nil || len(repairEvents) != 1 {
		t.Fatalf("fetchPeerMerkleRepairEvents len=%d err=%v", len(repairEvents), err)
	}

	if err := svc.repairPeerZones(ctx, server.URL); err != nil {
		t.Fatalf("repairPeerZones: %v", err)
	}
	if err := svc.pushEvent(ctx, server.URL+"/missing", event); err == nil {
		t.Fatalf("pushEvent accepted error response")
	}
}

func TestReceiveEventRejectsSequenceGap(t *testing.T) {
	aPriv, aPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair A: %v", err)
	}
	bPriv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair B: %v", err)
	}

	event := Event{
		EventID:   "event-gap",
		Origin:    "node-a",
		Seq:       2,
		Entity:    entityKey("example.com.", "A", "www"),
		Zone:      "example.com.",
		RRType:    "A",
		Name:      "www",
		Operation: OperationUpsert,
		Value:     json.RawMessage(`{"ip":"192.0.2.10","ttl":300}`),
		Vector:    map[string]uint64{"node-a": 2},
		CreatedAt: 1,
	}
	sig, err := signEvent(aPriv, event)
	if err != nil {
		t.Fatalf("signEvent: %v", err)
	}
	event.Signature = sig

	bService := newTestService(t, "node-b", bPriv, map[string]string{"node-a": aPub})
	if _, err := bService.ReceiveEvent(context.Background(), event); err == nil {
		t.Fatalf("ReceiveEvent succeeded despite sequence gap")
	}
	vector, err := bService.Vector()
	if err != nil {
		t.Fatalf("Vector: %v", err)
	}
	if vector["node-a"] != 0 {
		t.Fatalf("vector[node-a] = %d, want 0", vector["node-a"])
	}
}

func TestNodeInfoIncludesDiscoveryFields(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	svc := newTestService(t, "node-a", priv, map[string]string{"node-b": pub})
	config.AppConfig.LiveForTest().Version = "go53 test"
	config.AppConfig.LiveForTest().Distributed.Transport = "tcp"
	config.AppConfig.LiveForTest().Distributed.SyncBindHost = "127.0.0.1"
	config.AppConfig.LiveForTest().Distributed.SyncPort = ":19090"

	info, err := svc.NodeInfo()
	if err != nil {
		t.Fatalf("NodeInfo: %v", err)
	}
	if info.NodeID != "node-a" || info.Transport != "tcp" || info.SyncEndpoint != "tcp://127.0.0.1:19090" {
		t.Fatalf("unexpected NodeInfo: %#v", info)
	}
	if info.PublicKey == "" || info.Fingerprint == "" || info.Version != "go53 test" {
		t.Fatalf("incomplete NodeInfo: %#v", info)
	}
	if got := PublicKeyFingerprint(info.PublicKey); got != info.Fingerprint {
		t.Fatalf("fingerprint = %q, want %q", got, info.Fingerprint)
	}

	config.AppConfig.LiveForTest().Distributed.Transport = "tls"
	info, err = svc.NodeInfo()
	if err != nil {
		t.Fatalf("TLS NodeInfo: %v", err)
	}
	if info.Transport != "tls" || info.SyncEndpoint != "tls://127.0.0.1:19090" || !info.TLSEnabled {
		t.Fatalf("unexpected TLS NodeInfo transport fields: %#v", info)
	}
	if info.TLSCertificate == "" || info.TLSFingerprint == "" || info.TLSPublicKeyPin != info.Fingerprint {
		t.Fatalf("incomplete TLS NodeInfo: %#v", info)
	}
}

func TestApplyConfigEventPreservesLocalDistributedIdentity(t *testing.T) {
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	svc := newTestService(t, "node-a", priv, nil)
	config.AppConfig.LiveForTest().DefaultTTL = 3600
	config.AppConfig.LiveForTest().Distributed.NodeID = "node-a"

	value, _ := json.Marshal(config.LiveConfig{
		DefaultTTL: 600,
		Distributed: config.DistributedConfig{
			NodeID: "must-not-apply",
		},
	})
	if err := svc.applyConfigEvent(Event{Operation: OperationUpsert, Value: value}); err != nil {
		t.Fatalf("applyConfigEvent: %v", err)
	}
	live := config.AppConfig.GetLive()
	if live.DefaultTTL != 600 {
		t.Fatalf("DefaultTTL = %d, want 600", live.DefaultTTL)
	}
	if live.Distributed.NodeID != "node-a" {
		t.Fatalf("Distributed.NodeID = %q, want node-a", live.Distributed.NodeID)
	}
}

func TestApplyTSIGEventUpdatesStorageAndCache(t *testing.T) {
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	svc := newTestService(t, "node-a", priv, nil)
	value := json.RawMessage(`{"algorithm":"hmac-sha256.","secret":"abc123"}`)

	if err := svc.applyTSIGEvent(Event{Name: "xfr-key.", Operation: OperationUpsert, Value: value}); err != nil {
		t.Fatalf("applyTSIGEvent upsert: %v", err)
	}
	key, ok := security.GetTSIGKey("xfr-key.")
	if !ok {
		t.Fatalf("TSIG key not loaded")
	}
	if key.Secret != "abc123" {
		t.Fatalf("TSIG secret = %q, want abc123", key.Secret)
	}
	if err := svc.applyTSIGEvent(Event{Name: "xfr-key.", Operation: OperationDelete}); err != nil {
		t.Fatalf("applyTSIGEvent delete: %v", err)
	}
	if _, ok := security.GetTSIGKey("xfr-key."); ok {
		t.Fatalf("TSIG key still present after delete")
	}
}

func TestApplyDNSSECKeyEventUpdatesStorageCache(t *testing.T) {
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	svc := newTestService(t, "node-a", priv, nil)
	key := types.StoredKey{
		KeyTag:    12345,
		Algorithm: "ED25519",
		Flags:     256,
		State:     security.KeyStateActive,
		PublicKey: "pub",
	}
	value, _ := json.Marshal(key)

	if err := svc.applyDNSSECKeyEvent(Event{Name: "key-1", Operation: OperationUpsert, Value: value}); err != nil {
		t.Fatalf("applyDNSSECKeyEvent upsert: %v", err)
	}
	stored, err := security.LoadStoredKey("key-1")
	if err != nil {
		t.Fatalf("LoadStoredKey: %v", err)
	}
	if stored.KeyTag != 12345 {
		t.Fatalf("stored key tag = %d, want 12345", stored.KeyTag)
	}
	if err := svc.applyDNSSECKeyEvent(Event{Name: "key-1", Operation: OperationDelete}); err != nil {
		t.Fatalf("applyDNSSECKeyEvent delete: %v", err)
	}
	if _, err := security.LoadStoredKey("key-1"); err == nil {
		t.Fatalf("DNSSEC key still present after delete")
	}
}

func TestEventWinsUsesVectorDominancePerRRSet(t *testing.T) {
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	svc := newTestService(t, "node-local", priv, nil)
	entity := entityKey("example.com.", "A", "www")

	if err := svc.saveEntityClock(entity, EntityClock{
		Origin: "node-b",
		Seq:    10,
		Vector: map[string]uint64{"node-a": 1, "node-b": 10},
	}); err != nil {
		t.Fatalf("saveEntityClock: %v", err)
	}
	dominating := Event{
		Origin: "node-a",
		Seq:    2,
		Entity: entity,
		Vector: map[string]uint64{"node-a": 2, "node-b": 10},
	}
	if !svc.eventWinsLocked(dominating) {
		t.Fatalf("dominating event with lower origin seq did not win")
	}

	if err := svc.saveEntityClock(entity, EntityClock{
		Origin: "node-b",
		Seq:    10,
		Vector: map[string]uint64{"node-a": 2, "node-b": 10},
	}); err != nil {
		t.Fatalf("saveEntityClock current: %v", err)
	}
	stale := Event{
		Origin: "node-a",
		Seq:    3,
		Entity: entity,
		Vector: map[string]uint64{"node-a": 3, "node-b": 5},
	}
	if svc.eventWinsLocked(stale) {
		t.Fatalf("non-dominating event won only because of higher origin seq")
	}
}

func TestEventWinsFallsBackToTieBreakForConcurrentVectors(t *testing.T) {
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	svc := newTestService(t, "node-local", priv, nil)
	entity := entityKey("example.com.", "A", "www")

	if err := svc.saveEntityClock(entity, EntityClock{
		Origin: "node-b",
		Seq:    1,
		Vector: map[string]uint64{"node-b": 1},
	}); err != nil {
		t.Fatalf("saveEntityClock: %v", err)
	}
	concurrentLowerNode := Event{
		Origin: "node-a",
		Seq:    1,
		Entity: entity,
		Vector: map[string]uint64{"node-a": 1},
	}
	if svc.eventWinsLocked(concurrentLowerNode) {
		t.Fatalf("concurrent lower node id unexpectedly won tie-break")
	}
	concurrentHigherSeq := Event{
		Origin: "node-a",
		Seq:    2,
		Entity: entity,
		Vector: map[string]uint64{"node-a": 2},
	}
	if !svc.eventWinsLocked(concurrentHigherSeq) {
		t.Fatalf("concurrent higher seq did not win deterministic tie-break")
	}
}

func TestLatestEventsForEntitiesUsesVectorWinner(t *testing.T) {
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	svc := newTestService(t, "node-local", priv, nil)
	entity := entityKey("example.com.", "A", "www")
	current := Event{
		EventID: "current",
		Origin:  "node-a",
		Seq:     2,
		Entity:  entity,
		Zone:    "example.com.",
		RRType:  "A",
		Name:    "www",
		Vector:  map[string]uint64{"node-a": 2},
	}
	winner := Event{
		EventID: "winner",
		Origin:  "node-b",
		Seq:     1,
		Entity:  entity,
		Zone:    "example.com.",
		RRType:  "A",
		Name:    "www",
		Vector:  map[string]uint64{"node-a": 2, "node-b": 1},
	}
	otherType := Event{
		EventID:    "config",
		Origin:     "node-c",
		Seq:        1,
		EntityType: EntityConfig,
		Entity:     EntityConfig + "/live",
		Vector:     map[string]uint64{"node-c": 1},
	}
	if err := svc.saveEvent(current); err != nil {
		t.Fatalf("save current: %v", err)
	}
	if err := svc.saveEvent(winner); err != nil {
		t.Fatalf("save winner: %v", err)
	}
	if err := svc.saveEvent(otherType); err != nil {
		t.Fatalf("save config: %v", err)
	}
	latest, err := svc.LatestEventsForEntities([]string{entity, EntityConfig + "/live", ""})
	if err != nil {
		t.Fatalf("LatestEventsForEntities: %v", err)
	}
	if len(latest) != 1 || latest[0].EventID != "winner" {
		t.Fatalf("latest = %#v, want winner only", latest)
	}
	if eventWinsEvent(current, winner) {
		t.Fatalf("stale event unexpectedly wins over dominating event")
	}
}

func TestMerkleRepairDetectsAndRepairsZoneDrift(t *testing.T) {
	aPriv, aPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair A: %v", err)
	}
	bPriv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair B: %v", err)
	}

	aService := newTestService(t, "node-a", aPriv, map[string]string{"node-b": ""})
	if err := aService.store.PutRecordRaw("example.com.", "A", "www", []any{
		map[string]any{"ip": "192.0.2.10", "ttl": float64(300)},
	}); err != nil {
		t.Fatalf("PutRecordRaw: %v", err)
	}
	if err := aService.PublishUpsert("example.com.", "A", "www", []any{
		map[string]any{"ip": "192.0.2.10", "ttl": float64(300)},
	}); err != nil {
		t.Fatalf("PublishUpsert: %v", err)
	}
	events, err := aService.Events("node-a", 0)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events len = %d, want 1", len(events))
	}

	bService := newTestService(t, "node-b", bPriv, map[string]string{"node-a": aPub})
	if _, err := bService.ReceiveEvent(context.Background(), events[0]); err != nil {
		t.Fatalf("ReceiveEvent: %v", err)
	}
	aRoots, err := aService.merkleZoneRoots()
	if err != nil {
		t.Fatalf("a merkleZoneRoots: %v", err)
	}
	bRoots, err := bService.merkleZoneRoots()
	if err != nil {
		t.Fatalf("b merkleZoneRoots: %v", err)
	}
	if aRoots["example.com."].Root != bRoots["example.com."].Root {
		t.Fatalf("roots differ before drift")
	}

	if err := bService.store.PutRecordRaw("example.com.", "A", "www", []any{
		map[string]any{"ip": "192.0.2.99", "ttl": float64(300)},
	}); err != nil {
		t.Fatalf("corrupt PutRecordRaw: %v", err)
	}
	localBranches, err := bService.merkleZoneBranches("example.com.")
	if err != nil {
		t.Fatalf("local branches: %v", err)
	}
	peerBranches, err := aService.merkleZoneBranches("example.com.")
	if err != nil {
		t.Fatalf("peer branches: %v", err)
	}
	prefixes := merkleDifferingBranches(localBranches, peerBranches)
	if len(prefixes) == 0 {
		t.Fatalf("Merkle branches did not detect drift")
	}
	localLeaves, err := bService.merkleZoneLeaves("example.com.", prefixes)
	if err != nil {
		t.Fatalf("local leaves: %v", err)
	}
	peerLeaves, err := aService.merkleZoneLeaves("example.com.", prefixes)
	if err != nil {
		t.Fatalf("peer leaves: %v", err)
	}
	entities := merkleDifferingEntities(localLeaves, peerLeaves)
	if len(entities) != 1 || entities[0] != entityKey("example.com.", "A", "www") {
		t.Fatalf("entities = %#v, want www A entity", entities)
	}
	repairEvents, err := aService.latestEventsForEntities(entities)
	if err != nil {
		t.Fatalf("latestEventsForEntities: %v", err)
	}
	if len(repairEvents) != 1 {
		t.Fatalf("repair events len = %d, want 1", len(repairEvents))
	}
	if err := bService.applyRepairEvent(context.Background(), repairEvents[0]); err != nil {
		t.Fatalf("applyRepairEvent: %v", err)
	}
	aRoots, err = aService.merkleZoneRoots()
	if err != nil {
		t.Fatalf("a merkleZoneRoots after repair: %v", err)
	}
	bRoots, err = bService.merkleZoneRoots()
	if err != nil {
		t.Fatalf("b merkleZoneRoots after repair: %v", err)
	}
	if aRoots["example.com."].Root != bRoots["example.com."].Root {
		t.Fatalf("roots differ after repair: a=%s b=%s", aRoots["example.com."].Root, bRoots["example.com."].Root)
	}
	_, _, raw, ok := bService.store.GetRecord("example.com.", "A", "www")
	if !ok {
		t.Fatalf("repaired record not found")
	}
	data, _ := json.Marshal(raw)
	if string(data) != `[{"ip":"192.0.2.10","ttl":300}]` {
		t.Fatalf("repaired record = %s", string(data))
	}
}

func TestMerkleSnapshotRepairBackfillsRecordsWithoutEvents(t *testing.T) {
	aPriv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair A: %v", err)
	}
	bPriv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair B: %v", err)
	}

	aService := newTestService(t, "node-a", aPriv, map[string]string{"node-b": ""})
	if err := aService.store.PutRecordRaw("bootstrap.test.", "SOA", "bootstrap.test.", map[string]any{
		"ns":      "ns1.bootstrap.test.",
		"mbox":    "hostmaster.bootstrap.test.",
		"serial":  float64(1),
		"refresh": float64(3600),
		"retry":   float64(600),
		"expire":  float64(86400),
		"minimum": float64(300),
		"ttl":     float64(300),
	}); err != nil {
		t.Fatalf("PutRecordRaw SOA: %v", err)
	}
	if err := aService.store.PutRecordRaw("bootstrap.test.", "A", "www", []any{
		map[string]any{"ip": "192.0.2.44", "ttl": float64(300)},
	}); err != nil {
		t.Fatalf("PutRecordRaw A: %v", err)
	}
	if events, err := aService.Events("node-a", 0); err != nil {
		t.Fatalf("Events: %v", err)
	} else if len(events) != 0 {
		t.Fatalf("events len = %d, want 0", len(events))
	}

	bService := newTestService(t, "node-b", bPriv, map[string]string{"node-a": ""})
	localBranches, err := bService.merkleZoneBranches("bootstrap.test.")
	if err != nil {
		t.Fatalf("local branches: %v", err)
	}
	peerBranches, err := aService.merkleZoneBranches("bootstrap.test.")
	if err != nil {
		t.Fatalf("peer branches: %v", err)
	}
	prefixes := merkleDifferingBranches(localBranches, peerBranches)
	localLeaves, err := bService.merkleZoneLeaves("bootstrap.test.", prefixes)
	if err != nil {
		t.Fatalf("local leaves: %v", err)
	}
	peerLeaves, err := aService.merkleZoneLeaves("bootstrap.test.", prefixes)
	if err != nil {
		t.Fatalf("peer leaves: %v", err)
	}
	entities := merkleDifferingEntities(localLeaves, peerLeaves)
	if len(entities) != 2 {
		t.Fatalf("entities len = %d, want 2: %#v", len(entities), entities)
	}
	repairEvents, err := aService.latestEventsForEntities(entities)
	if err != nil {
		t.Fatalf("latestEventsForEntities: %v", err)
	}
	if len(repairEvents) != 0 {
		t.Fatalf("repair events len = %d, want 0", len(repairEvents))
	}
	records, err := aService.merkleZoneRecords("bootstrap.test.", entities)
	if err != nil {
		t.Fatalf("merkleZoneRecords: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("records len = %d, want 2", len(records))
	}
	if err := bService.applyMerkleRecords(records); err != nil {
		t.Fatalf("applyMerkleRecords: %v", err)
	}
	aRoots, err := aService.merkleZoneRoots()
	if err != nil {
		t.Fatalf("a merkleZoneRoots: %v", err)
	}
	bRoots, err := bService.merkleZoneRoots()
	if err != nil {
		t.Fatalf("b merkleZoneRoots: %v", err)
	}
	if aRoots["bootstrap.test."].Root != bRoots["bootstrap.test."].Root {
		t.Fatalf("roots differ after snapshot repair: a=%s b=%s", aRoots["bootstrap.test."].Root, bRoots["bootstrap.test."].Root)
	}
	if _, _, _, ok := bService.store.GetRecord("bootstrap.test.", "SOA", "bootstrap.test."); !ok {
		t.Fatalf("SOA not backfilled")
	}
	if _, _, _, ok := bService.store.GetRecord("bootstrap.test.", "A", "www"); !ok {
		t.Fatalf("A not backfilled")
	}
}

func TestDNSSECKeySnapshotBackfillsKeysWithoutEvents(t *testing.T) {
	privA, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair A: %v", err)
	}
	aService := newTestService(t, "node-a", privA, nil)
	pubKSK, privKSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Generate KSK: %v", err)
	}
	pubZSK, privZSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Generate ZSK: %v", err)
	}
	if err := security.SavePrivateKeyToStorage("bootstrap.test.", "ksk-bootstrap", "ED25519", privKSK, pubKSK, 257); err != nil {
		t.Fatalf("SavePrivateKeyToStorage KSK: %v", err)
	}
	if err := security.SavePrivateKeyToStorage("bootstrap.test.", "zsk-bootstrap", "ED25519", privZSK, pubZSK, 256); err != nil {
		t.Fatalf("SavePrivateKeyToStorage ZSK: %v", err)
	}
	keys, err := aService.dnssecKeysForZone("bootstrap.test.")
	if err != nil {
		t.Fatalf("dnssecKeysForZone: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("keys len = %d, want 2", len(keys))
	}

	privB, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair B: %v", err)
	}
	bService := newTestService(t, "node-b", privB, nil)
	if err := bService.applyDNSSECKeys("bootstrap.test.", keys); err != nil {
		t.Fatalf("applyDNSSECKeys: %v", err)
	}
	stored, err := bService.dnssecKeysForZone("bootstrap.test.")
	if err != nil {
		t.Fatalf("dnssecKeysForZone B: %v", err)
	}
	if len(stored) != 2 {
		t.Fatalf("stored keys len = %d, want 2", len(stored))
	}
}

func TestApplyConfigEventGatesAuthOnAuthSync(t *testing.T) {
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	svc := newTestService(t, "node-a", priv, map[string]string{"node-a": mustPublicKeyFromPrivate(t, priv)})

	const key = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL" // 48 base62 chars
	authEvent := Event{
		EntityType: EntityConfig,
		Name:       "live",
		Operation:  OperationUpsert,
		Value:      []byte(`{"auth":{"x_auth_key":"` + key + `"}}`),
	}

	// Default (auth_sync unset) replicates the auth block.
	config.AppConfig.LiveForTest().Distributed.AuthSync = nil
	if err := svc.applyConfigEvent(authEvent); err != nil {
		t.Fatalf("applyConfigEvent (default): %v", err)
	}
	if got := config.AppConfig.GetLive().Auth.XAuthKey; got != key {
		t.Fatalf("auth not replicated by default: got %q", got)
	}

	// Opting out keeps the local auth untouched by peer events.
	config.AppConfig.LiveForTest().Auth.XAuthKey = "local-only"
	off := false
	config.AppConfig.LiveForTest().Distributed.AuthSync = &off
	if err := svc.applyConfigEvent(authEvent); err != nil {
		t.Fatalf("applyConfigEvent (auth_sync off): %v", err)
	}
	if got := config.AppConfig.GetLive().Auth.XAuthKey; got != "local-only" {
		t.Fatalf("auth overwritten despite auth_sync=false: got %q", got)
	}
}

func newTestService(t *testing.T, nodeID, privateKey string, peerKeys map[string]string) *Service {
	t.Helper()
	mock := &storage.MockStorage{}
	if err := mock.Init(); err != nil {
		t.Fatalf("mock init: %v", err)
	}
	storage.Backend = mock
	config.AppConfig.SetLive(config.DefaultLiveConfig)
	config.AppConfig.LiveForTest().Mode = "distributed"
	config.AppConfig.LiveForTest().DNSSECEnabled = false
	config.AppConfig.LiveForTest().Distributed.NodeID = nodeID
	config.AppConfig.LiveForTest().Distributed.Peers = ""
	config.AppConfig.LiveForTest().Distributed.PrivateKey = privateKey
	config.AppConfig.LiveForTest().Distributed.PeerPublicKeys = peerKeys

	mem, err := memory.NewZoneStore(mock)
	if err != nil {
		t.Fatalf("NewZoneStore: %v", err)
	}
	rtypes.InitMemoryStore(mem)
	return &Service{
		store:      mem,
		storage:    mock,
		client:     &http.Client{Timeout: time.Second},
		peerQueues: make(map[string]chan Event),
	}
}

func zoneListed(zones []string, zone string) bool {
	for _, z := range zones {
		if z == zone {
			return true
		}
	}
	return false
}

// TestZoneDeleteReplication verifies that deleting a zone propagates to peers:
// per-record delete events remove the records (repair-safe tombstones) and the
// zone-level delete event removes the residual empty zone shell.
func TestZoneDeleteReplication(t *testing.T) {
	aPriv, aPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair A: %v", err)
	}
	bPriv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair B: %v", err)
	}

	const zone = "zonedelete.test."

	// Origin node deletes the zone: emit a per-record delete for each record,
	// then the zone-level delete (mirrors DeleteZoneHandler).
	aService := newTestService(t, "node-a", aPriv, map[string]string{"node-b": ""})
	if err := aService.PublishDelete(zone, "SOA", "@"); err != nil {
		t.Fatalf("PublishDelete SOA: %v", err)
	}
	if err := aService.PublishDelete(zone, "A", "www"); err != nil {
		t.Fatalf("PublishDelete A: %v", err)
	}
	if err := aService.PublishZoneDelete(zone); err != nil {
		t.Fatalf("PublishZoneDelete: %v", err)
	}
	events, err := aService.Events("node-a", 0)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("events len = %d, want 3", len(events))
	}

	// Peer still holds the zone (two A values + SOA) before the events arrive.
	bService := newTestService(t, "node-b", bPriv, map[string]string{"node-a": aPub})
	if err := bService.store.PutRecordRaw(zone, "SOA", "@", map[string]any{"ns": "ns1." + zone, "ttl": float64(3600)}); err != nil {
		t.Fatalf("seed SOA: %v", err)
	}
	if err := bService.store.PutRecordRaw(zone, "A", "www", []any{
		map[string]any{"ip": "8.8.4.4", "ttl": float64(3600)},
		map[string]any{"ip": "8.8.8.8", "ttl": float64(3600)},
	}); err != nil {
		t.Fatalf("seed A: %v", err)
	}
	if !zoneListed(bService.store.ZoneNamesSnapshot(), zone) {
		t.Fatalf("precondition: peer should list the zone")
	}

	for i, e := range events {
		if _, err := bService.ReceiveEvent(context.Background(), e); err != nil {
			t.Fatalf("ReceiveEvent[%d]: %v", i, err)
		}
	}

	// Records are gone...
	if _, _, _, ok := bService.store.GetRecord(zone, "A", "www"); ok {
		t.Fatalf("A record should be deleted on peer")
	}
	if _, _, _, ok := bService.store.GetRecord(zone, "SOA", "@"); ok {
		t.Fatalf("SOA record should be deleted on peer")
	}
	// ...and the empty zone shell is removed too.
	if zoneListed(bService.store.ZoneNamesSnapshot(), zone) {
		t.Fatalf("zone shell should be removed on peer after zone-delete event")
	}
}
