package distributed

import (
	"context"
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
	config.AppConfig.Live = config.DefaultLiveConfig
	config.AppConfig.Live.Mode = "distributed"
	config.AppConfig.Live.Distributed.NodeID = "node-init"
	config.AppConfig.Live.Distributed.PrivateKey = priv
	config.AppConfig.Live.Distributed.PushTimeoutMs = 25
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

func TestStripDistributedKey(t *testing.T) {
	out, has, err := stripDistributedKey([]byte(`{"enable_edns":false,"distributed":{"node_id":"x"}}`))
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
	if _, ok := fields["distributed"]; ok {
		t.Fatalf("distributed block not stripped: %s", out)
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
		config.AppConfig.Live.Distributed.Peers = ""
		config.AppConfig.Live.Distributed.Transport = ""
	})
	config.AppConfig.Live = config.DefaultLiveConfig
	config.AppConfig.Live.Mode = "distributed"
	config.AppConfig.Live.Distributed.NodeID = "node-a"
	config.AppConfig.Live.Distributed.PrivateKey = "priv"
	config.AppConfig.Live.Distributed.Transport = "tls"
	config.AppConfig.Live.Distributed.Peers = " http://a.local/ , tls://b.local:53530 , "

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

	config.AppConfig.Live.Distributed.Transport = "http"
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
	config.AppConfig.Live.Distributed.Transport = "http"
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
	config.AppConfig.Live.Version = "go53 test"
	config.AppConfig.Live.Distributed.Transport = "tcp"
	config.AppConfig.Live.Distributed.SyncBindHost = "127.0.0.1"
	config.AppConfig.Live.Distributed.SyncPort = ":19090"

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

	config.AppConfig.Live.Distributed.Transport = "tls"
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
	config.AppConfig.Live.DefaultTTL = 3600
	config.AppConfig.Live.Distributed.NodeID = "node-a"

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

func newTestService(t *testing.T, nodeID, privateKey string, peerKeys map[string]string) *Service {
	t.Helper()
	mock := &storage.MockStorage{}
	if err := mock.Init(); err != nil {
		t.Fatalf("mock init: %v", err)
	}
	storage.Backend = mock
	config.AppConfig.Live = config.DefaultLiveConfig
	config.AppConfig.Live.Mode = "distributed"
	config.AppConfig.Live.DNSSECEnabled = false
	config.AppConfig.Live.Distributed.NodeID = nodeID
	config.AppConfig.Live.Distributed.Peers = ""
	config.AppConfig.Live.Distributed.PrivateKey = privateKey
	config.AppConfig.Live.Distributed.PeerPublicKeys = peerKeys

	mem, err := memory.NewZoneStore(mock)
	if err != nil {
		t.Fatalf("NewZoneStore: %v", err)
	}
	return &Service{
		store:      mem,
		storage:    mock,
		client:     &http.Client{Timeout: time.Second},
		peerQueues: make(map[string]chan Event),
	}
}
