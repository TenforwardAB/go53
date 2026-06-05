package distributed

import (
	"context"
	"encoding/json"
	"testing"

	"go53/config"
	"go53/memory"
	"go53/security"
	"go53/storage"
	"go53/types"
)

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
	config.AppConfig.Live.Distributed.PrivateKey = privateKey
	config.AppConfig.Live.Distributed.PeerPublicKeys = peerKeys

	mem, err := memory.NewZoneStore(mock)
	if err != nil {
		t.Fatalf("NewZoneStore: %v", err)
	}
	return &Service{
		store:      mem,
		storage:    mock,
		client:     nil,
		peerQueues: make(map[string]chan Event),
	}
}
