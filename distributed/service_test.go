package distributed

import (
	"context"
	"encoding/json"
	"testing"

	"go53/config"
	"go53/memory"
	"go53/storage"
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
