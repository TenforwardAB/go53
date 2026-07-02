package handlers

import (
	"testing"

	"go53/config"
	"go53/distributed"
	"go53/zone/rtypes"
)

func TestCanonicalRecordNameForDistributedEvents(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{name: "www", want: "www"},
		{name: "www.dist.test.", want: "www"},
		{name: "dist.test.", want: "@"},
	}

	for _, tt := range tests {
		if got := canonicalRecordName("dist.test.", "A", tt.name); got != tt.want {
			t.Fatalf("canonicalRecordName(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
	if got := canonicalRecordName("dist.test.", "SOA", "dist.test."); got != "@" {
		t.Fatalf("SOA canonicalRecordName = %q, want @", got)
	}
}

// TestPublishHelpersCanonicalizeZone is a regression test for issue #53. Records
// are stored under the FQDN-sanitized zone key ("dist.test."), but the HTTP
// handlers hand the publish helpers the raw URL segment ("dist.test", no trailing
// dot). Before the fix the upsert re-read missed ("stored record not found after
// add") and the delete tombstone was keyed under the wrong zone, so Merkle
// anti-entropy resurrected deleted records. Both events must be keyed by the FQDN
// zone.
func TestPublishHelpersCanonicalizeZone(t *testing.T) {
	setupHandlerTestStore(t)
	priv, pub, err := distributed.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	config.AppConfig.LiveForTest().Mode = "distributed"
	config.AppConfig.LiveForTest().Distributed.NodeID = "node-a"
	config.AppConfig.LiveForTest().Distributed.PrivateKey = priv
	config.AppConfig.LiveForTest().Distributed.PeerPublicKeys = map[string]string{"node-a": pub}
	mem := rtypes.GetMemStore()
	distributed.Init(mem)
	t.Cleanup(func() { distributed.Default = nil })

	// Stored under the FQDN zone key, exactly as the rtypes Add path does.
	if err := mem.AddRecord("dist.test.", "TXT", "sel._domainkey",
		[]any{map[string]any{"text": "v=DKIM1", "ttl": float64(300)}}); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}

	// Raw (non-FQDN) zone, as the handler passes it: upsert must not error...
	if err := publishDistributedUpsert("dist.test", "TXT", "sel._domainkey", map[string]interface{}{}); err != nil {
		t.Fatalf("publishDistributedUpsert with raw zone: %v", err)
	}
	// ...and the delete tombstone must be emitted too.
	if err := publishDistributedDelete("dist.test", "TXT", "sel._domainkey"); err != nil {
		t.Fatalf("publishDistributedDelete with raw zone: %v", err)
	}

	events, err := distributed.Default.Events("node-a", 0)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	var sawUpsert, sawDelete bool
	for _, ev := range events {
		if ev.Name != "sel._domainkey" {
			continue
		}
		if ev.Zone != "dist.test." {
			t.Errorf("event op=%s keyed zone=%q, want FQDN %q", ev.Operation, ev.Zone, "dist.test.")
		}
		switch ev.Operation {
		case distributed.OperationUpsert:
			sawUpsert = true
		case distributed.OperationDelete:
			sawDelete = true
		}
	}
	if !sawUpsert {
		t.Errorf("no upsert event emitted for the record")
	}
	if !sawDelete {
		t.Errorf("no delete tombstone emitted for the record")
	}
}
