package memory

import (
	"encoding/json"
	"testing"

	"github.com/miekg/dns"

	"go53/config"
	"go53/storage"
	"go53/types"
)

func TestEncodeDecodeZoneData(t *testing.T) {
	decoded, err := decodeZoneData(nil)
	if err != nil {
		t.Fatalf("decode empty: %v", err)
	}
	if len(decoded) != 0 {
		t.Fatalf("decoded empty = %#v", decoded)
	}

	data := map[string]map[string]any{
		"A": {
			"www": map[string]any{"ip": "192.0.2.1", "ttl": float64(300)},
		},
	}
	raw, err := encodeZoneData(data)
	if err != nil {
		t.Fatalf("encode zone data: %v", err)
	}
	roundTrip, err := decodeZoneData(raw)
	if err != nil {
		t.Fatalf("decode zone data: %v", err)
	}
	if roundTrip["A"]["www"].(map[string]any)["ip"] != "192.0.2.1" {
		t.Fatalf("round trip = %#v", roundTrip)
	}

	if _, err := encodeZoneData(nil); err == nil {
		t.Fatalf("encode nil succeeded")
	}
	if _, err := decodeZoneData([]byte(`{`)); err == nil {
		t.Fatalf("decode invalid JSON succeeded")
	}
}

func TestZoneStoreLoadsPersistsAndRendersRecords(t *testing.T) {
	backend := setupMemoryStoreBackend(t)
	seed := map[string]map[string]any{
		"A": {
			"www": []any{map[string]any{"ip": "192.0.2.10", "ttl": float64(180)}},
		},
		"TXT": {
			"@": []any{map[string]any{"text": "hello", "ttl": float64(60)}},
		},
	}
	raw, err := json.Marshal(seed)
	if err != nil {
		t.Fatalf("marshal seed: %v", err)
	}
	if err := backend.SaveZone("example.test.", raw); err != nil {
		t.Fatalf("save seed: %v", err)
	}

	store, err := NewZoneStore(backend)
	if err != nil {
		t.Fatalf("NewZoneStore: %v", err)
	}
	names := store.ZoneNamesSnapshot()
	if len(names) != 1 || names[0] != "example.test." {
		t.Fatalf("zone names = %#v", names)
	}
	zoneSnapshot := store.ZoneRecordsSnapshot("example.test.")
	if zoneSnapshot["A"]["www"] == nil {
		t.Fatalf("snapshot missing A record: %#v", zoneSnapshot)
	}

	rrs, err := store.GetZone("example.test.")
	if err != nil {
		t.Fatalf("GetZone: %v", err)
	}
	if len(rrs) != 2 {
		t.Fatalf("GetZone returned %d RRs: %#v", len(rrs), rrs)
	}
	if _, _, rec, ok := store.GetRecord("example.test.", "A", "www"); !ok || rec == nil {
		t.Fatalf("GetRecord failed: rec=%#v ok=%v", rec, ok)
	}

	if err := store.AddRecord("example.test.", "AAAA", "v6", map[string]any{"ip": "2001:db8::10"}); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}
	if _, _, _, ok := store.GetRecord("example.test.", "AAAA", "v6"); !ok {
		t.Fatalf("AAAA was not stored")
	}
	if err := store.DeleteRecord("example.test.", "AAAA", "v6"); err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}
	if _, _, _, ok := store.GetRecord("example.test.", "AAAA", "v6"); ok {
		t.Fatalf("AAAA remained after delete")
	}
	if err := store.DeleteRecord("example.test.", "NOPE", "v6"); err == nil {
		t.Fatalf("DeleteRecord missing type succeeded")
	}

	persisted, err := backend.LoadZone("example.test.")
	if err != nil {
		t.Fatalf("LoadZone persisted: %v", err)
	}
	if len(persisted) == 0 {
		t.Fatalf("persisted zone is empty")
	}
}

func TestZoneOwnerFQDNAndMissingZone(t *testing.T) {
	if got := zoneOwnerFQDN("example.test.", "@"); got != "example.test." {
		t.Fatalf("apex fqdn = %q", got)
	}
	if got := zoneOwnerFQDN("example.test.", "www"); got != "www.example.test." {
		t.Fatalf("relative fqdn = %q", got)
	}
	if got := zoneOwnerFQDN("example.test.", "WWW.EXAMPLE.TEST."); got != "WWW.EXAMPLE.TEST." {
		t.Fatalf("absolute fqdn = %q", got)
	}

	store, err := NewZoneStore(setupMemoryStoreBackend(t))
	if err != nil {
		t.Fatalf("NewZoneStore: %v", err)
	}
	if _, err := store.GetZone("missing.test."); err == nil {
		t.Fatalf("GetZone missing zone succeeded")
	}
}

func TestAuthoritativeNamePartsUsesLongestMatchingZone(t *testing.T) {
	store, err := NewZoneStore(setupMemoryStoreBackend(t))
	if err != nil {
		t.Fatalf("NewZoneStore: %v", err)
	}
	if err := store.AddRecord("example.co.uk.", "SOA", "@", map[string]any{"ns": "ns1.example.co.uk.", "mbox": "hostmaster.example.co.uk.", "serial": float64(1), "refresh": float64(3600), "retry": float64(600), "expire": float64(86400), "minimum": float64(300), "ttl": float64(300)}); err != nil {
		t.Fatalf("AddRecord example.co.uk.: %v", err)
	}
	if err := store.AddRecord("co.uk.", "SOA", "@", map[string]any{"ns": "ns1.co.uk.", "mbox": "hostmaster.co.uk.", "serial": float64(1), "refresh": float64(3600), "retry": float64(600), "expire": float64(86400), "minimum": float64(300), "ttl": float64(300)}); err != nil {
		t.Fatalf("AddRecord co.uk.: %v", err)
	}

	zoneName, host, ok := store.AuthoritativeNameParts("www.example.co.uk.")
	if !ok {
		t.Fatalf("AuthoritativeNameParts returned false")
	}
	if zoneName != "example.co.uk." || host != "www" {
		t.Fatalf("AuthoritativeNameParts = %q %q, want example.co.uk. www", zoneName, host)
	}
}

func TestSignZoneTransferRRsetsNoopWhenDNSSECDisabled(t *testing.T) {
	store, err := NewZoneStore(setupMemoryStoreBackend(t))
	if err != nil {
		t.Fatalf("NewZoneStore: %v", err)
	}
	rr := &dns.A{Hdr: dns.RR_Header{Name: "www.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}}
	out := store.SignZoneTransferRRsets([]dns.RR{rr})
	if len(out) != 1 || out[0] != rr {
		t.Fatalf("SignZoneTransferRRsets disabled = %#v", out)
	}
	if sigs, err := store.EnsureSignedRRSet([]dns.RR{rr}); err != nil || sigs != nil {
		t.Fatalf("EnsureSignedRRSet disabled sigs=%#v err=%v", sigs, err)
	}
	if _, err := store.EnsureSignedRRSet(nil); err == nil {
		t.Fatalf("EnsureSignedRRSet empty succeeded")
	}
}

func TestAddRecordRejectsCNAMECoexistence(t *testing.T) {
	store, zone := newMemoryTestStore(t)

	if err := store.AddRecord(zone, "CNAME", "alias", types.CNAMERecord{Target: "target.example.test.", TTL: 300}); err != nil {
		t.Fatalf("Add CNAME: %v", err)
	}
	if err := store.AddRecord(zone, "A", "alias", []types.ARecord{{IP: "192.0.2.10", TTL: 300}}); err == nil {
		t.Fatalf("Add A at CNAME owner succeeded")
	}

	if err := store.AddRecord(zone, "A", "www", []types.ARecord{{IP: "192.0.2.11", TTL: 300}}); err != nil {
		t.Fatalf("Add A: %v", err)
	}
	if err := store.AddRecord(zone, "CNAME", "www", types.CNAMERecord{Target: "target.example.test.", TTL: 300}); err == nil {
		t.Fatalf("Add CNAME at A owner succeeded")
	}
}

func TestAddRecordRejectsMixedRRSetTTL(t *testing.T) {
	store, zone := newMemoryTestStore(t)

	if err := store.AddRecord(zone, "A", "www", []types.ARecord{{IP: "192.0.2.10", TTL: 300}}); err != nil {
		t.Fatalf("Add first A: %v", err)
	}
	if err := store.AddRecord(zone, "A", "www", []types.ARecord{{IP: "192.0.2.11", TTL: 600}}); err == nil {
		t.Fatalf("Add mixed TTL A succeeded")
	}
	if err := store.AddRecord(zone, "A", "www", []types.ARecord{{IP: "192.0.2.12", TTL: 300}}); err != nil {
		t.Fatalf("Add same TTL A: %v", err)
	}
}

func setupMemoryStoreBackend(t *testing.T) *storage.MockStorage {
	t.Helper()
	backend := &storage.MockStorage{}
	if err := backend.Init(); err != nil {
		t.Fatalf("init mock storage: %v", err)
	}
	storage.Backend = backend
	config.AppConfig = &config.ConfigManager{}
	config.AppConfig.SetLive(config.DefaultLiveConfig)
	config.AppConfig.LiveForTest().DNSSECEnabled = false
	return backend
}

func newMemoryTestStore(t *testing.T) (*InMemoryZoneStore, string) {
	t.Helper()
	store, err := NewZoneStore(setupMemoryStoreBackend(t))
	if err != nil {
		t.Fatalf("NewZoneStore: %v", err)
	}
	return store, "example.test."
}

// TestGetRecordBridgesTrailingDot is a regression test for issue #53. Records are
// stored under the FQDN-sanitized zone key ("example.test."), but the distributed
// publish path looked them up with the raw URL zone ("example.test"), and
// GetRecord's fuzzy match only bridged case, not the trailing dot. The miss
// produced a spurious "stored record not found after add" and left delete
// tombstones keyed wrong, so anti-entropy resurrected deleted records.
func TestGetRecordBridgesTrailingDot(t *testing.T) {
	store, err := NewZoneStore(setupMemoryStoreBackend(t))
	if err != nil {
		t.Fatalf("NewZoneStore: %v", err)
	}
	// Stored under the FQDN zone key, exactly as the rtypes Add path does.
	if err := store.AddRecord("example.test.", "TXT", "sel._domainkey",
		map[string]any{"text": "v=DKIM1", "ttl": float64(3600)}); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}

	// Looking it up with the raw (non-FQDN) zone the HTTP handler passes must hit.
	zoneKey, _, rec, ok := store.GetRecord("example.test", "TXT", "sel._domainkey")
	if !ok || rec == nil {
		t.Fatalf("GetRecord with non-FQDN zone missed the record (the #53 bug)")
	}
	// And it must report the canonical stored zone key, so replicated events are
	// keyed consistently with storage/Merkle.
	if zoneKey != "example.test." {
		t.Errorf("expected canonical zone key %q, got %q", "example.test.", zoneKey)
	}

	// The FQDN form must keep working too.
	if _, _, _, ok := store.GetRecord("example.test.", "TXT", "sel._domainkey"); !ok {
		t.Errorf("GetRecord with FQDN zone should still resolve")
	}
}
