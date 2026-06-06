package memory

import (
	"encoding/json"
	"testing"

	"github.com/miekg/dns"

	"go53/config"
	"go53/storage"
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

func setupMemoryStoreBackend(t *testing.T) *storage.MockStorage {
	t.Helper()
	backend := &storage.MockStorage{}
	if err := backend.Init(); err != nil {
		t.Fatalf("init mock storage: %v", err)
	}
	storage.Backend = backend
	config.AppConfig = &config.ConfigManager{}
	config.AppConfig.Live = config.DefaultLiveConfig
	config.AppConfig.Live.DNSSECEnabled = false
	return backend
}
