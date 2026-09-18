package memory

import (
	"encoding/json"
	"testing"

	"go53/config"
	"go53/storage"
	"go53/types"
)

func TestAddRecordCanonicalizesZoneAndName(t *testing.T) {
	store, _ := newMemoryTestStore(t)

	value := []any{map[string]any{"ip": "192.0.2.7", "ttl": float64(120)}}
	if err := store.AddRecord("Example.COM", "A", "WWW", value); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}

	zone, _, rec, ok := store.GetRecord("example.com.", "A", "www")
	if !ok {
		t.Fatalf("canonical lookup missed")
	}
	if zone != "example.com." {
		t.Fatalf("zone = %q, want canonical %q", zone, "example.com.")
	}
	if rec == nil {
		t.Fatalf("record missing")
	}

	if _, _, _, ok := store.GetRecord("EXAMPLE.com", "A", "WwW"); !ok {
		t.Fatalf("mixed-case lookup missed")
	}

	snapshot := store.ZoneRecordsSnapshot("example.com.")
	if _, ok := snapshot["A"]["www"]; !ok {
		t.Fatalf("stored name key not canonical: %#v", snapshot["A"])
	}
	if _, ok := snapshot["A"]["WWW"]; ok {
		t.Fatalf("legacy-cased key stored alongside canonical: %#v", snapshot["A"])
	}
}

func TestDeleteRecordCanonicalizes(t *testing.T) {
	store, _ := newMemoryTestStore(t)

	value := []any{map[string]any{"ip": "192.0.2.8", "ttl": float64(120)}}
	if err := store.AddRecord("example.com.", "A", "www", value); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}
	if err := store.DeleteRecord("Example.Com", "A", "WWW"); err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}
	if _, _, _, ok := store.GetRecord("example.com.", "A", "www"); ok {
		t.Fatalf("record survived case-insensitive delete")
	}
}

func TestLoadFromStorageMigratesLegacyKeys(t *testing.T) {
	backend := setupMemoryStoreBackend(t)

	seed := map[string]map[string]any{
		"A": {
			"WWW": []any{map[string]any{"ip": "192.0.2.20", "ttl": float64(300)}},
		},
		"NSEC3": {
			// Uppercase base32 hash keys must never be case-folded.
			"P0GA1APK4C3STG52M1S4Q8AR2SVCSHRK": map[string]any{"next_hashed": "Q0GA1APK4C3STG52M1S4Q8AR2SVCSHRL"},
		},
		"RRSIG": {
			// Covered-type keys stay; nested owner keys are canonicalized.
			"A": map[string]any{
				"WWW": []any{map[string]any{"type_covered": "A"}},
			},
		},
	}
	raw, err := json.Marshal(seed)
	if err != nil {
		t.Fatalf("marshal seed: %v", err)
	}
	if err := backend.SaveZone("Example.COM", raw); err != nil {
		t.Fatalf("save seed: %v", err)
	}

	store, err := NewZoneStore(backend)
	if err != nil {
		t.Fatalf("NewZoneStore: %v", err)
	}

	if _, _, _, ok := store.GetRecord("example.com.", "A", "www"); !ok {
		t.Fatalf("migrated record not reachable via canonical keys")
	}

	snapshot := store.ZoneRecordsSnapshot("example.com.")
	if _, ok := snapshot["NSEC3"]["P0GA1APK4C3STG52M1S4Q8AR2SVCSHRK"]; !ok {
		t.Fatalf("NSEC3 hash key was case-folded: %#v", snapshot["NSEC3"])
	}
	inner, ok := snapshot["RRSIG"]["A"].(map[string]any)
	if !ok {
		t.Fatalf("RRSIG covered-type key missing: %#v", snapshot["RRSIG"])
	}
	if _, ok := inner["www"]; !ok {
		t.Fatalf("RRSIG nested owner key not canonicalized: %#v", inner)
	}

	if _, ok := backend.Zones["Example.COM"]; ok {
		t.Fatalf("legacy storage key still present after migration")
	}
	if _, ok := backend.Zones["example.com."]; !ok {
		t.Fatalf("canonical storage key missing after migration: %v", zoneKeys(backend.Zones))
	}
}

func TestAuthoritativeNamePartsCanonical(t *testing.T) {
	store, _ := newMemoryTestStore(t)

	value := []any{map[string]any{"ip": "192.0.2.9", "ttl": float64(120)}}
	if err := store.AddRecord("Example.COM", "A", "www", value); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}
	if err := store.AddRecord("sub.example.com.", "A", "www", value); err != nil {
		t.Fatalf("AddRecord sub: %v", err)
	}

	zone, host, ok := store.AuthoritativeNameParts("WWW.Sub.Example.COM")
	if !ok {
		t.Fatalf("no authoritative zone found")
	}
	if zone != "sub.example.com." {
		t.Fatalf("zone = %q, want longest canonical match %q", zone, "sub.example.com.")
	}
	if host != "www" {
		t.Fatalf("host = %q, want %q", host, "www")
	}

	zone, host, ok = store.AuthoritativeNameParts("example.com")
	if !ok || zone != "example.com." || host != "@" {
		t.Fatalf("apex parts = %q %q %v", zone, host, ok)
	}

	if _, _, ok := store.AuthoritativeNameParts("otherexample.com."); ok {
		t.Fatalf("suffix without label boundary must not match")
	}
}

func TestCaseSensitiveNameKeys(t *testing.T) {
	if !caseSensitiveNameKeys(string(types.TypeNSEC3)) || !caseSensitiveNameKeys(string(types.TypeRRSIG)) {
		t.Fatalf("NSEC3/RRSIG must keep case-sensitive keys")
	}
	if caseSensitiveNameKeys("A") || caseSensitiveNameKeys(string(types.TypeNSEC)) {
		t.Fatalf("regular owner-name keyed types must canonicalize")
	}
}

func zoneKeys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestGetRecordCanonicalInputAllocFree(t *testing.T) {
	store, _ := newMemoryTestStore(t)
	value := []any{map[string]any{"ip": "192.0.2.30", "ttl": float64(120)}}
	if err := store.AddRecord("example.com.", "A", "www", value); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}
	allocs := testing.AllocsPerRun(1000, func() {
		if _, _, _, ok := store.GetRecord("example.com.", "A", "www"); !ok {
			t.Fatalf("lookup missed")
		}
	})
	if allocs != 0 {
		t.Fatalf("GetRecord allocated %.1f times per canonical lookup", allocs)
	}
}

func BenchmarkGetRecordCanonical(b *testing.B) {
	store := newBenchStore(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		store.GetRecord("example.com.", "A", "www")
	}
}

func BenchmarkGetRecordMixedCase(b *testing.B) {
	store := newBenchStore(b)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		store.GetRecord("EXAMPLE.COM", "A", "WWW")
	}
}

func newBenchStore(b *testing.B) *InMemoryZoneStore {
	b.Helper()
	backend := &storage.MockStorage{}
	if err := backend.Init(); err != nil {
		b.Fatalf("init mock storage: %v", err)
	}
	storage.Backend = backend
	config.AppConfig = &config.ConfigManager{}
	config.AppConfig.SetLive(config.DefaultLiveConfig)
	config.AppConfig.LiveForTest().DNSSECEnabled = false
	store, err := NewZoneStore(backend)
	if err != nil {
		b.Fatalf("NewZoneStore: %v", err)
	}
	value := []any{map[string]any{"ip": "192.0.2.40", "ttl": float64(120)}}
	if err := store.AddRecord("example.com.", "A", "www", value); err != nil {
		b.Fatalf("AddRecord: %v", err)
	}
	return store
}
