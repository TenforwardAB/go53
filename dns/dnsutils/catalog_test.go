package dnsutils

import (
	"testing"

	"github.com/miekg/dns"

	"go53/config"
	"go53/memory"
	"go53/security"
	"go53/storage"
	"go53/zone"
	"go53/zone/rtypes"
)

func setupCatalogTestStore(t *testing.T, mode string) {
	t.Helper()
	backend := &storage.MockStorage{}
	if err := backend.Init(); err != nil {
		t.Fatalf("storage init: %v", err)
	}
	storage.Backend = backend
	config.AppConfig = &config.ConfigManager{}
	config.AppConfig.SetLive(config.DefaultLiveConfig)
	config.AppConfig.LiveForTest().Mode = mode
	config.AppConfig.LiveForTest().DNSSECEnabled = false
	config.AppConfig.LiveForTest().Secondary.CatalogEnabled = true
	config.AppConfig.LiveForTest().Secondary.CatalogZone = "_catalog.go53."
	config.AppConfig.LiveForTest().Secondary.MinFetchIntervalSec = 0
	store, err := memory.NewZoneStore(backend)
	if err != nil {
		t.Fatalf("NewZoneStore: %v", err)
	}
	rtypes.InitMemoryStore(store)
	clearFetchQueue()
	stateMu.Lock()
	zoneStates = make(map[string]*zoneState)
	stateMu.Unlock()
	security.TSIGSecrets = nil
}

func TestEnsureCatalogMemberCreatesRFC9432Catalog(t *testing.T) {
	setupCatalogTestStore(t, "primary")
	addTestSOA(t, "customer.example.")

	if err := EnsureCatalogMember("customer.example."); err != nil {
		t.Fatalf("EnsureCatalogMember: %v", err)
	}

	if _, ok := zone.LookupRecord(dns.TypeSOA, "_catalog.go53."); !ok {
		t.Fatalf("catalog SOA missing")
	}
	if _, ok := zone.LookupRecord(dns.TypeNS, "_catalog.go53."); !ok {
		t.Fatalf("catalog NS missing")
	}
	if _, ok := zone.LookupRecord(dns.TypeTXT, "version._catalog.go53."); !ok {
		t.Fatalf("catalog version TXT missing")
	}

	owner := catalogMemberOwner("customer.example.", "_catalog.go53.")
	rrs, ok := zone.LookupRecord(dns.TypePTR, owner)
	if !ok || len(rrs) != 1 {
		t.Fatalf("catalog member PTR = %#v ok=%v", rrs, ok)
	}
	ptr, ok := rrs[0].(*dns.PTR)
	if !ok || ptr.Ptr != "customer.example." {
		t.Fatalf("catalog member PTR = %#v", rrs[0])
	}
}

func TestRefreshZoneUnionIncludesCatalogAndMembers(t *testing.T) {
	setupCatalogTestStore(t, "primary")
	addTestSOA(t, "member.example.")
	if err := EnsureCatalogMember("member.example."); err != nil {
		t.Fatalf("EnsureCatalogMember: %v", err)
	}
	config.AppConfig.LiveForTest().Mode = "secondary"

	got := map[string]bool{}
	for _, z := range refreshZoneUnion() {
		got[z] = true
	}
	if !got["_catalog.go53."] || !got["member.example."] {
		t.Fatalf("refreshZoneUnion = %v, want catalog and member", got)
	}
}

func TestPruneRemovedCatalogMembersDeletesOnlyRemovedMembers(t *testing.T) {
	setupCatalogTestStore(t, "secondary")
	addTestSOA(t, "old.example.")
	addTestSOA(t, "keep.example.")

	pruneRemovedCatalogMembers(
		[]string{"old.example.", "keep.example."},
		[]string{"keep.example."},
	)

	if _, ok := zone.LookupRecord(dns.TypeSOA, "old.example."); ok {
		t.Fatalf("old catalog member still exists")
	}
	if _, ok := zone.LookupRecord(dns.TypeSOA, "keep.example."); !ok {
		t.Fatalf("kept catalog member was deleted")
	}
}

func TestPruneRemovedCatalogMembersKeepsConfiguredZones(t *testing.T) {
	setupCatalogTestStore(t, "secondary")
	config.AppConfig.LiveForTest().Secondary.Zones = []string{"manual.example."}
	addTestSOA(t, "manual.example.")

	pruneRemovedCatalogMembers([]string{"manual.example."}, nil)

	if _, ok := zone.LookupRecord(dns.TypeSOA, "manual.example."); !ok {
		t.Fatalf("configured zone was deleted")
	}
}

func TestCatalogPrimariesParsesGlobalAAndAAAA(t *testing.T) {
	setupCatalogTestStore(t, "secondary")
	addCatalogBaseForTest(t)
	addCatalogA(t, "ns1.primaries.ext", "192.0.2.53")
	addCatalogAAAA(t, "ns2.primaries.ext", "2001:db8::53")

	got := catalogPrimariesForZone("member.example.")
	want := map[string]bool{"192.0.2.53:53": true, "[2001:db8::53]:53": true}
	if len(got) != len(want) {
		t.Fatalf("catalog primaries = %#v, want %d entries", got, len(want))
	}
	for _, primary := range got {
		if !want[primary.addr()] {
			t.Fatalf("unexpected primary %s in %#v", primary.addr(), got)
		}
	}
}

func TestCatalogPrimariesMastersSynonym(t *testing.T) {
	setupCatalogTestStore(t, "secondary")
	addCatalogBaseForTest(t)
	addCatalogA(t, "legacy.masters.ext", "192.0.2.54")

	got := catalogPrimariesForZone("member.example.")
	if len(got) != 1 || got[0].addr() != "192.0.2.54:53" {
		t.Fatalf("masters primaries = %#v, want 192.0.2.54:53", got)
	}
}

func TestCatalogPrimariesMemberOverride(t *testing.T) {
	setupCatalogTestStore(t, "secondary")
	addCatalogBaseForTest(t)
	addCatalogPTR(t, "m1.zones", "member.example.")
	addCatalogA(t, "global.primaries.ext", "192.0.2.53")
	addCatalogA(t, "member.primaries.ext.m1.zones", "192.0.2.99")

	got := catalogPrimariesForZone("member.example.")
	if len(got) != 1 || got[0].addr() != "192.0.2.99:53" {
		t.Fatalf("member override primaries = %#v, want only 192.0.2.99:53", got)
	}
}

func TestCatalogPrimariesIgnoresUnknownMemberLabel(t *testing.T) {
	setupCatalogTestStore(t, "secondary")
	addCatalogBaseForTest(t)
	addCatalogPTR(t, "m1.zones", "member.example.")
	addCatalogA(t, "orphan.primaries.ext.other.zones", "192.0.2.99")

	if got := catalogPrimariesForZone("member.example."); len(got) != 0 {
		t.Fatalf("unexpected primaries for unknown member label: %#v", got)
	}
}

func TestCatalogPrimariesAssociatesTSIGKeyName(t *testing.T) {
	setupCatalogTestStore(t, "secondary")
	security.SetTSIGKey("xfr-key.", security.TSIGKey{Algorithm: dns.HmacSHA256, Secret: "YWJjMTIz"})
	addCatalogBaseForTest(t)
	addCatalogA(t, "ns1.primaries.ext", "192.0.2.53")
	addCatalogTXT(t, "ns1.primaries.ext", "xfr-key.")

	got := catalogPrimariesForZone("member.example.")
	if len(got) != 1 || got[0].addr() != "192.0.2.53:53" || got[0].TSIGKeyName != "xfr-key." {
		t.Fatalf("catalog TSIG primaries = %#v, want xfr-key primary", got)
	}
}

func TestCatalogPrimariesSkipsMissingTSIGKey(t *testing.T) {
	setupCatalogTestStore(t, "secondary")
	addCatalogBaseForTest(t)
	addCatalogA(t, "ns1.primaries.ext", "192.0.2.53")
	addCatalogTXT(t, "ns1.primaries.ext", "missing-key.")

	if got := catalogPrimariesForZone("member.example."); len(got) != 0 {
		t.Fatalf("missing-key TSIG primary should be skipped: %#v", got)
	}
}

func TestCatalogPrimariesSkipsInvalidTSIGTXT(t *testing.T) {
	setupCatalogTestStore(t, "secondary")
	security.SetTSIGKey("xfr-key.", security.TSIGKey{Algorithm: dns.HmacSHA256, Secret: "YWJjMTIz"})
	addCatalogBaseForTest(t)
	addCatalogA(t, "ns1.primaries.ext", "192.0.2.53")
	addCatalogTXT(t, "ns1.primaries.ext", "xfr-key.")
	addCatalogTXT(t, "ns1.primaries.ext", "other-key.")

	if got := catalogPrimariesForZone("member.example."); len(got) != 0 {
		t.Fatalf("multi-TXT TSIG primary should be skipped: %#v", got)
	}
}

func addTestSOA(t *testing.T, name string) {
	t.Helper()
	if err := zone.AddRecord(dns.TypeSOA, name, name, map[string]interface{}{
		"ns":      "ns1." + name,
		"mbox":    "hostmaster." + name,
		"refresh": float64(3600),
		"retry":   float64(600),
		"expire":  float64(86400),
		"minimum": float64(300),
		"ttl":     float64(300),
	}, nil); err != nil {
		t.Fatalf("add SOA %s: %v", name, err)
	}
}

func addCatalogBaseForTest(t *testing.T) {
	t.Helper()
	ttl := uint32(300)
	if err := ensureCatalogBase("_catalog.go53.", ttl); err != nil {
		t.Fatalf("ensure catalog base: %v", err)
	}
}

func addCatalogA(t *testing.T, name, ip string) {
	t.Helper()
	ttl := uint32(300)
	if err := zone.AddRecord(dns.TypeA, "_catalog.go53.", name, map[string]interface{}{"ip": ip}, &ttl); err != nil {
		t.Fatalf("add catalog A %s: %v", name, err)
	}
}

func addCatalogAAAA(t *testing.T, name, ip string) {
	t.Helper()
	ttl := uint32(300)
	if err := zone.AddRecord(dns.TypeAAAA, "_catalog.go53.", name, map[string]interface{}{"ip": ip}, &ttl); err != nil {
		t.Fatalf("add catalog AAAA %s: %v", name, err)
	}
}

func addCatalogPTR(t *testing.T, name, ptr string) {
	t.Helper()
	ttl := uint32(300)
	if err := zone.AddRecord(dns.TypePTR, "_catalog.go53.", name, map[string]interface{}{"ptr": ptr}, &ttl); err != nil {
		t.Fatalf("add catalog PTR %s: %v", name, err)
	}
}

func addCatalogTXT(t *testing.T, name, text string) {
	t.Helper()
	ttl := uint32(300)
	if err := zone.AddRecord(dns.TypeTXT, "_catalog.go53.", name, map[string]interface{}{"text": text}, &ttl); err != nil {
		t.Fatalf("add catalog TXT %s: %v", name, err)
	}
}
