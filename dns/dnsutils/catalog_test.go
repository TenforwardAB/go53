package dnsutils

import (
	"testing"

	"github.com/miekg/dns"

	"go53/config"
	"go53/memory"
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
	config.AppConfig.Live = config.DefaultLiveConfig
	config.AppConfig.Live.Mode = mode
	config.AppConfig.Live.DNSSECEnabled = false
	config.AppConfig.Live.Secondary.CatalogEnabled = true
	config.AppConfig.Live.Secondary.CatalogZone = "_catalog.go53."
	config.AppConfig.Live.Secondary.MinFetchIntervalSec = 0
	store, err := memory.NewZoneStore(backend)
	if err != nil {
		t.Fatalf("NewZoneStore: %v", err)
	}
	rtypes.InitMemoryStore(store)
	clearFetchQueue()
	stateMu.Lock()
	zoneStates = make(map[string]*zoneState)
	stateMu.Unlock()
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
	config.AppConfig.Live.Mode = "secondary"

	got := map[string]bool{}
	for _, z := range refreshZoneUnion() {
		got[z] = true
	}
	if !got["_catalog.go53."] || !got["member.example."] {
		t.Fatalf("refreshZoneUnion = %v, want catalog and member", got)
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
