package dnsutils

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"go53/config"
	"go53/memory"
	"go53/storage"
	"go53/types"
	"go53/zone"
	"go53/zone/rtypes"
)

func setupAliasFlattenStore(t *testing.T, mode string) {
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
	mem, err := memory.NewZoneStore(backend)
	if err != nil {
		t.Fatalf("NewZoneStore: %v", err)
	}
	rtypes.InitMemoryStore(mem)
}

func stubAliasResolver(t *testing.T, answers map[string][]net.IP, errs map[string]error) {
	t.Helper()
	prev := aliasLookupIP
	aliasLookupIP = func(_ context.Context, network, host string) ([]net.IP, error) {
		key := network + "|" + host
		if err, ok := errs[key]; ok {
			return nil, err
		}
		return answers[key], nil
	}
	t.Cleanup(func() { aliasLookupIP = prev })
}

func stubAliasNow(t *testing.T, at time.Time) {
	t.Helper()
	prev := aliasNow
	aliasNow = func() time.Time { return at }
	t.Cleanup(func() { aliasNow = prev })
}

func addAliasFixture(t *testing.T, zoneName, name, target string) {
	t.Helper()
	if err := zone.AddRecord(dns.TypeSOA, zoneName, "@", map[string]interface{}{
		"ns": "ns1." + zoneName, "mbox": "hostmaster." + zoneName,
		"serial": float64(1), "refresh": float64(3600), "retry": float64(600),
		"expire": float64(86400), "minimum": float64(300), "ttl": float64(300),
	}, nil); err != nil {
		t.Fatalf("add SOA: %v", err)
	}
	if err := zone.AddRecord(types.AliasTypeCode, zoneName, name, map[string]interface{}{"target": target}, nil); err != nil {
		t.Fatalf("add ALIAS: %v", err)
	}
}

func TestFlattenAliasesWritesARecords(t *testing.T) {
	setupAliasFlattenStore(t, "primary")
	addAliasFixture(t, "flatten.test.", "@", "edge.example.net.")
	stubAliasResolver(t, map[string][]net.IP{
		"ip4|edge.example.net.": {net.ParseIP("192.0.2.10"), net.ParseIP("192.0.2.11")},
	}, map[string]error{
		"ip6|edge.example.net.": errors.New("no AAAA"),
	})

	FlattenAliases(context.Background())

	rrs, ok := zone.LookupRecord(dns.TypeA, "flatten.test.")
	if !ok || len(rrs) != 2 {
		t.Fatalf("expected 2 flattened A records, got %#v ok=%v", rrs, ok)
	}
	for _, rr := range rrs {
		if rr.Header().Ttl != 60 {
			t.Errorf("expected flattened TTL 60, got %d", rr.Header().Ttl)
		}
	}
}

func TestFlattenAliasesUpdatesAfterFreshnessWindow(t *testing.T) {
	setupAliasFlattenStore(t, "primary")
	addAliasFixture(t, "reflatten.test.", "@", "edge.example.net.")
	stubAliasResolver(t, map[string][]net.IP{
		"ip4|edge.example.net.": {net.ParseIP("192.0.2.10")},
	}, nil)
	FlattenAliases(context.Background())

	stubAliasResolver(t, map[string][]net.IP{
		"ip4|edge.example.net.": {net.ParseIP("198.51.100.5")},
	}, nil)
	stubAliasNow(t, time.Now().Add(aliasFreshnessWindow+time.Second))
	FlattenAliases(context.Background())

	rrs, ok := zone.LookupRecord(dns.TypeA, "reflatten.test.")
	if !ok || len(rrs) != 1 {
		t.Fatalf("expected 1 flattened A record, got %#v ok=%v", rrs, ok)
	}
	if a, _ := rrs[0].(*dns.A); a == nil || a.A.String() != "198.51.100.5" {
		t.Fatalf("expected updated IP 198.51.100.5, got %v", rrs[0])
	}
}

func TestFlattenAliasesDefersWhileFresh(t *testing.T) {
	setupAliasFlattenStore(t, "primary")
	addAliasFixture(t, "defer.test.", "@", "edge.example.net.")
	stubAliasResolver(t, map[string][]net.IP{
		"ip4|edge.example.net.": {net.ParseIP("192.0.2.10")},
	}, nil)
	FlattenAliases(context.Background())

	stubAliasResolver(t, map[string][]net.IP{
		"ip4|edge.example.net.": {net.ParseIP("198.51.100.5")},
	}, nil)
	FlattenAliases(context.Background())

	rrs, ok := zone.LookupRecord(dns.TypeA, "defer.test.")
	if !ok || len(rrs) != 1 {
		t.Fatalf("expected 1 flattened A record, got %#v ok=%v", rrs, ok)
	}
	if a, _ := rrs[0].(*dns.A); a == nil || a.A.String() != "192.0.2.10" {
		t.Fatalf("expected fresh write to be deferred, got %v", rrs[0])
	}
}

func TestFlattenAliasesKeepsStaleOnResolveError(t *testing.T) {
	setupAliasFlattenStore(t, "primary")
	addAliasFixture(t, "stale.test.", "@", "edge.example.net.")
	stubAliasResolver(t, map[string][]net.IP{
		"ip4|edge.example.net.": {net.ParseIP("192.0.2.10")},
	}, nil)
	FlattenAliases(context.Background())

	stubAliasResolver(t, nil, map[string]error{
		"ip4|edge.example.net.": errors.New("upstream down"),
		"ip6|edge.example.net.": errors.New("upstream down"),
	})
	stubAliasNow(t, time.Now().Add(aliasFreshnessWindow+time.Second))
	FlattenAliases(context.Background())

	rrs, ok := zone.LookupRecord(dns.TypeA, "stale.test.")
	if !ok || len(rrs) != 1 {
		t.Fatalf("expected stale A record to survive resolve failure, got %#v ok=%v", rrs, ok)
	}
}

func TestFlattenAliasesNoopInSecondaryMode(t *testing.T) {
	setupAliasFlattenStore(t, "secondary")
	addAliasFixture(t, "secondary.test.", "@", "edge.example.net.")
	stubAliasResolver(t, map[string][]net.IP{
		"ip4|edge.example.net.": {net.ParseIP("192.0.2.10")},
	}, nil)

	FlattenAliases(context.Background())

	if _, ok := zone.LookupRecord(dns.TypeA, "secondary.test."); ok {
		t.Fatalf("secondary mode must not flatten aliases")
	}
}

func TestAliasDeleteCleansFlattenedRecords(t *testing.T) {
	setupAliasFlattenStore(t, "primary")
	addAliasFixture(t, "cleanup.test.", "@", "edge.example.net.")
	stubAliasResolver(t, map[string][]net.IP{
		"ip4|edge.example.net.": {net.ParseIP("192.0.2.10")},
	}, nil)
	FlattenAliases(context.Background())

	if err := zone.DeleteRecord(types.AliasTypeCode, "cleanup.test.", nil); err != nil {
		t.Fatalf("delete ALIAS: %v", err)
	}
	if _, ok := zone.LookupRecord(dns.TypeA, "cleanup.test."); ok {
		t.Fatalf("expected flattened A records to be removed with the ALIAS")
	}
}

func TestFlattenAliasesMarksFlattenedRecords(t *testing.T) {
	setupAliasFlattenStore(t, "primary")
	addAliasFixture(t, "marked.test.", "@", "edge.example.net.")
	stubAliasResolver(t, map[string][]net.IP{
		"ip4|edge.example.net.": {net.ParseIP("192.0.2.10")},
	}, nil)
	FlattenAliases(context.Background())

	_, _, raw, ok := rtypes.GetMemStore().GetRecord("marked.test.", string(types.TypeA), "@")
	if !ok {
		t.Fatalf("expected flattened A record in store")
	}
	entries, ok := raw.([]map[string]interface{})
	if !ok || len(entries) != 1 {
		t.Fatalf("unexpected stored shape %T", raw)
	}
	if marked, _ := entries[0]["alias"].(bool); !marked {
		t.Fatalf("flattened record must carry the alias marker")
	}
	if at, _ := entries[0]["resolved_at"].(float64); at <= 0 {
		t.Fatalf("flattened record must carry a resolved_at stamp")
	}
}

func TestFlattenAliasesCleansOrphans(t *testing.T) {
	setupAliasFlattenStore(t, "primary")
	addAliasFixture(t, "orphan.test.", "@", "edge.example.net.")
	stubAliasResolver(t, map[string][]net.IP{
		"ip4|edge.example.net.": {net.ParseIP("192.0.2.10")},
	}, nil)
	FlattenAliases(context.Background())

	store := rtypes.GetMemStore()
	if err := store.DeleteRecord("orphan.test.", string(types.TypeALIAS), "@"); err != nil {
		t.Fatalf("delete ALIAS row: %v", err)
	}
	if _, ok := zone.LookupRecord(dns.TypeA, "orphan.test."); !ok {
		t.Fatalf("flattened A should still exist before cleanup sweep")
	}

	FlattenAliases(context.Background())

	if _, ok := zone.LookupRecord(dns.TypeA, "orphan.test."); ok {
		t.Fatalf("orphaned flattened A records must be cleaned up")
	}
}

func TestFlattenAliasesKeepsUserRecordsDuringCleanup(t *testing.T) {
	setupAliasFlattenStore(t, "primary")
	if err := zone.AddRecord(dns.TypeSOA, "userkeep.test.", "@", map[string]interface{}{
		"ns": "ns1.userkeep.test.", "mbox": "hostmaster.userkeep.test.",
		"serial": float64(1), "refresh": float64(3600), "retry": float64(600),
		"expire": float64(86400), "minimum": float64(300), "ttl": float64(300),
	}, nil); err != nil {
		t.Fatalf("add SOA: %v", err)
	}
	if err := zone.AddRecord(dns.TypeA, "userkeep.test.", "www", map[string]interface{}{"ip": "203.0.113.9"}, nil); err != nil {
		t.Fatalf("add user A: %v", err)
	}

	FlattenAliases(context.Background())

	if _, ok := zone.LookupRecord(dns.TypeA, "www.userkeep.test."); !ok {
		t.Fatalf("user-created A records must never be removed by cleanup")
	}
}

func TestFlattenAliasesTakesOverStaleUnmarkedRecords(t *testing.T) {
	setupAliasFlattenStore(t, "primary")
	addAliasFixture(t, "takeover.test.", "@", "edge.example.net.")
	if err := zone.AddRecord(dns.TypeA, "takeover.test.", "@", map[string]interface{}{"ip": "203.0.113.7"}, nil); err != nil {
		t.Fatalf("add pre-existing A: %v", err)
	}
	stubAliasResolver(t, map[string][]net.IP{
		"ip4|edge.example.net.": {net.ParseIP("192.0.2.10")},
	}, nil)

	FlattenAliases(context.Background())

	rrs, ok := zone.LookupRecord(dns.TypeA, "takeover.test.")
	if !ok || len(rrs) != 1 {
		t.Fatalf("expected flattener to own A at alias name, got %#v ok=%v", rrs, ok)
	}
	if a, _ := rrs[0].(*dns.A); a == nil || a.A.String() != "192.0.2.10" {
		t.Fatalf("expected alias resolution to replace unmarked records, got %v", rrs[0])
	}
}
