package memory

import (
	"fmt"
	"testing"

	"go53/types"
)

// checkOwnerIndex asserts that the index for every zone equals what a full
// scan of the record map yields. Called after every mutation path below so
// any writer that forgets to maintain the index fails loudly.
func checkOwnerIndex(t *testing.T, store *InMemoryZoneStore) {
	t.Helper()
	store.mu.RLock()
	defer store.mu.RUnlock()
	for zone, zoneMap := range store.cache["zones"] {
		want := map[string]map[string]bool{}
		for rtype, names := range zoneMap {
			if !shouldMaintainNSEC(rtype) {
				continue
			}
			for owner := range names {
				if want[owner] == nil {
					want[owner] = map[string]bool{}
				}
				want[owner][rtype] = true
			}
		}
		idx := store.ownerIdx[zone]
		if len(idx) != len(want) {
			t.Fatalf("zone %s: index has %d owners, scan has %d\n index=%v\n scan=%v", zone, len(idx), len(want), idx, want)
		}
		for owner, rtypes := range want {
			if _, ok := idx[owner]; !ok {
				t.Fatalf("zone %s: owner %q missing from index", zone, owner)
			}
			for rtype := range rtypes {
				if !store.ownerHasTypeLocked(zone, ownerFQDN(zone, owner), rtype) {
					t.Fatalf("zone %s: index lacks %s at %q", zone, rtype, owner)
				}
			}
			for _, absent := range []string{"NS", "SOA", "A", "TXT"} {
				if !rtypes[absent] && store.ownerHasTypeLocked(zone, ownerFQDN(zone, owner), absent) {
					t.Fatalf("zone %s: index claims %s at %q which the map does not have", zone, absent, owner)
				}
			}
		}
	}
	for zone := range store.ownerIdx {
		if _, ok := store.cache["zones"][zone]; !ok {
			t.Fatalf("index has zone %s that the map does not", zone)
		}
	}
}

func TestOwnerIndexTracksEveryMutationPath(t *testing.T) {
	backend := setupMemoryStoreBackend(t)
	store, err := NewZoneStore(backend)
	if err != nil {
		t.Fatal(err)
	}
	zone := "idx.test."
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		checkOwnerIndex(t, store)
	}

	must(store.AddRecord(zone, "SOA", "@", types.SOARecord{Ns: "ns1." + zone, Mbox: "h." + zone, TTL: 300}))
	must(store.AddRecord(zone, "NS", "@", []types.NSRecord{{NS: "ns1." + zone, TTL: 300}}))
	must(store.AddRecord(zone, "A", "www", []types.ARecord{{IP: "192.0.2.1", TTL: 300}}))
	must(store.AddRecord(zone, "AAAA", "www", []types.AAAARecord{{IP: "2001:db8::1", TTL: 300}}))
	must(store.AddRecord(zone, "NS", "child", []types.NSRecord{{NS: "ns.child." + zone, TTL: 300}}))
	must(store.AddRecord(zone, "A", "*.wild", []types.ARecord{{IP: "192.0.2.2", TTL: 300}}))
	must(store.PutRecordRaw(zone, "TXT", "txt", []any{map[string]any{"text": "x", "ttl": float64(60)}}))
	// A type the index does not track must not create an owner.
	must(store.PutRecordRaw(zone, "NSEC", "orphan", map[string]any{"next_domain": zone, "ttl": float64(60)}))
	must(store.AddRecord(zone, "MX", "MiXeD", []types.MXRecord{{Host: "mx." + zone, Priority: 10, TTL: 300}})) // canonicalised key

	// Remove one of two types at an owner: owner stays.
	must(store.DeleteRecord(zone, "AAAA", "www"))
	store.mu.RLock()
	if !store.ownerExistsLocked(zone, "www."+zone) || store.ownerHasTypeLocked(zone, "www."+zone, "AAAA") {
		t.Fatal("www should still exist with A only")
	}
	store.mu.RUnlock()
	// Remove the last type: owner goes.
	must(store.DeleteRecordRaw(zone, "A", "www"))
	store.mu.RLock()
	if store.ownerExistsLocked(zone, "www."+zone) {
		t.Fatal("www should be gone")
	}
	store.mu.RUnlock()
	// Deleting something that is not there is harmless.
	_ = store.DeleteRecord(zone, "A", "nope")
	checkOwnerIndex(t, store)

	// A reload from storage rebuilds the index from persisted data.
	reloaded, err := NewZoneStore(backend)
	if err != nil {
		t.Fatal(err)
	}
	checkOwnerIndex(t, reloaded)
	reloaded.mu.RLock()
	if !reloaded.ownerExistsLocked(zone, "txt."+zone) || !reloaded.ownerHasTypeLocked(zone, "child."+zone, "NS") {
		t.Fatal("reloaded index incomplete")
	}
	reloaded.mu.RUnlock()

	must(store.DeleteZone(zone))
	if _, ok := store.ownerIdx[zone]; ok {
		t.Fatal("DeleteZone left the index behind")
	}
}

func TestOwnerIndexRebuildMatchesIncremental(t *testing.T) {
	backend := setupMemoryStoreBackend(t)
	store, err := NewZoneStore(backend)
	if err != nil {
		t.Fatal(err)
	}
	zone := "rebuild.test."
	for i := 0; i < 50; i++ {
		owner := fmt.Sprintf("h%d", i)
		if err := store.AddRecord(zone, "A", owner, []types.ARecord{{IP: "192.0.2.1", TTL: 60}}); err != nil {
			t.Fatal(err)
		}
		if i%3 == 0 {
			if err := store.AddRecord(zone, "TXT", owner, []types.TXTRecord{{Text: "t", TTL: 60}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	for i := 0; i < 50; i += 2 {
		if err := store.DeleteRecord(zone, "A", fmt.Sprintf("h%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	checkOwnerIndex(t, store)
	store.mu.Lock()
	incremental := fmt.Sprint(store.ownerIdx[zone])
	store.rebuildOwnerIndexLocked(zone)
	rebuilt := fmt.Sprint(store.ownerIdx[zone])
	store.mu.Unlock()
	if incremental != rebuilt {
		t.Fatalf("incremental index differs from rebuild\n inc=%s\n reb=%s", incremental, rebuilt)
	}
}

func TestClosestEncloserAndDelegation(t *testing.T) {
	backend := setupMemoryStoreBackend(t)
	store, err := NewZoneStore(backend)
	if err != nil {
		t.Fatal(err)
	}
	zone := "enc.test."
	for _, r := range []struct{ rtype, owner string }{
		{"SOA", "@"}, {"NS", "@"}, {"A", "www"}, {"A", "a.b.c"}, {"A", "*.b.c"},
		{"NS", "sub"}, {"A", "deep.sub"},
	} {
		var v any
		switch r.rtype {
		case "SOA":
			v = types.SOARecord{Ns: "ns1." + zone, Mbox: "h." + zone, TTL: 300}
		case "NS":
			v = []types.NSRecord{{NS: "ns1." + zone, TTL: 300}}
		default:
			v = []types.ARecord{{IP: "192.0.2.1", TTL: 300}}
		}
		if err := store.AddRecord(zone, r.rtype, r.owner, v); err != nil {
			t.Fatal(err)
		}
	}
	store.mu.RLock()
	defer store.mu.RUnlock()

	cases := []struct {
		q                          string
		encloser, nextCloser, wild string
		ok                         bool
	}{
		{"www." + zone, "www." + zone, "www." + zone, "*.www." + zone, true},       // exact
		{"x.www." + zone, "www." + zone, "x.www." + zone, "*.www." + zone, true},   // one below
		{"y.x.www." + zone, "www." + zone, "x.www." + zone, "*.www." + zone, true}, // two below
		{"nope." + zone, zone, "nope." + zone, "*." + zone, true},                  // apex is the encloser
		{"WWW." + zone, "www." + zone, "www." + zone, "*.www." + zone, true},       // case-folded
		{"q.b.c." + zone, "b.c." + zone, "q.b.c." + zone, "*.b.c." + zone, true},   // wildcard parent exists via *.b.c? no: b.c itself does not exist
		{"other.zone.", "", "", "", false},                                         // outside
	}
	// "b.c" has no records itself; only "a.b.c" and "*.b.c" do. Its closest
	// encloser is the apex. Fix the expectation accordingly.
	cases[5] = struct {
		q                          string
		encloser, nextCloser, wild string
		ok                         bool
	}{"q.b.c." + zone, zone, "c." + zone, "*." + zone, true}

	for _, c := range cases {
		enc, next, wild, ok := store.closestEncloserLocked(zone, c.q)
		if ok != c.ok || enc != c.encloser || next != c.nextCloser || wild != c.wild {
			t.Errorf("closestEncloser(%q) = (%q, %q, %q, %v); want (%q, %q, %q, %v)", c.q, enc, next, wild, ok, c.encloser, c.nextCloser, c.wild, c.ok)
		}
	}

	if d, ok := store.closestDelegationLocked(zone, "deep.sub."+zone); !ok || d != "sub."+zone {
		t.Errorf("delegation for deep.sub = %q,%v", d, ok)
	}
	if d, ok := store.closestDelegationLocked(zone, "sub."+zone); !ok || d != "sub."+zone {
		t.Errorf("delegation for sub = %q,%v", d, ok)
	}
	if _, ok := store.closestDelegationLocked(zone, "www."+zone); ok {
		t.Error("www must not be a delegation")
	}
	if _, ok := store.closestDelegationLocked(zone, zone); ok {
		t.Error("the apex (NS with SOA) must not be a delegation")
	}
	if !store.ownerExistsLocked(zone, "*.b.c."+zone) || !store.ownerExistsLocked(zone, zone) {
		t.Error("wildcard owner and apex must exist")
	}
}

func TestClosestEncloserAllocFree(t *testing.T) {
	backend := setupMemoryStoreBackend(t)
	store, err := NewZoneStore(backend)
	if err != nil {
		t.Fatal(err)
	}
	zone := "alloc.test."
	_ = store.AddRecord(zone, "SOA", "@", types.SOARecord{Ns: "ns1." + zone, Mbox: "h." + zone, TTL: 300})
	_ = store.AddRecord(zone, "A", "www", []types.ARecord{{IP: "192.0.2.1", TTL: 300}})
	store.mu.RLock()
	defer store.mu.RUnlock()
	q := "a.b.missing." + zone
	allocs := testing.AllocsPerRun(500, func() {
		if !store.ownerExistsLocked(zone, "www."+zone) {
			t.Fatal("www")
		}
		if _, ok := store.closestDelegationLocked(zone, q); ok {
			t.Fatal("unexpected delegation")
		}
	})
	if allocs != 0 {
		t.Fatalf("existence + delegation walk allocates %.1f/op", allocs)
	}
	// The encloser walk allocates once: the "*."+encloser wildcard string.
	allocs = testing.AllocsPerRun(500, func() {
		if _, _, _, ok := store.closestEncloserLocked(zone, q); !ok {
			t.Fatal("no encloser")
		}
	})
	if allocs > 1 {
		t.Fatalf("encloser walk allocates %.1f/op, want <= 1", allocs)
	}
}
