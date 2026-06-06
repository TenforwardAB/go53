package memory

import (
	"testing"
	"time"

	"github.com/miekg/dns"

	"go53/types"
)

func TestRawRecordPersistenceAndDeleteZone(t *testing.T) {
	backend := setupMemoryStoreBackend(t)
	store, err := NewZoneStore(backend)
	if err != nil {
		t.Fatalf("NewZoneStore: %v", err)
	}

	if err := store.PutRecordRaw("raw.test.", "A", "www", []any{map[string]any{"ip": "192.0.2.1", "ttl": float64(300)}}); err != nil {
		t.Fatalf("PutRecordRaw: %v", err)
	}
	if _, _, raw, ok := store.GetRecord("raw.test.", "A", "www"); !ok || raw == nil {
		t.Fatalf("GetRecord after PutRecordRaw = %#v ok=%v", raw, ok)
	}
	if persisted, err := backend.LoadZone("raw.test."); err != nil || len(persisted) == 0 {
		t.Fatalf("LoadZone after PutRecordRaw len=%d err=%v", len(persisted), err)
	}

	if err := store.DeleteRecordRaw("raw.test.", "A", "www"); err != nil {
		t.Fatalf("DeleteRecordRaw: %v", err)
	}
	if _, _, _, ok := store.GetRecord("raw.test.", "A", "www"); ok {
		t.Fatalf("record remained after DeleteRecordRaw")
	}
	if err := store.DeleteRecordRaw("raw.test.", "TXT", "missing"); err != nil {
		t.Fatalf("DeleteRecordRaw missing record: %v", err)
	}

	if err := store.PutRecordRaw("raw.test.", "AAAA", "v6", []any{map[string]any{"ip": "2001:db8::1"}}); err != nil {
		t.Fatalf("PutRecordRaw before DeleteZone: %v", err)
	}
	if err := store.DeleteZone("raw.test."); err != nil {
		t.Fatalf("DeleteZone: %v", err)
	}
	if _, ok := store.cache["zones"]["raw.test."]; ok {
		t.Fatalf("zone remained in cache after DeleteZone")
	}
	if raw, _ := backend.LoadZone("raw.test."); raw != nil {
		t.Fatalf("zone remained in storage after DeleteZone: %q", string(raw))
	}
	if err := store.DeleteZone("missing.test."); err != nil {
		t.Fatalf("DeleteZone missing: %v", err)
	}
}

func TestRefreshDNSSECKeyMaterialPersistsWhenDisabled(t *testing.T) {
	backend := setupMemoryStoreBackend(t)
	store, err := NewZoneStore(backend)
	if err != nil {
		t.Fatalf("NewZoneStore: %v", err)
	}
	if err := store.RefreshDNSSECKeyMaterial("refresh.test."); err != nil {
		t.Fatalf("RefreshDNSSECKeyMaterial: %v", err)
	}
	if _, ok := store.cache["zones"]["refresh.test."]; !ok {
		t.Fatalf("RefreshDNSSECKeyMaterial did not create zone")
	}
	if persisted, err := backend.LoadZone("refresh.test."); err != nil || len(persisted) == 0 {
		t.Fatalf("RefreshDNSSECKeyMaterial persisted len=%d err=%v", len(persisted), err)
	}
	if err := store.RefreshDNSSECKeyMaterial("bad zone"); err == nil {
		t.Fatalf("RefreshDNSSECKeyMaterial accepted invalid zone")
	}
}

func TestRRSIGInvalidationHelpers(t *testing.T) {
	store, err := NewZoneStore(setupMemoryStoreBackend(t))
	if err != nil {
		t.Fatalf("NewZoneStore: %v", err)
	}
	zone := "sig-invalidate.test."
	sig := &types.RRSIGRecord{
		TypeCovered: "A",
		Algorithm:   15,
		Labels:      3,
		OrigTTL:     300,
		Expiration:  uint32(time.Now().Add(10 * 24 * time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-time.Minute).Unix()),
		KeyTag:      1,
		SignerName:  zone,
		Signature:   "abc",
		TTL:         300,
	}
	store.storeRRSIG(zone, "A", "www", sig)
	aaaaSig := *sig
	aaaaSig.TypeCovered = "AAAA"
	store.storeRRSIG(zone, "AAAA", "v6", &aaaaSig)

	store.mu.Lock()
	store.invalidateAllRRSIGLocked(zone, "A")
	store.invalidateAllRRSIGLocked("missing.test.", "A")
	store.mu.Unlock()
	if cached := store.cachedRRSIGs(zone, "A", "www", dns.TypeA, "www."+zone); len(cached) != 0 {
		t.Fatalf("A signatures remained after invalidateAllRRSIGLocked: %#v", cached)
	}
	if cached := store.cachedRRSIGs(zone, "AAAA", "v6", dns.TypeAAAA, "v6."+zone); len(cached) != 1 {
		t.Fatalf("AAAA signatures missing after A invalidation: %#v", cached)
	}

	store.mu.Lock()
	store.invalidateAllRRSIGsLocked(zone)
	store.invalidateAllRRSIGsLocked("missing.test.")
	store.mu.Unlock()
	if cached := store.cachedRRSIGs(zone, "AAAA", "v6", dns.TypeAAAA, "v6."+zone); len(cached) != 0 {
		t.Fatalf("signatures remained after invalidateAllRRSIGsLocked: %#v", cached)
	}
}

func TestNSECOnlyDenialProofInternals(t *testing.T) {
	store, zone := setupDNSSECProofStore(t)
	store.mu.Lock()
	delete(store.cache["zones"][zone], string(types.TypeNSEC3))
	delete(store.cache["zones"][zone], "NSEC3PARAM")
	nxdomain := store.nsecDenialProofsLocked(zone, "missing."+zone, dns.TypeA, true)
	noData := store.nsecDenialProofsLocked(zone, "www."+zone, dns.TypeMX, false)
	exact, exactOK := store.nsecExactLocked(zone, "www."+zone)
	covering, coveringOK := store.nsecCoveringLocked(zone, "missing."+zone)
	proof, proofOK := store.nsecProofLocked(zone, "missing."+zone)
	delete(store.cache["zones"][zone], string(types.TypeNSEC))
	_, noNSECExact := store.nsecExactLocked(zone, "www."+zone)
	_, noNSECCover := store.nsecCoveringLocked(zone, "missing."+zone)
	store.mu.Unlock()

	if len(nxdomain) == 0 || len(noData) == 0 {
		t.Fatalf("NSEC-only proofs empty: nxdomain=%#v nodata=%#v", nxdomain, noData)
	}
	if !exactOK || len(exact) != 1 || exact[0].Header().Rrtype != dns.TypeNSEC {
		t.Fatalf("nsecExactLocked = %#v ok=%v", exact, exactOK)
	}
	if !coveringOK || len(covering) != 1 || covering[0].Header().Rrtype != dns.TypeNSEC {
		t.Fatalf("nsecCoveringLocked = %#v ok=%v", covering, coveringOK)
	}
	if !proofOK || len(proof) != 1 {
		t.Fatalf("nsecProofLocked = %#v ok=%v", proof, proofOK)
	}
	if noNSECExact || noNSECCover {
		t.Fatalf("NSEC lookup succeeded after NSEC map removal")
	}
}

func TestHasOtherRecordsAndDeepSizeEdges(t *testing.T) {
	if size := DeepSize(&struct {
		Name string
		Next *int
	}{Name: "x"}); size == 0 {
		t.Fatalf("DeepSize returned 0 for non-empty struct")
	}
	if found, rrtype := HasOtherRecords[struct{}](nil, "util.test.", "www", dns.TypeA, map[uint16]struct{}{dns.TypeAAAA: {}}); found || rrtype != 0 {
		t.Fatalf("HasOtherRecords nil = found=%v rrtype=%d", found, rrtype)
	}

	store, err := NewZoneStore(setupMemoryStoreBackend(t))
	if err != nil {
		t.Fatalf("NewZoneStore: %v", err)
	}
	if err := store.PutRecordRaw("util.test.", "1", "www", "a"); err != nil {
		t.Fatalf("PutRecordRaw numeric type: %v", err)
	}
	registry := map[uint16]struct{}{dns.TypeA: {}, dns.TypeAAAA: {}}
	if found, rrtype := HasOtherRecords(store, "util.test.", "www", dns.TypeAAAA, registry); !found || rrtype != dns.TypeA {
		t.Fatalf("HasOtherRecords = found=%v rrtype=%d, want A", found, rrtype)
	}
	if found, rrtype := HasOtherRecords(store, "util.test.", "www", dns.TypeA, registry); found || rrtype != 0 {
		t.Fatalf("HasOtherRecords excluded type = found=%v rrtype=%d", found, rrtype)
	}
}
