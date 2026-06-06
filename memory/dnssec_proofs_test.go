package memory

import (
	"testing"
	"time"

	"github.com/miekg/dns"

	"go53/config"
	"go53/types"
)

func TestDNSSECDenialProofsAndOwnerHelpers(t *testing.T) {
	store, zone := setupDNSSECProofStore(t)

	if !store.NameExists("www." + zone) {
		t.Fatalf("NameExists returned false for www")
	}
	if store.NameExists("missing." + zone) {
		t.Fatalf("NameExists returned true for missing owner")
	}
	wildcard, ok := store.WildcardName("missing.wild." + zone)
	if !ok || wildcard != "*.wild."+zone {
		t.Fatalf("WildcardName = %q ok=%v", wildcard, ok)
	}
	if !store.WildcardExists("missing.wild." + zone) {
		t.Fatalf("WildcardExists returned false")
	}
	delegation, ns, ok := store.DelegationFor("host.child." + zone)
	if !ok || delegation != "child."+zone || len(ns) != 1 {
		t.Fatalf("DelegationFor = delegation=%q ns=%#v ok=%v", delegation, ns, ok)
	}

	nsec, ok := store.FindNSECProof("missing." + zone)
	if !ok || len(nsec) == 0 || nsec[0].Header().Rrtype != dns.TypeNSEC {
		t.Fatalf("FindNSECProof = %#v ok=%v", nsec, ok)
	}
	nsec3, ok := store.FindNSEC3Proof("missing." + zone)
	if !ok || len(nsec3) == 0 || nsec3[0].Header().Rrtype != dns.TypeNSEC3 {
		t.Fatalf("FindNSEC3Proof = %#v ok=%v", nsec3, ok)
	}

	nxProofs := store.DenialProofs("missing."+zone, dns.TypeA, true)
	if len(nxProofs) == 0 {
		t.Fatalf("NXDOMAIN denial proofs empty")
	}
	noDataProofs := store.DenialProofs("www."+zone, dns.TypeMX, false)
	if len(noDataProofs) == 0 {
		t.Fatalf("no-data denial proofs empty")
	}
	wildcardProofs := store.DenialProofs("missing.wild."+zone, dns.TypeA, false)
	if len(wildcardProofs) == 0 {
		t.Fatalf("wildcard denial proofs empty")
	}
}

func TestDNSSECChainRebuildAndRawConverters(t *testing.T) {
	store, zone := setupDNSSECProofStore(t)
	store.mu.RLock()
	nsecMap := store.cache["zones"][zone][string(types.TypeNSEC)]
	nsec3Map := store.cache["zones"][zone][string(types.TypeNSEC3)]
	store.mu.RUnlock()
	if len(nsecMap) == 0 || len(nsec3Map) == 0 {
		t.Fatalf("rebuilt chains are empty: nsec=%#v nsec3=%#v", nsecMap, nsec3Map)
	}

	if rec, ok := nsecRecordFromRaw(map[string]interface{}{"next_domain": "next.example.test.", "types": []interface{}{"A", "RRSIG"}, "ttl": float64(300)}); !ok || rec.TTL != 300 || len(rec.Types) != 2 {
		t.Fatalf("nsecRecordFromRaw map = %#v ok=%v", rec, ok)
	}
	if _, ok := nsecRecordFromRaw("bad"); ok {
		t.Fatalf("nsecRecordFromRaw accepted bad input")
	}
	if rec, ok := nsec3ParamFromRaw(map[string]interface{}{"hash_algorithm": float64(1), "flags": float64(1), "iterations": float64(0), "salt": "-", "ttl": float64(300)}); !ok || rec.Salt != "" || rec.Flags != 1 {
		t.Fatalf("nsec3ParamFromRaw map = %#v ok=%v", rec, ok)
	}
	if rec, ok := nsec3RecordFromRaw(map[string]interface{}{"hash_algorithm": float64(1), "flags": float64(1), "iterations": float64(0), "salt": "-", "next_hashed": dns.HashName(zone, dns.SHA1, 0, ""), "types": []interface{}{"A"}, "ttl": float64(300)}); !ok || rec.HashAlg != 1 || len(rec.Types) != 1 {
		t.Fatalf("nsec3RecordFromRaw map = %#v ok=%v", rec, ok)
	}
	if nsec3HashLength(dns.HashName(zone, dns.SHA1, 0, "")) == 0 {
		t.Fatalf("nsec3HashLength returned 0 for valid hash")
	}
	if nsec3SaltLength("ABCD") != 2 || nsec3SaltLength("bad") != 0 {
		t.Fatalf("nsec3SaltLength unexpected")
	}
	if !nsecCovers("b."+zone, "d."+zone, "c."+zone) {
		t.Fatalf("nsecCovers linear interval returned false")
	}
	if !nsec3Covers("F", "3", "0") {
		t.Fatalf("nsec3Covers wrap interval returned false")
	}
}

func TestRRSIGCacheHelpers(t *testing.T) {
	store, err := NewZoneStore(setupMemoryStoreBackend(t))
	if err != nil {
		t.Fatalf("NewZoneStore: %v", err)
	}
	zone := "sig.test."
	sig := &types.RRSIGRecord{
		TypeCovered: "A",
		Algorithm:   15,
		Labels:      3,
		OrigTTL:     300,
		Expiration:  uint32(time.Now().Add(10 * 24 * time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-time.Minute).Unix()),
		KeyTag:      12345,
		SignerName:  zone,
		Signature:   "abc",
		TTL:         300,
	}
	store.storeRRSIG(zone, "A", "www", sig)
	store.storeRRSIG(zone, "A", "www", sig)

	cached := store.cachedRRSIGs(zone, "A", "www", dns.TypeA, "www."+zone)
	if len(cached) != 1 {
		t.Fatalf("cachedRRSIGs returned %d records: %#v", len(cached), cached)
	}
	if parsed := rrsigRecordsFromRaw([]interface{}{map[string]interface{}{"type_covered": "A", "algorithm": float64(15), "labels": float64(3), "original_ttl": float64(300), "expiration": float64(sig.Expiration), "inception": float64(sig.Inception), "key_tag": float64(12345), "signer_name": zone, "signature": "abc", "ttl": float64(300)}}); len(parsed) != 1 {
		t.Fatalf("rrsigRecordsFromRaw parsed %d records", len(parsed))
	}
	if _, err := rrsigRecordToDNS("www."+zone, &types.RRSIGRecord{TypeCovered: "NOPE"}); err == nil {
		t.Fatalf("rrsigRecordToDNS accepted invalid covered type")
	}

	store.mu.Lock()
	store.invalidateRRSIGLocked(zone, "A", "www")
	store.mu.Unlock()
	if cached := store.cachedRRSIGs(zone, "A", "www", dns.TypeA, "www."+zone); len(cached) != 0 {
		t.Fatalf("RRSIG cache remained after invalidate: %#v", cached)
	}
}

func setupDNSSECProofStore(t *testing.T) (*InMemoryZoneStore, string) {
	t.Helper()
	backend := setupMemoryStoreBackend(t)
	configureProofDefaults()
	store, err := NewZoneStore(backend)
	if err != nil {
		t.Fatalf("NewZoneStore: %v", err)
	}
	zone := "proof.test."
	store.cache["zones"][zone] = map[string]map[string]any{
		string(types.TypeSOA): {
			"@": types.SOARecord{Ns: "ns1.proof.test.", Mbox: "hostmaster.proof.test.", Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300, TTL: 300},
		},
		string(types.TypeNS): {
			"@":     []types.NSRecord{{NS: "ns1.proof.test.", TTL: 300}},
			"child": []types.NSRecord{{NS: "ns.child.proof.test.", TTL: 300}},
		},
		string(types.TypeA): {
			"www":    []types.ARecord{{IP: "192.0.2.1", TTL: 300}},
			"wild":   []types.ARecord{{IP: "192.0.2.3", TTL: 300}},
			"*.wild": []types.ARecord{{IP: "192.0.2.2", TTL: 300}},
		},
		"NSEC3PARAM": {
			"@": types.NSEC3ParamRecord{HashAlgorithm: dns.SHA1, Flags: 1, Iterations: 0, Salt: "", TTL: 300},
		},
	}
	store.mu.Lock()
	store.rebuildNSECChainLocked(zone)
	store.rebuildNSEC3ChainLocked(zone)
	store.mu.Unlock()
	return store, zone
}

func configureProofDefaults() {
	config.AppConfig.Live.DefaultTTL = 300
	config.AppConfig.Live.DNSSECEnabled = false
}
