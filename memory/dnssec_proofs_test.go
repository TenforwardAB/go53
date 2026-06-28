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

	requireNameExists(t, store, "www."+zone)
	requireNameMissing(t, store, "missing."+zone)
	wildcard, ok := store.WildcardName(owner(zone, "missing.wild"))
	if !ok || wildcard != "*.wild."+zone {
		t.Fatalf("WildcardName = %q ok=%v", wildcard, ok)
	}
	if !store.WildcardExists(owner(zone, "missing.wild")) {
		t.Fatalf("WildcardExists returned false")
	}
	delegation, ns, ok := store.DelegationFor(owner(zone, "host.child"))
	if !ok || delegation != "child."+zone || len(ns) != 1 {
		t.Fatalf("DelegationFor = delegation=%q ns=%#v ok=%v", delegation, ns, ok)
	}

	nsec, ok := store.FindNSECProof(owner(zone, "missing"))
	requireProof(t, "FindNSECProof", dns.TypeNSEC, nsec, ok)
	nsec3, ok := store.FindNSEC3Proof(owner(zone, "missing"))
	requireProof(t, "FindNSEC3Proof", dns.TypeNSEC3, nsec3, ok)
	requireDenialProofs(t, store, "NXDOMAIN", owner(zone, "missing"), dns.TypeA, true)
	requireDenialProofs(t, store, "no-data", owner(zone, "www"), dns.TypeMX, false)
	requireDenialProofs(t, store, "wildcard", owner(zone, "missing.wild"), dns.TypeA, false)
	requireWildcardNODATAProofSet(t, store, zone)
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

	if rec, ok := nsecRecordFromRaw(nsecRaw("next.example.test.", "A", "RRSIG")); !ok || rec.TTL != proofTTL || len(rec.Types) != 2 {
		t.Fatalf("nsecRecordFromRaw map = %#v ok=%v", rec, ok)
	}
	if _, ok := nsecRecordFromRaw("bad"); ok {
		t.Fatalf("nsecRecordFromRaw accepted bad input")
	}
	if rec, ok := nsec3ParamFromRaw(nsec3ParamRaw("-", 1)); !ok || rec.Salt != "" || rec.Flags != 1 {
		t.Fatalf("nsec3ParamFromRaw map = %#v ok=%v", rec, ok)
	}
	if rec, ok := nsec3RecordFromRaw(nsec3Raw(zone, "-", "A")); !ok || rec.HashAlg != 1 || len(rec.Types) != 1 {
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
	store := setupProofZoneStore(t)
	zone := "sig.test."
	sig := testRRSIG(zone)
	store.storeRRSIG(zone, "A", "www", sig)
	store.storeRRSIG(zone, "A", "www", sig)

	cached := store.cachedRRSIGs(zone, "A", "www", dns.TypeA, owner(zone, "www"))
	if len(cached) != 1 {
		t.Fatalf("cachedRRSIGs returned %d records: %#v", len(cached), cached)
	}
	if parsed := rrsigRecordsFromRaw([]interface{}{rrsigRaw(zone, sig)}); len(parsed) != 1 {
		t.Fatalf("rrsigRecordsFromRaw parsed %d records", len(parsed))
	}
	if _, err := rrsigRecordToDNS(owner(zone, "www"), &types.RRSIGRecord{TypeCovered: "NOPE"}); err == nil {
		t.Fatalf("rrsigRecordToDNS accepted invalid covered type")
	}

	store.mu.Lock()
	store.invalidateRRSIGLocked(zone, "A", "www")
	store.mu.Unlock()
	if cached := store.cachedRRSIGs(zone, "A", "www", dns.TypeA, owner(zone, "www")); len(cached) != 0 {
		t.Fatalf("RRSIG cache remained after invalidate: %#v", cached)
	}
}

func setupDNSSECProofStore(t *testing.T) (*InMemoryZoneStore, string) {
	t.Helper()
	configureProofDefaults()
	store := setupProofZoneStore(t)
	zone := "proof.test."
	store.cache["zones"][zone] = map[string]map[string]any{
		string(types.TypeSOA): {
			"@": proofSOA(),
		},
		string(types.TypeNS): {
			"@":     nsRecords("ns1." + zone),
			"child": nsRecords("ns.child." + zone),
		},
		string(types.TypeA): {
			"www":    aRecords("192.0.2.1"),
			"wild":   aRecords("192.0.2.3"),
			"*.wild": aRecords("192.0.2.2"),
		},
		"NSEC3PARAM": {
			"@": proofNSEC3Param(),
		},
	}
	store.mu.Lock()
	store.rebuildNSECChainLocked(zone)
	store.rebuildNSEC3ChainLocked(zone)
	store.mu.Unlock()
	return store, zone
}

const proofTTL = 300

func setupProofZoneStore(t *testing.T) *InMemoryZoneStore {
	t.Helper()
	store, err := NewZoneStore(setupMemoryStoreBackend(t))
	if err != nil {
		t.Fatalf("NewZoneStore: %v", err)
	}
	return store
}

func configureProofDefaults() {
	config.AppConfig.LiveForTest().DefaultTTL = proofTTL
	config.AppConfig.LiveForTest().DNSSECEnabled = false
}

func owner(zone, name string) string {
	return name + "." + zone
}

func requireNameExists(t *testing.T, store *InMemoryZoneStore, name string) {
	t.Helper()
	if !store.NameExists(name) {
		t.Fatalf("NameExists(%q) returned false", name)
	}
}

func requireNameMissing(t *testing.T, store *InMemoryZoneStore, name string) {
	t.Helper()
	if store.NameExists(name) {
		t.Fatalf("NameExists(%q) returned true", name)
	}
}

func requireProof(t *testing.T, label string, rrtype uint16, proof []dns.RR, ok bool) {
	t.Helper()
	if !ok || len(proof) == 0 || proof[0].Header().Rrtype != rrtype {
		t.Fatalf("%s = %#v ok=%v", label, proof, ok)
	}
}

func requireDenialProofs(t *testing.T, store *InMemoryZoneStore, label, name string, rrtype uint16, nxdomain bool) {
	t.Helper()
	if proofs := store.DenialProofs(name, rrtype, nxdomain); len(proofs) == 0 {
		t.Fatalf("%s denial proofs empty", label)
	}
}

func requireWildcardNODATAProofSet(t *testing.T, store *InMemoryZoneStore, zone string) {
	t.Helper()
	proofs := store.DenialProofs(owner(zone, "missing.wild"), dns.TypeDS, false)
	if len(proofs) < 3 {
		t.Fatalf("wildcard NODATA proofs = %d, want closest, next-closer, and wildcard proofs: %#v", len(proofs), proofs)
	}
}

func proofSOA() types.SOARecord {
	return types.SOARecord{
		Ns:      "ns1.proof.test.",
		Mbox:    "hostmaster.proof.test.",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minimum: proofTTL,
		TTL:     proofTTL,
	}
}

func nsRecords(ns string) []types.NSRecord {
	return []types.NSRecord{{NS: ns, TTL: proofTTL}}
}

func aRecords(ip string) []types.ARecord {
	return []types.ARecord{{IP: ip, TTL: proofTTL}}
}

func proofNSEC3Param() types.NSEC3ParamRecord {
	return types.NSEC3ParamRecord{
		HashAlgorithm: dns.SHA1,
		Flags:         1,
		Iterations:    0,
		Salt:          "",
		TTL:           proofTTL,
	}
}

func nsecRaw(next string, types ...string) map[string]interface{} {
	return map[string]interface{}{
		"next_domain": next,
		"types":       stringInterfaces(types...),
		"ttl":         float64(proofTTL),
	}
}

func nsec3ParamRaw(salt string, flags int) map[string]interface{} {
	return map[string]interface{}{
		"hash_algorithm": float64(dns.SHA1),
		"flags":          float64(flags),
		"iterations":     float64(0),
		"salt":           salt,
		"ttl":            float64(proofTTL),
	}
}

func nsec3Raw(zone, salt string, types ...string) map[string]interface{} {
	raw := nsec3ParamRaw(salt, 1)
	raw["next_hashed"] = dns.HashName(zone, dns.SHA1, 0, "")
	raw["types"] = stringInterfaces(types...)
	return raw
}

func stringInterfaces(values ...string) []interface{} {
	out := make([]interface{}, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

func testRRSIG(zone string) *types.RRSIGRecord {
	return &types.RRSIGRecord{
		TypeCovered: "A",
		Algorithm:   15,
		Labels:      3,
		OrigTTL:     proofTTL,
		Expiration:  uint32(time.Now().Add(10 * 24 * time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-time.Minute).Unix()),
		KeyTag:      12345,
		SignerName:  zone,
		Signature:   "abc",
		TTL:         proofTTL,
	}
}

func rrsigRaw(zone string, sig *types.RRSIGRecord) map[string]interface{} {
	return map[string]interface{}{
		"type_covered": sig.TypeCovered,
		"algorithm":    float64(sig.Algorithm),
		"labels":       float64(sig.Labels),
		"original_ttl": float64(sig.OrigTTL),
		"expiration":   float64(sig.Expiration),
		"inception":    float64(sig.Inception),
		"key_tag":      float64(sig.KeyTag),
		"signer_name":  zone,
		"signature":    sig.Signature,
		"ttl":          float64(sig.TTL),
	}
}
