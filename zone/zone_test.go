package zone

import (
	"testing"

	"github.com/miekg/dns"

	"go53/config"
	"go53/memory"
	"go53/storage"
	"go53/zone/rtypes"
)

func TestZoneFacadeRecordLifecycle(t *testing.T) {
	setupZoneFacadeTestStore(t)

	ttl := uint32(120)
	value := map[string]interface{}{"ip": "192.0.2.10"}
	if err := AddRecord(dns.TypeA, "facade.test.", "www", value, &ttl); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}

	records, ok := LookupRecord(dns.TypeA, "www.facade.test.")
	if !ok {
		t.Fatalf("LookupRecord did not find A record")
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	a, ok := records[0].(*dns.A)
	if !ok {
		t.Fatalf("record type = %T, want A", records[0])
	}
	if a.A.String() != "192.0.2.10" {
		t.Fatalf("A = %s, want 192.0.2.10", a.A.String())
	}
	if !NameExists("www.facade.test.") {
		t.Fatalf("NameExists returned false for stored owner")
	}

	if err := DeleteRecord(dns.TypeA, "www.facade.test.", "192.0.2.10"); err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}
	if _, ok := LookupRecord(dns.TypeA, "www.facade.test."); ok {
		t.Fatalf("LookupRecord found deleted A record")
	}
}

func TestZoneFacadeLookupUsesLongestAuthoritativeZone(t *testing.T) {
	setupZoneFacadeTestStore(t)

	if err := AddRecord(dns.TypeSOA, "example.co.uk.", "@", map[string]interface{}{"ns": "ns1.example.co.uk.", "mbox": "hostmaster.example.co.uk.", "serial": float64(1), "refresh": float64(3600), "retry": float64(600), "expire": float64(86400), "minimum": float64(300)}, nil); err != nil {
		t.Fatalf("AddRecord SOA: %v", err)
	}
	if err := AddRecord(dns.TypeA, "example.co.uk.", "www", map[string]interface{}{"ip": "192.0.2.53"}, nil); err != nil {
		t.Fatalf("AddRecord A: %v", err)
	}

	records, ok := LookupRecord(dns.TypeA, "www.example.co.uk.")
	if !ok {
		t.Fatalf("LookupRecord did not find public suffix-style zone record")
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	a, ok := records[0].(*dns.A)
	if !ok || a.A.String() != "192.0.2.53" {
		t.Fatalf("record = %#v, want A 192.0.2.53", records[0])
	}
}

func TestZoneFacadeDeleteZone(t *testing.T) {
	setupZoneFacadeTestStore(t)

	if err := AddRecord(dns.TypeA, "delete.test.", "www", map[string]interface{}{"ip": "192.0.2.11"}, nil); err != nil {
		t.Fatalf("AddRecord: %v", err)
	}
	if err := DeleteZone("delete.test."); err != nil {
		t.Fatalf("DeleteZone: %v", err)
	}
	if _, ok := LookupRecord(dns.TypeA, "www.delete.test."); ok {
		t.Fatalf("LookupRecord found record after DeleteZone")
	}
}

func TestZoneFacadeUnknownRRType(t *testing.T) {
	setupZoneFacadeTestStore(t)

	if err := AddRecord(65534, "unknown.test.", "www", map[string]interface{}{}, nil); err == nil {
		t.Fatalf("AddRecord unknown type succeeded")
	}
	if _, ok := LookupRecord(65534, "www.unknown.test."); ok {
		t.Fatalf("LookupRecord unknown type succeeded")
	}
	if err := DeleteRecord(65534, "www.unknown.test.", nil); err == nil {
		t.Fatalf("DeleteRecord unknown type succeeded")
	}
}

func TestZoneFacadeMemoryBackedDNSSECWrappers(t *testing.T) {
	setupZoneFacadeTestStore(t)

	if err := rtypes.GetMemStore().AddRecord("proof.test.", "SOA", "@", map[string]any{"ns": "ns1.proof.test.", "mbox": "hostmaster.proof.test.", "serial": float64(1), "refresh": float64(3600), "retry": float64(600), "expire": float64(86400), "minimum": float64(300), "ttl": float64(300)}); err != nil {
		t.Fatalf("Add SOA: %v", err)
	}
	if err := rtypes.GetMemStore().AddRecord("proof.test.", "A", "www", []map[string]interface{}{{"ip": "192.0.2.1", "ttl": float64(300)}}); err != nil {
		t.Fatalf("Add A: %v", err)
	}
	if err := RefreshDNSSECKeyMaterial("proof.test."); err != nil {
		t.Fatalf("RefreshDNSSECKeyMaterial: %v", err)
	}
	if !NameExists("www.proof.test.") {
		t.Fatalf("NameExists returned false")
	}
	if _, ok := FindNSECProof("missing.proof.test."); ok {
		t.Fatalf("FindNSECProof should be false with DNSSEC disabled/no chain")
	}
	if proofs := DenialProofs("missing.proof.test.", dns.TypeA, true); len(proofs) != 0 {
		t.Fatalf("DenialProofs = %#v", proofs)
	}
}

func TestZoneFacadeNilMemoryStoreWrappers(t *testing.T) {
	previous := rtypes.GetMemStore()
	rtypes.InitMemoryStore(nil)
	t.Cleanup(func() { rtypes.InitMemoryStore(previous) })

	if err := DeleteZone("nil.test."); err == nil {
		t.Fatalf("DeleteZone succeeded with nil memory store")
	}
	if _, err := EnsureSignedRRSet([]dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "www.nil.test.", Rrtype: dns.TypeA, Class: dns.ClassINET}}}); err == nil {
		t.Fatalf("EnsureSignedRRSet succeeded with nil memory store")
	}
	if err := RefreshDNSSECKeyMaterial("nil.test."); err == nil {
		t.Fatalf("RefreshDNSSECKeyMaterial succeeded with nil memory store")
	}
	if _, ok := FindNSECProof("missing.nil.test."); ok {
		t.Fatalf("FindNSECProof succeeded with nil memory store")
	}
	if _, ok := FindNSEC3Proof("missing.nil.test."); ok {
		t.Fatalf("FindNSEC3Proof succeeded with nil memory store")
	}
	if DenialProofs("missing.nil.test.", dns.TypeA, true) != nil {
		t.Fatalf("DenialProofs returned non-nil with nil memory store")
	}
	if NameExists("www.nil.test.") || WildcardExists("www.nil.test.") {
		t.Fatalf("existence wrappers returned true with nil memory store")
	}
	if wildcard, ok := WildcardName("www.nil.test."); ok || wildcard != "" {
		t.Fatalf("WildcardName = %q ok=%v", wildcard, ok)
	}
	if delegation, ns, ok := DelegationFor("www.nil.test."); ok || delegation != "" || ns != nil {
		t.Fatalf("DelegationFor = %q %#v ok=%v", delegation, ns, ok)
	}
}

func setupZoneFacadeTestStore(t *testing.T) {
	t.Helper()
	config.AppConfig = &config.ConfigManager{}
	config.AppConfig.SetLive(config.DefaultLiveConfig)
	config.AppConfig.LiveForTest().DNSSECEnabled = false

	backend := &storage.MockStorage{}
	if err := backend.Init(); err != nil {
		t.Fatalf("init mock storage: %v", err)
	}
	store, err := memory.NewZoneStore(backend)
	if err != nil {
		t.Fatalf("new zone store: %v", err)
	}
	rtypes.InitMemoryStore(store)
}
