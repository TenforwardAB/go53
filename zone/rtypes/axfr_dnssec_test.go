package rtypes

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"go53/config"
	"go53/security"
)

func TestAXFRIncludesCompleteDNSSECMaterial(t *testing.T) {
	config.AppConfig.SetLive(config.DefaultLiveConfig)
	config.AppConfig.LiveForTest().DNSSECEnabled = true
	config.AppConfig.LiveForTest().Mode = "primary"

	zone := "axfr-dnssec.test"
	ttl := uint32(3600)

	if err := mustRR(t, dns.TypeSOA).Add(zone, zone, map[string]interface{}{
		"ns":      "ns1." + zone,
		"mbox":    "hostmaster." + zone,
		"refresh": float64(3600),
		"retry":   float64(900),
		"expire":  float64(1209600),
		"minimum": float64(300),
	}, &ttl); err != nil {
		t.Fatalf("add SOA: %v", err)
	}

	now := time.Now().Unix()
	if _, _, err := security.GenerateRolloverKey(zone, "ksk", "ED25519", now-10, now-10); err != nil {
		t.Fatalf("generate KSK: %v", err)
	}
	if _, _, err := security.GenerateRolloverKey(zone, "zsk", "ED25519", now-10, now-10); err != nil {
		t.Fatalf("generate ZSK: %v", err)
	}
	if err := memStore.RefreshDNSSECKeyMaterial(zone); err != nil {
		t.Fatalf("refresh DNSSEC key material: %v", err)
	}

	if err := mustRR(t, dns.TypeA).Add(zone, "www", map[string]interface{}{"ip": "192.0.2.53"}, &ttl); err != nil {
		t.Fatalf("add A: %v", err)
	}
	if err := mustRR(t, dns.TypeNSEC3PARAM).Add(zone, "@", map[string]interface{}{
		"hash_algorithm": float64(1),
		"flags":          float64(0),
		"iterations":     float64(0),
		"salt":           "-",
	}, &ttl); err != nil {
		t.Fatalf("add NSEC3PARAM: %v", err)
	}

	rrs, ok := mustRR(t, dns.TypeAXFR).Lookup(zone + ".")
	if !ok {
		t.Fatalf("AXFR lookup failed")
	}

	if countType(rrs, dns.TypeSOA) != 2 {
		t.Fatalf("SOA count = %d, want opening and closing SOA", countType(rrs, dns.TypeSOA))
	}
	for _, rrtype := range []uint16{dns.TypeDNSKEY, dns.TypeCDS, dns.TypeCDNSKEY, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM} {
		if countType(rrs, rrtype) == 0 {
			t.Fatalf("AXFR missing %s", dns.TypeToString[rrtype])
		}
	}
	for _, covered := range []uint16{dns.TypeSOA, dns.TypeA, dns.TypeDNSKEY, dns.TypeCDS, dns.TypeCDNSKEY, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM} {
		if countRRSIGCovered(rrs, covered) == 0 {
			t.Fatalf("AXFR missing RRSIG covering %s", dns.TypeToString[covered])
		}
	}
}

func mustRR(t *testing.T, rrtype uint16) RRType {
	t.Helper()
	rr, ok := Get(rrtype)
	if !ok {
		t.Fatalf("rrtype %s not registered", dns.TypeToString[rrtype])
	}
	return rr
}

func countType(rrs []dns.RR, rrtype uint16) int {
	count := 0
	for _, rr := range rrs {
		if rr.Header().Rrtype == rrtype {
			count++
		}
	}
	return count
}

func countRRSIGCovered(rrs []dns.RR, covered uint16) int {
	count := 0
	for _, rr := range rrs {
		rrsig, ok := rr.(*dns.RRSIG)
		if ok && rrsig.TypeCovered == covered {
			count++
		}
	}
	return count
}
