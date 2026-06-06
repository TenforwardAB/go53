package security

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/miekg/dns"

	"go53/config"
	"go53/storage"
	"go53/types"
)

func TestTSIGProviderGenerateVerifyAndList(t *testing.T) {
	storage.Backend = &storage.MockStorage{Zones: map[string][]byte{}, Tables: map[string]map[string][]byte{}}
	if err := storage.Backend.Init(); err != nil {
		t.Fatalf("storage init: %v", err)
	}
	secret := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	if err := storage.Backend.SaveTable("tsig-keys", "xfr-key", []byte(`{"algorithm":"hmac-sha256.","secret":"`+secret+`"}`)); err != nil {
		t.Fatalf("SaveTable: %v", err)
	}
	if err := LoadTSIGKeysFromStorage(); err != nil {
		t.Fatalf("LoadTSIGKeysFromStorage: %v", err)
	}
	if key, ok := GetTSIGKey("xfr-key."); !ok || key.Secret != secret {
		t.Fatalf("GetTSIGKey = %#v ok=%v", key, ok)
	}
	if listed := ListTSIGKeys(); len(listed) != 1 {
		t.Fatalf("ListTSIGKeys = %#v", listed)
	}

	provider := DynamicTSIGProvider{}
	msg := []byte("message")
	mac, err := provider.Generate(msg, &dns.TSIG{Hdr: dns.RR_Header{Name: "xfr-key."}, Algorithm: dns.HmacSHA256})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := provider.Verify(msg, &dns.TSIG{Hdr: dns.RR_Header{Name: "xfr-key."}, Algorithm: dns.HmacSHA256, MAC: hex.EncodeToString(mac)}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := provider.Verify([]byte("other"), &dns.TSIG{Hdr: dns.RR_Header{Name: "xfr-key."}, Algorithm: dns.HmacSHA256, MAC: hex.EncodeToString(mac)}); err == nil {
		t.Fatalf("Verify accepted wrong message")
	}
	DeleteTSIGKey("xfr-key.")
	if _, ok := GetTSIGKey("xfr-key."); ok {
		t.Fatalf("DeleteTSIGKey did not remove key")
	}
	if _, err := GenerateTSIGSecret(); err != nil {
		t.Fatalf("GenerateTSIGSecret: %v", err)
	}
}

func TestDNSSECUtilities(t *testing.T) {
	config.AppConfig = &config.ConfigManager{}
	config.AppConfig.Live = config.DefaultLiveConfig
	config.AppConfig.Live.DNSSEC = config.DNSSECSignaturePolicy{
		ValiditySeconds:       3600,
		DNSKEYValiditySeconds: 7200,
		RefreshBeforeSeconds:  600,
		JitterSeconds:         10,
		InceptionSkewSeconds:  30,
	}
	policy := PolicyForRRType(dns.TypeA)
	if policy.Validity != time.Hour || policy.RefreshBefore != 10*time.Minute {
		t.Fatalf("A policy = %#v", policy)
	}
	dnskeyPolicy := PolicyForRRType(dns.TypeDNSKEY)
	if dnskeyPolicy.Validity != 2*time.Hour {
		t.Fatalf("DNSKEY policy = %#v", dnskeyPolicy)
	}

	rrs, err := ToRRSet("www.example.test.", "A", []types.ARecord{{IP: "192.0.2.1", TTL: 300}})
	if err != nil || len(rrs) != 1 {
		t.Fatalf("ToRRSet = %#v err=%v", rrs, err)
	}
	if _, err := ToRRSet("www.example.test.", "NOPE", nil); err == nil {
		t.Fatalf("ToRRSet accepted unknown type")
	}

	now := time.Now()
	fresh := &types.RRSIGRecord{TypeCovered: "A", Inception: uint32(now.Add(-time.Minute).Unix()), Expiration: uint32(now.Add(time.Hour).Unix()), KeyTag: 1}
	if !RRSIGFresh("www.example.test.", fresh, dns.TypeA, now) {
		t.Fatalf("RRSIGFresh returned false for fresh signature")
	}
	expired := *fresh
	expired.Expiration = uint32(now.Add(-time.Minute).Unix())
	if RRSIGFresh("www.example.test.", &expired, dns.TypeA, now) {
		t.Fatalf("RRSIGFresh accepted expired signature")
	}

	rrsig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "www.example.test.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		TypeCovered: dns.TypeA,
		Algorithm:   15,
		Labels:      3,
		OrigTtl:     300,
		Expiration:  uint32(now.Add(time.Hour).Unix()),
		Inception:   uint32(now.Add(-time.Minute).Unix()),
		KeyTag:      12345,
		SignerName:  "example.test.",
		Signature:   "abc",
	}
	converted := RRSIGFromDNS(rrsig)
	if converted.TypeCovered != "A" || converted.KeyTag != 12345 || converted.TTL != 300 {
		t.Fatalf("RRSIGFromDNS = %#v", converted)
	}
	if RRSIGFromDNS(nil) != nil {
		t.Fatalf("RRSIGFromDNS(nil) did not return nil")
	}
}
