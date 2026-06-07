package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/miekg/dns"
	"go53/config"
	"go53/types"
)

func TestSignRRSetUsesSignaturePolicy(t *testing.T) {
	config.AppConfig.Live.DNSSEC = config.DNSSECSignaturePolicy{
		ValiditySeconds:       7200,
		DNSKEYValiditySeconds: 14400,
		RefreshBeforeSeconds:  1800,
		JitterSeconds:         10,
		InceptionSkewSeconds:  300,
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rr := &dns.A{
		Hdr: dns.RR_Header{Name: "www.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   []byte{192, 0, 2, 1},
	}
	before := time.Now()
	sig, err := SignRRSet([]dns.RR{rr}, priv, 12345, "example.test.", dns.ED25519)
	if err != nil {
		t.Fatal(err)
	}
	after := time.Now()

	expected := int64((7200*time.Second + 300*time.Second - signatureJitterSeconds(rr.Hdr.Name, rr.Hdr.Rrtype, 12345, 10*time.Second)) / time.Second)
	if got := int64(sig.Expiration) - int64(sig.Inception); got != expected {
		t.Fatalf("signature window = %d seconds, want %d", got, expected)
	}
	if time.Unix(int64(sig.Inception), 0).After(before.Add(-300*time.Second)) || time.Unix(int64(sig.Inception), 0).Before(after.Add(-310*time.Second)) {
		t.Fatalf("inception %d not within configured skew window", sig.Inception)
	}
}

func TestSignRRSetWildcardLabelsExcludeWildcardOwner(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rr := &dns.A{
		Hdr: dns.RR_Header{Name: "*.wild.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   []byte{192, 0, 2, 1},
	}
	sig, err := SignRRSet([]dns.RR{rr}, priv, 12345, "example.test.", dns.ED25519)
	if err != nil {
		t.Fatal(err)
	}

	if sig.Labels != 3 {
		t.Fatalf("wildcard RRSIG labels = %d, want 3", sig.Labels)
	}
}

func TestRRSIGLabelCountNonWildcard(t *testing.T) {
	if got := rrsigLabelCount("www.example.test."); got != 3 {
		t.Fatalf("rrsigLabelCount = %d, want 3", got)
	}
}

func TestRRSIGFreshRefreshBeforeExpiration(t *testing.T) {
	config.AppConfig.Live.DNSSEC = config.DNSSECSignaturePolicy{
		ValiditySeconds:       7200,
		DNSKEYValiditySeconds: 14400,
		RefreshBeforeSeconds:  1800,
		JitterSeconds:         1,
		InceptionSkewSeconds:  300,
	}
	now := time.Unix(10000, 0)
	fresh := &types.RRSIGRecord{
		TypeCovered: "A",
		KeyTag:      1,
		Inception:   uint32(now.Add(-time.Hour).Unix()),
		Expiration:  uint32(now.Add(2 * time.Hour).Unix()),
	}
	if !RRSIGFresh("www.example.test.", fresh, dns.TypeA, now) {
		t.Fatalf("signature outside refresh window should be fresh")
	}

	stale := *fresh
	stale.Expiration = uint32(now.Add(20 * time.Minute).Unix())
	if RRSIGFresh("www.example.test.", &stale, dns.TypeA, now) {
		t.Fatalf("signature inside refresh window should be stale")
	}
}
