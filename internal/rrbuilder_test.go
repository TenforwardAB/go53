package internal

import (
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"go53/types"
)

func TestUtilHelpers(t *testing.T) {
	zone, host, ok := SplitName("www.example.test.")
	if !ok || zone != "example.test" || host != "www" {
		t.Fatalf("SplitName = zone=%q host=%q ok=%v", zone, host, ok)
	}
	if _, _, ok := SplitName("localhost"); ok {
		t.Fatalf("SplitName accepted single-label name")
	}

	if rrtype, err := RRTypeStringToUint16("a"); err != nil || rrtype != dns.TypeA {
		t.Fatalf("RRTypeStringToUint16(A) = %d err=%v", rrtype, err)
	}
	if _, err := RRTypeStringToUint16("nope"); err == nil {
		t.Fatalf("RRTypeStringToUint16 accepted unknown type")
	}

	if got, err := SanitizeFQDN(" Example.Test "); err != nil || got != "Example.Test." {
		t.Fatalf("SanitizeFQDN = %q err=%v", got, err)
	}
	if got, err := SanitizeFQDN("@"); err != nil || got != "@" {
		t.Fatalf("SanitizeFQDN @ = %q err=%v", got, err)
	}
	if got, err := SanitizeFQDN("_catalog.go53."); err != nil || got != "_catalog.go53." {
		t.Fatalf("SanitizeFQDN _catalog = %q err=%v", got, err)
	}
	if _, err := SanitizeFQDN("bad$name"); err == nil {
		t.Fatalf("SanitizeFQDN accepted invalid name")
	}

	old := uint32(0)
	next := NextSerial(old)
	if next == 0 || NextSerial(next) <= next {
		t.Fatalf("NextSerial did not increase from %d", next)
	}
}

func TestMergeStructsAndDNSKEYParsing(t *testing.T) {
	type nestedConfig struct {
		Delay int
	}
	type mergeConfig struct {
		LogLevel string
		Mode     string
		Enabled  bool
		Nested   nestedConfig
		Peers    map[string]string
	}

	dst := mergeConfig{
		LogLevel: "info",
		Mode:     "primary",
		Nested:   nestedConfig{Delay: 10},
	}
	src := mergeConfig{
		LogLevel: "debug",
		Enabled:  true,
		Nested:   nestedConfig{Delay: 20},
		Peers:    map[string]string{"node-a": "pub"},
	}
	MergeStructs(&dst, &src)
	if dst.LogLevel != "debug" || !dst.Enabled || dst.Nested.Delay != 20 {
		t.Fatalf("merged config = %#v", dst)
	}
	if !reflect.DeepEqual(dst.Peers, map[string]string{"node-a": "pub"}) {
		t.Fatalf("merged map = %#v", dst.Peers)
	}

	rec, ok := ParseToDNSKEYRecord(map[string]interface{}{
		"flags":      float64(257),
		"algorithm":  float64(15),
		"public_key": "abc",
		"ttl":        float64(600),
	})
	if !ok || rec.Flags != 257 || rec.Algorithm != 15 || rec.Protocol != 3 || rec.TTL != 600 {
		t.Fatalf("ParseToDNSKEYRecord = %#v ok=%v", rec, ok)
	}
	if _, ok := ParseToDNSKEYRecord(map[string]interface{}{"flags": float64(257)}); ok {
		t.Fatalf("ParseToDNSKEYRecord accepted missing public key")
	}
}

func TestRRBuildersCommonAndDNSSECRecords(t *testing.T) {
	name := "www.example.test."
	validHash := strings.TrimRight(dns.HashName("example.test.", dns.SHA1, 0, ""), "=")
	tests := []struct {
		rrtype string
		data   any
		want   uint16
	}{
		{"A", []interface{}{map[string]interface{}{"ip": "192.0.2.1", "ttl": float64(120)}}, dns.TypeA},
		{"AAAA", []interface{}{map[string]interface{}{"ip": "2001:db8::1", "ttl": float64(120)}}, dns.TypeAAAA},
		{"NS", []interface{}{map[string]interface{}{"ns": "ns1.example.test.", "ttl": float64(120)}}, dns.TypeNS},
		{"DS", []interface{}{map[string]interface{}{"key_tag": float64(12345), "algorithm": float64(15), "digest_type": float64(2), "digest": "abcd", "ttl": float64(120)}}, dns.TypeDS},
		{"CDS", []interface{}{map[string]interface{}{"key_tag": float64(12345), "algorithm": float64(15), "digest_type": float64(2), "digest": "abcd", "ttl": float64(120)}}, dns.TypeCDS},
		{"MX", []interface{}{map[string]interface{}{"priority": float64(10), "host": "mail.example.test.", "ttl": float64(120)}}, dns.TypeMX},
		{"TXT", []interface{}{map[string]interface{}{"text": "hello", "ttl": float64(120)}}, dns.TypeTXT},
		{"SRV", []interface{}{map[string]interface{}{"priority": float64(10), "weight": float64(5), "port": float64(443), "target": "svc.example.test.", "ttl": float64(120)}}, dns.TypeSRV},
		{"PTR", []interface{}{map[string]interface{}{"ptr": "ptr.example.test.", "ttl": float64(120)}}, dns.TypePTR},
		{"CNAME", map[string]interface{}{"target": "target.example.test.", "ttl": float64(120)}, dns.TypeCNAME},
		{"DNAME", map[string]interface{}{"target": "target.example.test.", "ttl": float64(120)}, dns.TypeDNAME},
		{"SPF", map[string]interface{}{"text": "v=spf1 -all", "ttl": float64(120)}, dns.TypeSPF},
		{"SOA", map[string]interface{}{"ns": "ns1.example.test.", "mbox": "hostmaster.example.test.", "serial": float64(1), "refresh": float64(3600), "retry": float64(600), "expire": float64(86400), "minimum": float64(300), "ttl": float64(120)}, dns.TypeSOA},
		{"NSEC", map[string]interface{}{"next_domain": "next.example.test.", "types": []string{"A", "RRSIG"}, "ttl": float64(120)}, dns.TypeNSEC},
		{"NSEC3", map[string]interface{}{"hash_alg": float64(1), "flags": float64(1), "iterations": float64(0), "salt": "-", "next_hashed": validHash, "types": []string{"A"}, "ttl": float64(120)}, dns.TypeNSEC3},
		{"NSEC3PARAM", map[string]interface{}{"hash_algorithm": float64(1), "flags": float64(0), "iterations": float64(0), "salt": "-", "ttl": float64(120)}, dns.TypeNSEC3PARAM},
		{"DNSKEY", map[string]interface{}{"flags": float64(257), "protocol": float64(3), "algorithm": float64(15), "public_key": "abc", "ttl": float64(120)}, dns.TypeDNSKEY},
		{"CDNSKEY", map[string]interface{}{"flags": float64(257), "protocol": float64(3), "algorithm": float64(15), "public_key": "abc", "ttl": float64(120)}, dns.TypeCDNSKEY},
		{"RRSIG", []interface{}{map[string]interface{}{"name": "www", "type_covered": "A", "algorithm": float64(15), "labels": float64(3), "orig_ttl": float64(120), "expiration": float64(2000), "inception": float64(1000), "key_tag": float64(12345), "signer_name": "example.test.", "signature": "abc", "ttl": float64(120)}}, dns.TypeRRSIG},
	}

	for _, tt := range tests {
		t.Run(tt.rrtype, func(t *testing.T) {
			rrs := RRBuilders[tt.rrtype](name, tt.data)
			if len(rrs) != 1 {
				t.Fatalf("%s builder returned %d RRs: %#v", tt.rrtype, len(rrs), rrs)
			}
			if rrs[0].Header().Rrtype != tt.want {
				t.Fatalf("%s builder rrtype = %d, want %d", tt.rrtype, rrs[0].Header().Rrtype, tt.want)
			}
		})
	}

	if got := RRBuilders["NSEC3"](name, map[string]interface{}{"next_hashed": "not valid"}); got != nil {
		t.Fatalf("invalid NSEC3 hash produced RRs: %#v", got)
	}
}

func TestRRToZoneData(t *testing.T) {
	rrs := []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.1")},
		&dns.AAAA{Hdr: dns.RR_Header{Name: "v6.example.test.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300}, AAAA: net.ParseIP("2001:db8::1")},
		&dns.MX{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300}, Preference: 10, Mx: "mail.example.test."},
		&dns.NS{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns1.example.test."},
		&dns.TXT{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{"hello", "world"}},
		&dns.SRV{Hdr: dns.RR_Header{Name: "_sip._tcp.example.test.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 300}, Priority: 10, Weight: 5, Port: 5060, Target: "sip.example.test."},
		&dns.PTR{Hdr: dns.RR_Header{Name: "1.2.0.192.in-addr.arpa.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 300}, Ptr: "example.test."},
		&dns.CNAME{Hdr: dns.RR_Header{Name: "alias.example.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "target.example.test."},
		&dns.DNAME{Hdr: dns.RR_Header{Name: "old.example.test.", Rrtype: dns.TypeDNAME, Class: dns.ClassINET, Ttl: 300}, Target: "new.example.test."},
		&dns.SPF{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeSPF, Class: dns.ClassINET, Ttl: 300}, Txt: []string{"v=spf1", "-all"}},
		&dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300}, Flags: 257, Protocol: 3, Algorithm: 15, PublicKey: "abc"},
		&dns.CDNSKEY{DNSKEY: dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeCDNSKEY, Class: dns.ClassINET, Ttl: 300}, Flags: 257, Protocol: 3, Algorithm: 15, PublicKey: "abc"}},
		&dns.DS{Hdr: dns.RR_Header{Name: "child.example.test.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 300}, KeyTag: 12345, Algorithm: 15, DigestType: 2, Digest: "abcd"},
		&dns.CDS{DS: dns.DS{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeCDS, Class: dns.ClassINET, Ttl: 300}, KeyTag: 12345, Algorithm: 15, DigestType: 2, Digest: "abcd"}},
		&dns.RRSIG{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300}, TypeCovered: dns.TypeA, Algorithm: 15, Labels: 2, OrigTtl: 300, Expiration: 2000, Inception: 1000, KeyTag: 12345, SignerName: "example.test.", Signature: "abc"},
		&dns.SOA{Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}, Ns: "ns1.example.test.", Mbox: "hostmaster.example.test.", Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 300},
	}
	zd := RRToZoneData(rrs)
	if got := zd.A["@"][0].IP; got != "192.0.2.1" {
		t.Fatalf("A = %q", got)
	}
	if got := zd.AAAA["v6"][0].IP; got != "2001:db8::1" {
		t.Fatalf("AAAA = %q", got)
	}
	if got := zd.TXT["@"][0].Text; got != "hello world" {
		t.Fatalf("TXT = %q", got)
	}
	if got := zd.SOA.Serial; got != 1 {
		t.Fatalf("SOA serial = %d", got)
	}
	if len(zd.RRSIG["A"]) != 1 {
		t.Fatalf("RRSIG records = %#v", zd.RRSIG)
	}
	if _, ok := any(zd.CNAME["alias"]).(types.CNAMERecord); !ok {
		t.Fatalf("CNAME not populated: %#v", zd.CNAME)
	}
}
