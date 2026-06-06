package rtypes

import (
	"testing"

	"github.com/miekg/dns"

	"go53/config"
	"go53/memory"
	"go53/storage"
)

func TestDNSSECRTypesLifecycle(t *testing.T) {
	ttl := uint32(120)
	hash := dns.HashName("example.test.", dns.SHA1, 0, "")

	tests := []struct {
		name       string
		record     RRType
		zone       string
		owner      string
		lookupHost string
		value      map[string]interface{}
		wantType   uint16
	}{
		{
			name:       "DNSKEY",
			record:     DNSKEYRecord{},
			zone:       "example.test.",
			owner:      "example.test.",
			lookupHost: "example.test.",
			value:      map[string]interface{}{"flags": float64(257), "protocol": float64(3), "algorithm": float64(15), "public_key": "abc"},
			wantType:   dns.TypeDNSKEY,
		},
		{
			name:       "CDNSKEY",
			record:     CDNSKEYRecord{},
			zone:       "example.test.",
			owner:      "example.test.",
			lookupHost: "example.test.",
			value:      map[string]interface{}{"flags": float64(257), "protocol": float64(3), "algorithm": float64(15), "public_key": "abc"},
			wantType:   dns.TypeCDNSKEY,
		},
		{
			name:       "DS",
			record:     DSRecord{},
			zone:       "example.test.",
			owner:      "child",
			lookupHost: "child.example.test.",
			value:      map[string]interface{}{"key_tag": float64(12345), "algorithm": float64(15), "digest_type": float64(2), "digest": "abcd"},
			wantType:   dns.TypeDS,
		},
		{
			name:       "CDS",
			record:     CDSRecord{},
			zone:       "example.test.",
			owner:      "@",
			lookupHost: "example.test.",
			value:      map[string]interface{}{"key_tag": float64(12345), "algorithm": float64(15), "digest_type": float64(2), "digest": "abcd"},
			wantType:   dns.TypeCDS,
		},
		{
			name:       "DNAME",
			record:     DNAMERecord{},
			zone:       "example.test.",
			owner:      "old",
			lookupHost: "old.example.test.",
			value:      map[string]interface{}{"target": "new.example.test."},
			wantType:   dns.TypeDNAME,
		},
		{
			name:       "SPF",
			record:     SPFRecord{},
			zone:       "example.test.",
			owner:      "@",
			lookupHost: "example.test.",
			value:      map[string]interface{}{"text": "v=spf1 -all"},
			wantType:   dns.TypeSPF,
		},
		{
			name:       "NSEC",
			record:     NSEC{},
			zone:       "example.test.",
			owner:      "@",
			lookupHost: "example.test.",
			value:      map[string]interface{}{"next_domain": "www.example.test.", "types": []interface{}{"SOA", "NS", "DNSKEY"}},
			wantType:   dns.TypeNSEC,
		},
		{
			name:       "NSEC3",
			record:     NSEC3{},
			zone:       "example.test.",
			owner:      hash,
			lookupHost: hash + ".example.test.",
			value:      map[string]interface{}{"hash_algorithm": float64(1), "flags": float64(1), "iterations": float64(0), "salt": "-", "next_hashed": hash, "types": []interface{}{"A", "RRSIG"}},
			wantType:   dns.TypeNSEC3,
		},
		{
			name:       "NSEC3PARAM",
			record:     NSEC3PARAM{},
			zone:       "example.test.",
			owner:      "@",
			lookupHost: "example.test.",
			value:      map[string]interface{}{"hash_algorithm": float64(1), "flags": float64(0), "iterations": float64(0), "salt": "-"},
			wantType:   dns.TypeNSEC3PARAM,
		},
		{
			name:       "RRSIG",
			record:     RRSIGRecord{},
			zone:       "example.test.",
			owner:      "@",
			lookupHost: "example.test.___A",
			value:      map[string]interface{}{"type_covered": "A", "algorithm": float64(15), "labels": float64(2), "original_ttl": float64(300), "expiration": float64(2000), "inception": float64(1000), "key_tag": float64(12345), "signer_name": "example.test.", "signature": "abc"},
			wantType:   dns.TypeRRSIG,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupRTypesLifecycleStore(t)
			if err := tt.record.Add(tt.zone, tt.owner, tt.value, &ttl); err != nil {
				t.Fatalf("Add: %v", err)
			}
			rrs, ok := tt.record.Lookup(tt.lookupHost)
			if !ok || len(rrs) == 0 {
				if _, _, raw, found := memStore.GetRecord(tt.zone, dns.TypeToString[tt.wantType], tt.owner); found {
					t.Fatalf("Lookup returned ok=%v rrs=%#v raw=%#v", ok, rrs, raw)
				}
				t.Fatalf("Lookup returned ok=%v rrs=%#v", ok, rrs)
			}
			if rrs[0].Header().Rrtype != tt.wantType {
				t.Fatalf("Lookup rrtype = %d, want %d", rrs[0].Header().Rrtype, tt.wantType)
			}
			if tt.wantType != dns.TypeRRSIG {
				if err := tt.record.Delete(tt.lookupHost, nil); err != nil {
					t.Fatalf("Delete: %v", err)
				}
			}
		})
	}
}

func TestDNSSECRTypesRejectInvalidInput(t *testing.T) {
	setupRTypesLifecycleStore(t)
	if err := (DSRecord{}).Add("example.test.", "child", map[string]interface{}{"algorithm": float64(15)}, nil); err == nil {
		t.Fatalf("DS Add accepted missing key_tag")
	}
	if err := (NSEC3{}).Add("example.test.", "bad-hash", map[string]interface{}{"hash_algorithm": float64(1), "flags": float64(2), "iterations": float64(0), "salt": "-", "next_hashed": "bad", "types": []interface{}{"A"}}, nil); err == nil {
		t.Fatalf("NSEC3 Add accepted unsupported flags/hash")
	}
	if _, ok := (RRSIGRecord{}).Lookup("example.test."); ok {
		t.Fatalf("RRSIG Lookup accepted host without covered type separator")
	}
}

func setupRTypesLifecycleStore(t *testing.T) {
	t.Helper()
	backend := &storage.MockStorage{}
	if err := backend.Init(); err != nil {
		t.Fatalf("init storage: %v", err)
	}
	storage.Backend = backend
	config.AppConfig = &config.ConfigManager{}
	config.AppConfig.Live = config.DefaultLiveConfig
	config.AppConfig.Live.DNSSECEnabled = false

	mem, err := memory.NewZoneStore(backend)
	if err != nil {
		t.Fatalf("new memory store: %v", err)
	}
	InitMemoryStore(mem)
	store = mem
}
