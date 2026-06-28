package dnsutils

import (
	"testing"

	"github.com/miekg/dns"

	"go53/config"
	"go53/memory"
	"go53/storage"
	"go53/types"
	"go53/zone"
	"go53/zone/rtypes"
)

func TestImportFromZoneDataAddsCommonRecords(t *testing.T) {
	setupDNSUtilsImportStore(t)
	zd := types.ZoneData{
		A: map[string][]types.ARecord{
			"www": {{IP: "192.0.2.10", TTL: 300}},
		},
		CNAME: map[string]types.CNAMERecord{
			"alias": {Target: "www.import.test.", TTL: 300},
		},
		RRSIG: map[string][]*types.RRSIGRecord{
			"A": {{Name: "www", TypeCovered: "A", Algorithm: 15, Labels: 3, OrigTTL: 300, Expiration: 2000, Inception: 1000, KeyTag: 12345, SignerName: "import.test.", Signature: "abc", TTL: 300}},
		},
		SOA: &types.SOARecord{Ns: "ns1.import.test.", Mbox: "hostmaster.import.test.", Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300, TTL: 300},
	}
	if err := importFromZoneData("import.test.", zd, false); err != nil {
		t.Fatalf("importFromZoneData: %v", err)
	}
	if rrs, ok := zone.LookupRecord(dns.TypeA, "www.import.test."); !ok || len(rrs) != 1 {
		t.Fatalf("A lookup = %#v ok=%v", rrs, ok)
	}
	if rrs, ok := zone.LookupRecord(dns.TypeCNAME, "alias.import.test."); !ok || len(rrs) != 1 {
		t.Fatalf("CNAME lookup = %#v ok=%v", rrs, ok)
	}
	if rrs, ok := zone.LookupRecord(dns.TypeRRSIG, "www.import.test.___A"); !ok || len(rrs) != 1 {
		t.Fatalf("RRSIG lookup = %#v ok=%v", rrs, ok)
	}
}

func TestImportRecordsRejectsUnsupportedInput(t *testing.T) {
	setupDNSUtilsImportStore(t)
	if err := ImportRecords("A", "bad.test.", 123); err == nil {
		t.Fatalf("ImportRecords accepted unsupported input")
	}
	if err := ImportRecords("A", "bad.test.", map[string]interface{}{}); err == nil {
		t.Fatalf("ImportRecords accepted JSON map without multi rrtype")
	}
}

func setupDNSUtilsImportStore(t *testing.T) {
	t.Helper()
	backend := &storage.MockStorage{}
	if err := backend.Init(); err != nil {
		t.Fatalf("storage init: %v", err)
	}
	storage.Backend = backend
	config.AppConfig = &config.ConfigManager{}
	config.AppConfig.SetLive(config.DefaultLiveConfig)
	config.AppConfig.LiveForTest().Mode = "secondary"
	config.AppConfig.LiveForTest().DNSSECEnabled = false
	mem, err := memory.NewZoneStore(backend)
	if err != nil {
		t.Fatalf("NewZoneStore: %v", err)
	}
	rtypes.InitMemoryStore(mem)
}
