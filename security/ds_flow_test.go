package security

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"go53/storage"
)

func TestDSCDSCDNSKEYFlowUsesOnlyActiveKSKs(t *testing.T) {
	storage.Backend = &storage.MockStorage{
		Zones:  map[string][]byte{},
		Tables: map[string]map[string][]byte{},
	}

	now := time.Now().Unix()
	activeID, active, err := GenerateRolloverKey("flow.test", "ksk", "ED25519", now-20, now-10)
	if err != nil {
		t.Fatalf("GenerateRolloverKey active KSK: %v", err)
	}
	if activeID == "" || active.KeyTag == 0 {
		t.Fatalf("active KSK was not stored with key id/tag")
	}
	if _, _, err := GenerateRolloverKey("flow.test", "ksk", "ED25519", now-10, now+3600); err != nil {
		t.Fatalf("GenerateRolloverKey prepublished KSK: %v", err)
	}
	if _, _, err := GenerateRolloverKey("flow.test", "zsk", "ED25519", now-20, now-10); err != nil {
		t.Fatalf("GenerateRolloverKey active ZSK: %v", err)
	}

	dsList, err := GetDSWithDigestTypes("flow.test", []uint8{dns.SHA256})
	if err != nil {
		t.Fatalf("GetDSWithDigestTypes: %v", err)
	}
	if len(dsList) != 1 {
		t.Fatalf("DS count = %d, want 1 active KSK DS", len(dsList))
	}
	if dsList[0].KeyTag != active.KeyTag || dsList[0].DigestType != dns.SHA256 {
		t.Fatalf("DS = keytag %d digest %d, want keytag %d digest %d", dsList[0].KeyTag, dsList[0].DigestType, active.KeyTag, dns.SHA256)
	}

	cdsList, err := GetCDS("flow.test")
	if err != nil {
		t.Fatalf("GetCDS: %v", err)
	}
	if len(cdsList) != 1 || cdsList[0].KeyTag != active.KeyTag {
		t.Fatalf("CDS count/keytag = %d/%d, want 1/%d", len(cdsList), cdsList[0].KeyTag, active.KeyTag)
	}

	cdnskeyList, err := GetCDNSKEY("flow.test")
	if err != nil {
		t.Fatalf("GetCDNSKEY: %v", err)
	}
	if len(cdnskeyList) != 1 || cdnskeyList[0].Flags != 257 || cdnskeyList[0].KeyTag() != active.KeyTag {
		t.Fatalf("CDNSKEY = count %d flags %d keytag %d, want 1/257/%d", len(cdnskeyList), cdnskeyList[0].Flags, cdnskeyList[0].KeyTag(), active.KeyTag)
	}
}

func TestDeleteDSSignalingRecords(t *testing.T) {
	cds := DeleteDSCDS("flow.test", 7200)
	if cds.Hdr.Rrtype != dns.TypeCDS || cds.KeyTag != 0 || cds.Algorithm != 0 || cds.DigestType != 0 || cds.Digest != "00" || cds.Hdr.Ttl != 7200 {
		t.Fatalf("unexpected delete CDS: %#v", cds)
	}
	cdnskey := DeleteDSCDNSKEY("flow.test", 7200)
	if cdnskey.Hdr.Rrtype != dns.TypeCDNSKEY || cdnskey.Flags != 0 || cdnskey.Protocol != 3 || cdnskey.Algorithm != 0 || cdnskey.PublicKey == "" || cdnskey.Hdr.Ttl != 7200 {
		t.Fatalf("unexpected delete CDNSKEY: %#v", cdnskey)
	}
}
