package security

import (
	"encoding/base64"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"

	"go53/storage"
)

func setupSecurityMockStorage(t *testing.T) {
	t.Helper()
	storage.Backend = &storage.MockStorage{Zones: map[string][]byte{}, Tables: map[string]map[string][]byte{}}
	if err := storage.Backend.Init(); err != nil {
		t.Fatalf("storage init: %v", err)
	}
	if err := InitDNSSECKeyCache(); err != nil {
		t.Fatalf("InitDNSSECKeyCache: %v", err)
	}
}

func TestDSCDSAndCDNSKEYFlow(t *testing.T) {
	setupSecurityMockStorage(t)
	now := time.Now().Unix()
	if _, _, err := GenerateRolloverKey("delegated.test.", "ksk", "ED25519", now-10, now-5); err != nil {
		t.Fatalf("GenerateRolloverKey KSK: %v", err)
	}
	if _, _, err := GenerateRolloverKey("delegated.test.", "zsk", "ED25519", now-10, now-5); err != nil {
		t.Fatalf("GenerateRolloverKey ZSK: %v", err)
	}

	parentKeys, err := ParentDSDNSKEYs("delegated.test.", now)
	if err != nil {
		t.Fatalf("ParentDSDNSKEYs: %v", err)
	}
	if len(parentKeys) != 1 || parentKeys[0].Flags != 257 {
		t.Fatalf("parent DNSKEYs = %#v, want active KSK only", parentKeys)
	}

	ds, err := GetDSWithDigestTypes("delegated.test.", []uint8{dns.SHA1, dns.SHA256})
	if err != nil {
		t.Fatalf("GetDSWithDigestTypes: %v", err)
	}
	if len(ds) != 2 || ds[0].DigestType != dns.SHA1 || ds[1].DigestType != dns.SHA256 {
		t.Fatalf("DS records = %#v", ds)
	}
	defaultDS, err := GetDS("delegated.test.")
	if err != nil || len(defaultDS) != 1 || defaultDS[0].DigestType != dns.SHA256 {
		t.Fatalf("GetDS = %#v err=%v", defaultDS, err)
	}
	cds, err := GetCDS("delegated.test.")
	if err != nil || len(cds) != 1 || cds[0].Hdr.Rrtype != dns.TypeCDS {
		t.Fatalf("GetCDS = %#v err=%v", cds, err)
	}
	cdnskey, err := GetCDNSKEY("delegated.test.")
	if err != nil || len(cdnskey) != 1 || cdnskey[0].Hdr.Rrtype != dns.TypeCDNSKEY {
		t.Fatalf("GetCDNSKEY = %#v err=%v", cdnskey, err)
	}

	deleteCDS := DeleteDSCDS("delegated.test.", 0)
	if deleteCDS.Hdr.Ttl != 3600 || deleteCDS.KeyTag != 0 || deleteCDS.Digest != "00" {
		t.Fatalf("DeleteDSCDS = %#v", deleteCDS)
	}
	deleteCDNSKEY := DeleteDSCDNSKEY("delegated.test.", 123)
	if deleteCDNSKEY.Hdr.Ttl != 123 || deleteCDNSKEY.Flags != 0 || deleteCDNSKEY.PublicKey != "AA==" {
		t.Fatalf("DeleteDSCDNSKEY = %#v", deleteCDNSKEY)
	}
}

func TestParentDSDNSKEYsRequiresActiveKSK(t *testing.T) {
	setupSecurityMockStorage(t)
	now := time.Now().Unix()
	if _, _, err := GenerateRolloverKey("zskonly.test.", "zsk", "ED25519", now-10, now-5); err != nil {
		t.Fatalf("GenerateRolloverKey ZSK: %v", err)
	}
	if _, err := ParentDSDNSKEYs("zskonly.test.", now); err == nil {
		t.Fatalf("ParentDSDNSKEYs succeeded without active KSK")
	}
	if _, _, err := GenerateRolloverKey("future.test.", "ksk", "ED25519", now+100, now+200); err != nil {
		t.Fatalf("GenerateRolloverKey future KSK: %v", err)
	}
	if _, err := ParentDSDNSKEYs("future.test.", now); err == nil {
		t.Fatalf("ParentDSDNSKEYs succeeded for unpublished KSK")
	}
}

func TestSavePrivateKeyToStorageAndActiveSigningNames(t *testing.T) {
	setupSecurityMockStorage(t)
	priv, pub, err := generateKeyPair(15)
	if err != nil {
		t.Fatalf("generateKeyPair: %v", err)
	}
	if err := SavePrivateKeyToStorage("save.test.", "zsk-save", "ED25519", priv, pub, 256); err != nil {
		t.Fatalf("SavePrivateKeyToStorage: %v", err)
	}
	loadedPriv, stored, err := LoadPrivateKeyFromStorage("zsk-save")
	if err != nil {
		t.Fatalf("LoadPrivateKeyFromStorage: %v", err)
	}
	if loadedPriv == nil || stored.Flags != 256 || stored.Zone != "save.test" || stored.KeyTag == 0 {
		t.Fatalf("loaded key = %#v priv=%T", stored, loadedPriv)
	}
	names, err := GetDNSSECKeyNames("save.test.")
	if err != nil || len(names) != 1 || names[0] != "zsk-save" {
		t.Fatalf("GetDNSSECKeyNames = %#v err=%v", names, err)
	}
	if names, err := GetDNSSECKeyNamesForRRSet("save.test.", true); err != nil || len(names) != 0 {
		t.Fatalf("DNSKEY signing names = %#v err=%v, want no KSK", names, err)
	}
}

func TestImportPrivateKeysPDNSECDSAP256(t *testing.T) {
	setupSecurityMockStorage(t)
	data := []byte(`{
		"format":"go53-dnssec-private-keys",
		"version":1,
		"source":"powerdns",
		"zone":"solutrix.se.",
		"keys":[{
			"source_key_id":"5",
			"role":"CSK",
			"flags":257,
			"algorithm":"ECDSAP256SHA256",
			"algorithm_number":13,
			"keytag":30798,
			"private_key_format":"v1.2",
			"private_algorithm":"13 (ECDSAP256SHA256)",
			"private_key":"Y/VymWb6trMT7QWKTLz2hbIg8qz5KuBxc4WnCCp2eR4="
		}]
	}`)

	result, err := ImportPrivateKeys(data)
	if err != nil {
		t.Fatalf("ImportPrivateKeys: %v", err)
	}
	if len(result.Imported) != 1 {
		t.Fatalf("imported keys = %#v", result.Imported)
	}
	_, stored, err := LoadPrivateKeyFromStorage(result.Imported[0])
	if err != nil {
		t.Fatalf("LoadPrivateKeyFromStorage: %v", err)
	}
	if stored.Zone != "solutrix.se" || stored.Algorithm != "ECDSAP256SHA256" || stored.Flags != 257 || stored.KeyTag != 30798 {
		t.Fatalf("stored key = %#v", stored)
	}
	if stored.PublicKey != "UDKBux3OJRYDDGqeIlTo8Zi9HWkDiOIYOCVk0aL44p7UsHuSfhG3HMEO3vs3yG6YwvCIAf7UZqqADvb+SkHqig==" {
		t.Fatalf("public key = %q", stored.PublicKey)
	}
}

func TestPublicKeyToDNSErrorsAndAlgorithmNames(t *testing.T) {
	if _, err := PublicKeyToDNS(nil, 15); err == nil {
		t.Fatalf("PublicKeyToDNS accepted nil key")
	}
	if _, err := PublicKeyToDNS("not a key", 15); err == nil {
		t.Fatalf("PublicKeyToDNS accepted wrong ED25519 key type")
	}
	if _, err := PublicKeyToDNS("not a key", 8); err == nil {
		t.Fatalf("PublicKeyToDNS accepted wrong RSA key type")
	}
	if _, err := PublicKeyToDNS("not a key", 13); err == nil {
		t.Fatalf("PublicKeyToDNS accepted wrong ECDSA key type")
	}
	if _, err := PublicKeyToDNS("not a key", 14); err == nil {
		t.Fatalf("PublicKeyToDNS accepted wrong ECDSA P-384 key type")
	}
	if _, err := PublicKeyToDNS("not a key", 16); err == nil {
		t.Fatalf("PublicKeyToDNS accepted ED448")
	}
	if _, err := PublicKeyToDNS("not a key", 99); err == nil {
		t.Fatalf("PublicKeyToDNS accepted unsupported algorithm")
	}
	if AlgorithmNumberFromName("ED448") != 16 {
		t.Fatalf("AlgorithmNumberFromName ED448 mismatch")
	}
	defer func() {
		if recover() == nil {
			t.Fatalf("AlgorithmNumberFromName did not panic for unknown algorithm")
		}
	}()
	AlgorithmNumberFromName("NOPE")
}

func TestTSIGSetAndHMACVariants(t *testing.T) {
	TSIGSecrets = nil
	secret := base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	SetTSIGKey(" Mixed.Name ", TSIGKey{Algorithm: dns.HmacSHA256, Secret: secret})
	key, ok := GetTSIGKey("mixed.name.")
	if !ok || key.Secret != secret {
		t.Fatalf("GetTSIGKey = %#v ok=%v", key, ok)
	}
	listed := ListTSIGKeys()
	listed["mixed.name."] = TSIGKey{Secret: "mutated"}
	key, _ = GetTSIGKey("mixed.name.")
	if key.Secret == "mutated" {
		t.Fatalf("ListTSIGKeys returned mutable backing map")
	}

	for _, alg := range []string{dns.HmacSHA1, dns.HmacSHA224, dns.HmacSHA256, dns.HmacSHA384, dns.HmacSHA512} {
		if mac, err := generateTSIGHMAC([]byte("msg"), secret, alg); err != nil || len(mac) == 0 {
			t.Fatalf("generateTSIGHMAC alg=%s len=%d err=%v", alg, len(mac), err)
		}
	}
	if _, err := generateTSIGHMAC([]byte("msg"), "not-base64", dns.HmacSHA256); err == nil {
		t.Fatalf("generateTSIGHMAC accepted invalid base64")
	}
	if _, err := generateTSIGHMAC([]byte("msg"), secret, "hmac-nope."); err == nil {
		t.Fatalf("generateTSIGHMAC accepted invalid algorithm")
	}
}

func TestSortRRCanonicallyOrdersByPackedCanonicalWire(t *testing.T) {
	rrs := []dns.RR{
		&dns.TXT{Hdr: dns.RR_Header{Name: "b.sort.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{"b"}},
		&dns.A{Hdr: dns.RR_Header{Name: "a.sort.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{192, 0, 2, 1}},
		&dns.TXT{Hdr: dns.RR_Header{Name: "A.sort.test.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300}, Txt: []string{"a"}},
	}
	want := append([]dns.RR(nil), rrs...)
	SortRRCanonically(want)

	SortRRCanonically(rrs)
	if !reflect.DeepEqual(rrs, want) {
		t.Fatalf("SortRRCanonically = %#v, want %#v", rrs, want)
	}
	for i := 1; i < len(rrs); i++ {
		if rrCanonicalLess(rrs[i], rrs[i-1]) {
			t.Fatalf("RRs are not canonically sorted at %d: %s before %s", i, rrs[i], rrs[i-1])
		}
	}
}
