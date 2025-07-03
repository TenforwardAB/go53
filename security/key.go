package security

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/miekg/dns"
	"go53/internal"
	"go53/storage"
	"go53/types"
	"go53/zonereader"
	"log"
	"strings"
)

const dnssecKeyTable = "dnssec_keys"

var supportedAlgos = []struct {
	Algorithm uint8
	Name      string
	Flags     []uint16
}{
	{8, "RSASHA256", []uint16{256, 257}},
	{10, "RSASHA512", []uint16{256, 257}},
	{13, "ECDSAP256SHA256", []uint16{256, 257}},
	{14, "ECDSAP384SHA384", []uint16{256, 257}},
	{15, "ED25519", []uint16{256, 257}},
	{16, "ED448", []uint16{256, 257}},
}

func GenerateAndStoreAllKeys(zone string) error {
	for _, algo := range supportedAlgos {
		for _, flag := range algo.Flags {
			priv, pub, err := generateKeyPair(algo.Algorithm)
			if err != nil {
				return fmt.Errorf("generate %s key: %w", algo.Name, err)
			}

			log.Printf("Generating key for zone=%s, flag=%d, algorithm=%s", zone, flag, algo.Name)
			log.Printf("algo=%s → algonum=%d", algo.Name, AlgorithmNumberFromName(algo.Name))

			pubBytes, err := PublicKeyToDNS(pub, algo.Algorithm)
			if err != nil {
				return fmt.Errorf("convert pubkey: %w", err)
			}

			keyTag := ComputeKeyTag(flag, 3, algo.Algorithm, pubBytes)
			keyID := fmt.Sprintf("%s_%s_%s", flagName(flag), zone, algo.Name)

			pemPriv, err := EncodePrivateKeyPEM(priv)
			if err != nil {
				return fmt.Errorf("PEM encode failed: %w", err)
			}

			stored := types.StoredKey{
				KeyTag:     keyTag,
				Zone:       zone,
				Algorithm:  algo.Name,
				Flags:      flag,
				PrivatePEM: pemPriv,
				PublicKey:  base64.StdEncoding.EncodeToString(pubBytes),
			}

			serialized, err := json.Marshal(stored)
			if err != nil {
				return fmt.Errorf("marshal key: %w", err)
			}

			if err := storage.Backend.SaveTable(dnssecKeyTable, keyID, serialized); err != nil {
				return fmt.Errorf("store key: %w", err)
			}
		}
	}
	return nil
}

func GetDS(zone string) ([]*dns.DS, error) {
	sz, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return nil, fmt.Errorf("FQDN sanitize check failed: %w", err)
	}

	recs, found := zonereader.LookupRecord(dns.TypeDNSKEY, sz)
	if !found {
		return nil, fmt.Errorf("no DNSKEYs found for zone %s", sz)
	}

	var dsList []*dns.DS
	for _, rr := range recs {
		dnskey, ok := rr.(*dns.DNSKEY)
		if !ok || dnskey.Flags != 257 {
			continue // Only consider KSKs
		}

		keyTag := dnskey.KeyTag()

		wire := make([]byte, 1024)
		off, err := dns.PackRR(dnskey, wire, 0, nil, true)
		if err != nil {
			return nil, fmt.Errorf("failed to pack DNSKEY: %w", err)
		}
		wire = wire[:off]
		digestInput := wire[12:]

		// SHA-1 digest (type 1)
		sha1sum := sha1.Sum(digestInput)
		ds1 := &dns.DS{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(zone),
				Rrtype: dns.TypeDS,
				Class:  dns.ClassINET,
				Ttl:    dnskey.Hdr.Ttl,
			},
			KeyTag:     keyTag,
			Algorithm:  dnskey.Algorithm,
			DigestType: dns.SHA1,
			Digest:     hex.EncodeToString(sha1sum[:]),
		}
		dsList = append(dsList, ds1)

		// SHA-256 digest (type 2)
		sha256sum := sha256.Sum256(digestInput)
		ds2 := &dns.DS{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(zone),
				Rrtype: dns.TypeDS,
				Class:  dns.ClassINET,
				Ttl:    dnskey.Hdr.Ttl,
			},
			KeyTag:     keyTag,
			Algorithm:  dnskey.Algorithm,
			DigestType: dns.SHA256,
			Digest:     hex.EncodeToString(sha256sum[:]),
		}
		dsList = append(dsList, ds2)
	}

	if len(dsList) == 0 {
		return nil, fmt.Errorf("no KSK found in DNSKEYs for zone %s", zone)
	}

	return dsList, nil
}

func generateKeyPair(algorithm uint8) (crypto.PrivateKey, crypto.PublicKey, error) {
	switch algorithm {
	case 8, 10: // RSASHA256 / RSASHA512
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		return priv, priv.Public(), err
	case 13: // ECDSAP256
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		return priv, priv.Public(), err
	case 14: // ECDSAP384
		priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		return priv, priv.Public(), err
	case 15: // ED25519
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, pub, err
	case 16: // ED448 – not in Go stdlib
		return nil, nil, fmt.Errorf("ED448 not supported in Go stdlib yet")
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm %d", algorithm)
	}
}

func EncodePrivateKeyPEM(priv crypto.PrivateKey) (string, error) {
	var block *pem.Block
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		b := x509.MarshalPKCS1PrivateKey(k)
		block = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: b}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return "", err
		}
		block = &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	case ed25519.PrivateKey:
		b, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return "", err
		}
		block = &pem.Block{Type: "PRIVATE KEY", Bytes: b}
	default:
		return "", fmt.Errorf("unsupported key type")
	}
	return string(pem.EncodeToMemory(block)), nil
}

func PublicKeyToDNS(pub crypto.PublicKey, algorithm uint8) ([]byte, error) {
	log.Printf("→ PublicKeyToDNS: algorithm=%d, pubkey type=%T", algorithm, pub)
	if pub == nil {
		return nil, fmt.Errorf("public key is nil")
	}

	switch algorithm {
	case 8, 10:
		if k, ok := pub.(*rsa.PublicKey); ok {
			return x509.MarshalPKIXPublicKey(k)
		}
		return nil, fmt.Errorf("expected RSA public key")

	case 13:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok || k.X == nil || k.Y == nil {
			return nil, fmt.Errorf("invalid ECDSA public key")
		}
		xBytes := k.X.Bytes()
		yBytes := k.Y.Bytes()
		xPad := append(make([]byte, 32-len(xBytes)), xBytes...)
		yPad := append(make([]byte, 32-len(yBytes)), yBytes...)
		return append([]byte{0x04}, append(xPad, yPad...)...), nil

	case 14: // ECDSAP384SHA384
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok || k.X == nil || k.Y == nil {
			return nil, fmt.Errorf("invalid ECDSA P-384 public key")
		}
		xBytes := k.X.Bytes()
		yBytes := k.Y.Bytes()
		xPad := append(make([]byte, 48-len(xBytes)), xBytes...)
		yPad := append(make([]byte, 48-len(yBytes)), yBytes...)
		return append([]byte{0x04}, append(xPad, yPad...)...), nil

	case 15:
		if k, ok := pub.(ed25519.PublicKey); ok {
			return k, nil
		}
		return nil, fmt.Errorf("expected ed25519 public key")

	case 16:
		return nil, fmt.Errorf("ED448 not supported")

	default:
		return nil, fmt.Errorf("unsupported algorithm %d", algorithm)
	}
}

func flagName(f uint16) string {
	if f == 257 {
		return "ksk"
	}
	return "zsk"
}

func SavePrivateKeyToStorage(zone, keyID, algorithmName string, priv crypto.PrivateKey, pub crypto.PublicKey, flags uint16) error {
	pemPriv, err := EncodePrivateKeyPEM(priv)
	if err != nil {
		return fmt.Errorf("encode private key: %w", err)
	}

	pubBytes, err := PublicKeyToDNS(pub, AlgorithmNumberFromName(algorithmName))
	if err != nil {
		return fmt.Errorf("convert public key: %w", err)
	}

	keyTag := ComputeKeyTag(flags, 3, AlgorithmNumberFromName(algorithmName), pubBytes)

	stored := types.StoredKey{
		KeyTag:     keyTag,
		Zone:       zone,
		Algorithm:  algorithmName,
		Flags:      flags,
		PrivatePEM: pemPriv,
		PublicKey:  base64.StdEncoding.EncodeToString(pubBytes),
	}

	data, err := json.Marshal(stored)
	if err != nil {
		return fmt.Errorf("marshal StoredKey: %w", err)
	}

	if err := storage.Backend.SaveTable(dnssecKeyTable, keyID, data); err != nil {
		return fmt.Errorf("save to backend: %w", err)
	}

	return nil
}

func LoadPrivateKeyFromStorage(keyID string) (crypto.PrivateKey, *types.StoredKey, error) {
	table, err := storage.Backend.LoadTable(dnssecKeyTable)
	if err != nil {
		return nil, nil, fmt.Errorf("load table: %w", err)
	}

	data, ok := table[keyID]
	if !ok {
		return nil, nil, fmt.Errorf("key %q not found", keyID)
	}

	var stored types.StoredKey
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, nil, fmt.Errorf("unmarshal StoredKey: %w", err)
	}

	block, _ := pem.Decode([]byte(stored.PrivatePEM))
	if block == nil {
		return nil, nil, fmt.Errorf("invalid PEM block")
	}

	var privKey crypto.PrivateKey
	switch block.Type {
	case "EC PRIVATE KEY":
		privKey, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY": // for ed25519 (PKCS#8)
		privKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("parse private key: %w", err)
	}

	return privKey, &stored, nil
}

func LoadAllKeysForZone(zone string) ([]*types.StoredKey, error) {
	table, err := storage.Backend.LoadTable(dnssecKeyTable)
	if err != nil {
		return nil, fmt.Errorf("load table: %w", err)
	}

	var keys []*types.StoredKey
	for keyID, raw := range table {
		if strings.Contains(keyID, zone) {
			var stored types.StoredKey
			if err := json.Unmarshal(raw, &stored); err != nil {
				return nil, fmt.Errorf("unmarshal StoredKey for %q: %w", keyID, err)
			}
			keys = append(keys, &stored)
		}
	}

	return keys, nil
}

func GetDNSSECKeys(zoneName string) ([]*dns.DNSKEY, []*dns.DNSKEY, error) {
	zoneApex := dns.Fqdn(zoneName)

	recs, ok := zonereader.LookupRecord(dns.TypeDNSKEY, zoneApex)
	if !ok {
		return nil, nil, fmt.Errorf("no DNSKEY records found for %s", zoneApex)
	}

	var ksks []*dns.DNSKEY
	var zsks []*dns.DNSKEY

	for _, rr := range recs {
		dnskey, ok := rr.(*dns.DNSKEY)
		if !ok {
			continue
		}
		switch dnskey.Flags {
		case 257:
			ksks = append(ksks, dnskey)
		case 256:
			zsks = append(zsks, dnskey)
		default:
			// ignore the rest
		}
	}

	return ksks, zsks, nil
}

func GetDNSSECKeyNames(zoneName string) ([]string, error) {
	zoneApex := dns.Fqdn(zoneName)

	recs, ok := zonereader.LookupRecord(dns.TypeDNSKEY, zoneApex)
	if !ok {
		return nil, fmt.Errorf("no DNSKEY records found for %s", zoneApex)
	}

	var keyNames []string

	for _, rr := range recs {
		dnskey, ok := rr.(*dns.DNSKEY)
		if !ok {
			continue
		}

		var prefix string
		switch dnskey.Flags {
		case 257:
			prefix = "ksk"
		case 256:
			prefix = "zsk"
		default:
			continue
		}

		algoName := dns.AlgorithmToString[dnskey.Algorithm]
		if algoName == "" {
			algoName = fmt.Sprintf("ALG%d", dnskey.Algorithm)
		}

		keyName := fmt.Sprintf("%s_%s_%s", prefix, strings.TrimSuffix(zoneApex, "."), algoName)
		keyNames = append(keyNames, keyName)
	}

	return keyNames, nil
}

func ComputeKeyTag(flags uint16, protocol uint8, algorithm uint8, pubkey []byte) uint16 {
	rdata := make([]byte, 4+len(pubkey))
	rdata[0] = byte(flags >> 8)
	rdata[1] = byte(flags)
	rdata[2] = protocol
	rdata[3] = algorithm
	copy(rdata[4:], pubkey)

	var ac uint32
	for i, b := range rdata {
		if i&1 == 0 {
			ac += uint32(b) << 8
		} else {
			ac += uint32(b)
		}
	}
	ac += (ac >> 16) & 0xFFFF
	return uint16(ac & 0xFFFF)
}

func AlgorithmNumberFromName(name string) uint8 {

	switch name {
	case "RSASHA256":
		return 8
	case "RSASHA512":
		return 10
	case "ECDSAP256SHA256":
		return 13
	case "ECDSAP384SHA384":
		return 14
	case "ED25519":
		return 15
	case "ED448":
		return 16
	default:
		panic("unknown algorithm name: " + name)
	}
}
