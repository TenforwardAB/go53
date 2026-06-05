package security

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/miekg/dns"
	"go53/internal"
	"go53/storage"
	"go53/types"
	"go53/zonereader"
	"log"
	"math/big"
	"sort"
	"strings"
	"time"
)

const dnssecKeyTable = "dnssec_keys"

const (
	KeyStateGenerated = "generated"
	KeyStatePublished = "published"
	KeyStateActive    = "active"
	KeyStateRetired   = "retired"
	KeyStateRevoked   = "revoked"
	KeyStateRemoved   = "removed"

	dnskeyRevokeFlag uint16 = 0x0080
)

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
}

func GenerateAndStoreAllKeys(zone string) error {
	now := time.Now().Unix()
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
				State:      KeyStateActive,
				CreatedAt:  now,
				PublishAt:  now,
				ActivateAt: now,
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
	return GetDSWithDigestTypes(zone, []uint8{dns.SHA256})
}

func GetDSWithDigestTypes(zone string, digestTypes []uint8) ([]*dns.DS, error) {
	dnskeys, err := ParentDSDNSKEYs(zone, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	if len(digestTypes) == 0 {
		digestTypes = []uint8{dns.SHA256}
	}
	var dsList []*dns.DS
	for _, dnskey := range dnskeys {
		for _, digestType := range digestTypes {
			ds := dnskey.ToDS(digestType)
			if ds == nil {
				return nil, fmt.Errorf("failed to build DS digest type %d for key tag %d", digestType, dnskey.KeyTag())
			}
			dsList = append(dsList, ds)
		}
	}
	sort.SliceStable(dsList, func(i, j int) bool {
		if dsList[i].KeyTag != dsList[j].KeyTag {
			return dsList[i].KeyTag < dsList[j].KeyTag
		}
		return dsList[i].DigestType < dsList[j].DigestType
	})
	return dsList, nil
}

func GetCDS(zone string) ([]*dns.CDS, error) {
	dsList, err := GetDSWithDigestTypes(zone, []uint8{dns.SHA256})
	if err != nil {
		return nil, err
	}
	cdsList := make([]*dns.CDS, 0, len(dsList))
	for _, ds := range dsList {
		cdsList = append(cdsList, ds.ToCDS())
	}
	return cdsList, nil
}

func GetCDNSKEY(zone string) ([]*dns.CDNSKEY, error) {
	dnskeys, err := ParentDSDNSKEYs(zone, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	out := make([]*dns.CDNSKEY, 0, len(dnskeys))
	for _, key := range dnskeys {
		out = append(out, key.ToCDNSKEY())
	}
	return out, nil
}

func DeleteDSCDS(zone string, ttl uint32) *dns.CDS {
	if ttl == 0 {
		ttl = 3600
	}
	return &dns.CDS{DS: dns.DS{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(zone),
			Rrtype: dns.TypeCDS,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		KeyTag:     0,
		Algorithm:  0,
		DigestType: 0,
		Digest:     "00",
	}}
}

func DeleteDSCDNSKEY(zone string, ttl uint32) *dns.CDNSKEY {
	if ttl == 0 {
		ttl = 3600
	}
	return &dns.CDNSKEY{DNSKEY: dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(zone),
			Rrtype: dns.TypeCDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Flags:     0,
		Protocol:  3,
		Algorithm: 0,
		PublicKey: "AA==",
	}}
}

func ParentDSDNSKEYs(zone string, now int64) ([]*dns.DNSKEY, error) {
	sz, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return nil, fmt.Errorf("FQDN sanitize check failed: %w", err)
	}

	keys, err := LoadPublishedKeysForZone(sz, now)
	if err != nil {
		return nil, err
	}
	var out []*dns.DNSKEY
	for _, key := range keys {
		if !isKSK(key) || !keySignsAt(key, now) {
			continue
		}
		out = append(out, storedKeyToDNSKEY(sz, key, 3600))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no active KSK DNSKEY found for zone %s", sz)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].KeyTag() < out[j].KeyTag()
	})
	return out, nil
}

func storedKeyToDNSKEY(zone string, key *types.StoredKey, ttl uint32) *dns.DNSKEY {
	return &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(zone),
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Flags:     DNSKEYFlags(key),
		Protocol:  3,
		Algorithm: AlgorithmNumberFromName(key.Algorithm),
		PublicKey: key.PublicKey,
	}
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
			exponent := new(big.Int).SetInt64(int64(k.E)).Bytes()
			modulus := k.N.Bytes()
			if len(exponent) < 256 {
				return append(append([]byte{byte(len(exponent))}, exponent...), modulus...), nil
			}

			out := []byte{0, byte(len(exponent) >> 8), byte(len(exponent))}
			out = append(out, exponent...)
			out = append(out, modulus...)
			return out, nil
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
	if f&1 == 1 {
		return "ksk"
	}
	return "zsk"
}

func roleFlags(role string) (uint16, error) {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "ksk":
		return 257, nil
	case "zsk":
		return 256, nil
	default:
		return 0, fmt.Errorf("unknown DNSSEC key role %q", role)
	}
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
		State:      KeyStateActive,
		CreatedAt:  time.Now().Unix(),
		PublishAt:  time.Now().Unix(),
		ActivateAt: time.Now().Unix(),
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

func GenerateRolloverKey(zone, role, algorithmName string, publishAt, activateAt int64) (string, *types.StoredKey, error) {
	flags, err := roleFlags(role)
	if err != nil {
		return "", nil, err
	}
	algorithm := AlgorithmNumberFromName(algorithmName)
	if algorithm == 0 {
		return "", nil, fmt.Errorf("unsupported algorithm %q", algorithmName)
	}
	now := time.Now().Unix()
	if publishAt == 0 {
		publishAt = now
	}
	if activateAt == 0 {
		activateAt = publishAt
	}

	priv, pub, err := generateKeyPair(algorithm)
	if err != nil {
		return "", nil, err
	}
	pubBytes, err := PublicKeyToDNS(pub, algorithm)
	if err != nil {
		return "", nil, err
	}
	pemPriv, err := EncodePrivateKeyPEM(priv)
	if err != nil {
		return "", nil, err
	}
	keyTag := ComputeKeyTag(flags, 3, algorithm, pubBytes)
	state := KeyStatePublished
	if activateAt <= now {
		state = KeyStateActive
	}
	stored := &types.StoredKey{
		KeyTag:     keyTag,
		Zone:       strings.TrimSuffix(dns.Fqdn(zone), "."),
		Algorithm:  algorithmName,
		Flags:      flags,
		PrivatePEM: pemPriv,
		PublicKey:  base64.StdEncoding.EncodeToString(pubBytes),
		State:      state,
		CreatedAt:  now,
		PublishAt:  publishAt,
		ActivateAt: activateAt,
	}
	keyID := keyIDForStored(stored)
	data, err := json.Marshal(stored)
	if err != nil {
		return "", nil, err
	}
	if err := storage.Backend.SaveTable(dnssecKeyTable, keyID, data); err != nil {
		return "", nil, err
	}
	return keyID, stored, nil
}

func UpdateKeyLifecycle(keyID string, update types.StoredKey) (*types.StoredKey, error) {
	stored, err := LoadStoredKey(keyID)
	if err != nil {
		return nil, err
	}
	if update.State != "" {
		stored.State = update.State
	}
	if update.PublishAt != 0 {
		stored.PublishAt = update.PublishAt
	}
	if update.ActivateAt != 0 {
		stored.ActivateAt = update.ActivateAt
	}
	if update.RetireAt != 0 {
		stored.RetireAt = update.RetireAt
	}
	if update.RemoveAt != 0 {
		stored.RemoveAt = update.RemoveAt
	}
	if update.RevokedAt != 0 {
		stored.RevokedAt = update.RevokedAt
	}
	if update.Revoke {
		stored.Revoke = true
		if stored.RevokedAt == 0 {
			stored.RevokedAt = time.Now().Unix()
		}
		stored.State = KeyStateRevoked
	}
	if update.State == "" {
		stored.State = keyStateAt(stored, time.Now().Unix())
	}
	if err := saveStoredKey(keyID, stored); err != nil {
		return nil, err
	}
	return stored, nil
}

func RetireKey(keyID string, removeAfter time.Duration) (*types.StoredKey, error) {
	now := time.Now().Unix()
	if removeAfter == 0 {
		removeAfter = 30 * 24 * time.Hour
	}
	return UpdateKeyLifecycle(keyID, types.StoredKey{
		State:    KeyStateRetired,
		RetireAt: now,
		RemoveAt: now + int64(removeAfter.Seconds()),
	})
}

func RevokeKey(keyID string, removeAfter time.Duration) (*types.StoredKey, error) {
	now := time.Now().Unix()
	if removeAfter == 0 {
		removeAfter = 30 * 24 * time.Hour
	}
	return UpdateKeyLifecycle(keyID, types.StoredKey{
		State:     KeyStateRevoked,
		Revoke:    true,
		RevokedAt: now,
		RetireAt:  now,
		RemoveAt:  now + int64(removeAfter.Seconds()),
	})
}

func LoadStoredKey(keyID string) (*types.StoredKey, error) {
	table, err := storage.Backend.LoadTable(dnssecKeyTable)
	if err != nil {
		return nil, fmt.Errorf("load table: %w", err)
	}
	data, ok := table[keyID]
	if !ok {
		return nil, fmt.Errorf("key %q not found", keyID)
	}
	var stored types.StoredKey
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("unmarshal StoredKey: %w", err)
	}
	normalizeStoredKey(&stored)
	return &stored, nil
}

func saveStoredKey(keyID string, stored *types.StoredKey) error {
	normalizeStoredKey(stored)
	data, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	return storage.Backend.SaveTable(dnssecKeyTable, keyID, data)
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
	normalizeStoredKey(&stored)

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
			normalizeStoredKey(&stored)
			keys = append(keys, &stored)
		}
	}

	return keys, nil
}

func LoadPublishedKeysForZone(zone string, now int64) (map[string]*types.StoredKey, error) {
	table, err := storage.Backend.LoadTable(dnssecKeyTable)
	if err != nil {
		return nil, fmt.Errorf("load table: %w", err)
	}
	zone = strings.TrimSuffix(dns.Fqdn(zone), ".")
	out := make(map[string]*types.StoredKey)
	for keyID, raw := range table {
		var stored types.StoredKey
		if err := json.Unmarshal(raw, &stored); err != nil {
			return nil, fmt.Errorf("unmarshal StoredKey for %q: %w", keyID, err)
		}
		normalizeStoredKey(&stored)
		if !strings.EqualFold(strings.TrimSuffix(dns.Fqdn(stored.Zone), "."), zone) {
			continue
		}
		if keyPublishedAt(&stored, now) {
			copy := stored
			out[keyID] = &copy
		}
	}
	return out, nil
}

func ActiveSigningKeyIDs(zone string, isDNSKEY bool, now int64) ([]string, error) {
	table, err := storage.Backend.LoadTable(dnssecKeyTable)
	if err != nil {
		return nil, fmt.Errorf("load table: %w", err)
	}
	zone = strings.TrimSuffix(dns.Fqdn(zone), ".")
	var ids []string
	for keyID, raw := range table {
		var stored types.StoredKey
		if err := json.Unmarshal(raw, &stored); err != nil {
			return nil, fmt.Errorf("unmarshal StoredKey for %q: %w", keyID, err)
		}
		normalizeStoredKey(&stored)
		if !strings.EqualFold(strings.TrimSuffix(dns.Fqdn(stored.Zone), "."), zone) {
			continue
		}
		if isDNSKEY && !isKSK(&stored) {
			continue
		}
		if !isDNSKEY && !isZSK(&stored) {
			continue
		}
		if keySignsAt(&stored, now) {
			ids = append(ids, keyID)
		}
	}
	sort.Strings(ids)
	return ids, nil
}

func DNSKEYFlags(stored *types.StoredKey) uint16 {
	if stored == nil {
		return 0
	}
	flags := stored.Flags
	if stored.Revoke {
		flags |= dnskeyRevokeFlag
	}
	return flags
}

func DNSKEYKeyTag(stored *types.StoredKey) uint16 {
	if stored == nil {
		return 0
	}
	pubBytes, err := base64.StdEncoding.DecodeString(stored.PublicKey)
	if err != nil {
		return stored.KeyTag
	}
	return ComputeKeyTag(DNSKEYFlags(stored), 3, AlgorithmNumberFromName(stored.Algorithm), pubBytes)
}

func normalizeStoredKey(stored *types.StoredKey) {
	if stored == nil {
		return
	}
	stored.Zone = strings.TrimSuffix(dns.Fqdn(stored.Zone), ".")
	if stored.State == "" {
		stored.State = KeyStateActive
	}
	if stored.CreatedAt == 0 {
		stored.CreatedAt = time.Now().Unix()
	}
	if stored.PublishAt == 0 {
		stored.PublishAt = stored.CreatedAt
	}
	if stored.State == KeyStateActive && stored.ActivateAt == 0 {
		stored.ActivateAt = stored.PublishAt
	}
}

func keyPublishedAt(stored *types.StoredKey, now int64) bool {
	normalizeStoredKey(stored)
	if now == 0 {
		now = time.Now().Unix()
	}
	if stored.State == KeyStateRemoved {
		return false
	}
	if stored.PublishAt > now {
		return false
	}
	if stored.RemoveAt != 0 && stored.RemoveAt <= now {
		return false
	}
	return true
}

func keySignsAt(stored *types.StoredKey, now int64) bool {
	normalizeStoredKey(stored)
	if now == 0 {
		now = time.Now().Unix()
	}
	if stored.Revoke || stored.State == KeyStateRevoked || stored.State == KeyStateRemoved {
		return false
	}
	if stored.ActivateAt == 0 || stored.ActivateAt > now {
		return false
	}
	if stored.RetireAt != 0 && stored.RetireAt <= now {
		return false
	}
	return true
}

func keyStateAt(stored *types.StoredKey, now int64) string {
	normalizeStoredKey(stored)
	switch {
	case stored.RemoveAt != 0 && stored.RemoveAt <= now:
		return KeyStateRemoved
	case stored.Revoke:
		return KeyStateRevoked
	case stored.RetireAt != 0 && stored.RetireAt <= now:
		return KeyStateRetired
	case stored.ActivateAt != 0 && stored.ActivateAt <= now:
		return KeyStateActive
	case stored.PublishAt != 0 && stored.PublishAt <= now:
		return KeyStatePublished
	default:
		return KeyStateGenerated
	}
}

func isKSK(stored *types.StoredKey) bool {
	return stored.Flags&1 == 1
}

func isZSK(stored *types.StoredKey) bool {
	return stored.Flags&1 == 0
}

func keyIDForStored(stored *types.StoredKey) string {
	return fmt.Sprintf("%s_%s_%s_%d", flagName(stored.Flags), strings.TrimSuffix(dns.Fqdn(stored.Zone), "."), stored.Algorithm, stored.KeyTag)
}

func GetDNSSECKeys(zoneName string) ([]*dns.DNSKEY, []*dns.DNSKEY, error) {
	zoneApex, _ := internal.SanitizeFQDN(zoneName)

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
	return ActiveSigningKeyIDs(zoneName, false, time.Now().Unix())
}

func GetDNSSECKeyNamesForRRSet(zoneName string, isDNSKEY bool) ([]string, error) {
	return ActiveSigningKeyIDs(zoneName, isDNSKEY, time.Now().Unix())
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
