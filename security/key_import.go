package security

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go53/types"
	"math/big"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type PrivateKeyImportFile struct {
	Format  string                  `json:"format"`
	Version int                     `json:"version"`
	Source  string                  `json:"source"`
	Zone    string                  `json:"zone"`
	Keys    []PrivateKeyImportEntry `json:"keys"`
}

type PrivateKeyImportEntry struct {
	SourceKeyID      string `json:"source_key_id"`
	Role             string `json:"role"`
	Flags            uint16 `json:"flags"`
	Algorithm        string `json:"algorithm"`
	AlgorithmNumber  uint8  `json:"algorithm_number"`
	KeyTag           uint16 `json:"keytag"`
	PrivateKeyFormat string `json:"private_key_format"`
	PrivateAlgorithm string `json:"private_algorithm"`
	PrivateKey       string `json:"private_key"`
}

type PrivateKeyImportResult struct {
	Imported []string `json:"imported"`
}

func ImportPrivateKeys(data []byte) (PrivateKeyImportResult, error) {
	var in PrivateKeyImportFile
	if err := json.Unmarshal(data, &in); err != nil {
		return PrivateKeyImportResult{}, fmt.Errorf("invalid key import JSON: %w", err)
	}
	if in.Format != "go53-dnssec-private-keys" || in.Version != 1 {
		return PrivateKeyImportResult{}, fmt.Errorf("unsupported key import format")
	}
	zone := dns.Fqdn(in.Zone)
	if zone == "." || len(in.Keys) == 0 {
		return PrivateKeyImportResult{}, fmt.Errorf("key import requires zone and at least one key")
	}

	var result PrivateKeyImportResult
	for _, entry := range in.Keys {
		keyID, err := importPrivateKeyEntry(zone, entry)
		if err != nil {
			return result, err
		}
		result.Imported = append(result.Imported, keyID)
	}
	return result, nil
}

func importPrivateKeyEntry(zone string, entry PrivateKeyImportEntry) (string, error) {
	algorithm := strings.ToUpper(strings.TrimSpace(entry.Algorithm))
	if algorithm == "" && entry.AlgorithmNumber != 0 {
		algorithm = algorithmNameFromNumber(entry.AlgorithmNumber)
	}
	if algorithm == "" {
		return "", fmt.Errorf("missing algorithm for source key %q", entry.SourceKeyID)
	}
	algorithmNumber, ok := algorithmNumberByName(algorithm)
	if !ok {
		return "", fmt.Errorf("unsupported algorithm %q for source key %q", algorithm, entry.SourceKeyID)
	}
	if entry.AlgorithmNumber != 0 && entry.AlgorithmNumber != algorithmNumber {
		return "", fmt.Errorf("algorithm mismatch for source key %q", entry.SourceKeyID)
	}
	flags := entry.Flags
	if flags == 0 {
		switch strings.ToLower(entry.Role) {
		case "ksk", "csk":
			flags = 257
		case "zsk":
			flags = 256
		default:
			return "", fmt.Errorf("missing flags for source key %q", entry.SourceKeyID)
		}
	}

	priv, pub, err := privateKeyFromImport(entry.PrivateKey, algorithmNumber)
	if err != nil {
		return "", fmt.Errorf("source key %q: %w", entry.SourceKeyID, err)
	}
	pubBytes, err := importedPublicKeyToDNS(pub, algorithmNumber)
	if err != nil {
		return "", err
	}
	keyTag := ComputeKeyTag(flags, 3, algorithmNumber, pubBytes)
	if entry.KeyTag != 0 && entry.KeyTag != keyTag {
		return "", fmt.Errorf("source key %q keytag mismatch: import=%d computed=%d", entry.SourceKeyID, entry.KeyTag, keyTag)
	}
	pemPriv, err := EncodePrivateKeyPEM(priv)
	if err != nil {
		return "", err
	}
	now := time.Now().Unix()
	stored := &types.StoredKey{
		KeyTag:     keyTag,
		Zone:       strings.TrimSuffix(zone, "."),
		Algorithm:  algorithm,
		Flags:      flags,
		PrivatePEM: pemPriv,
		PublicKey:  base64.StdEncoding.EncodeToString(pubBytes),
		State:      KeyStateActive,
		CreatedAt:  now,
		PublishAt:  now,
		ActivateAt: now,
	}
	keyID := keyIDForStored(stored)
	return keyID, saveStoredKey(keyID, stored)
}

func privateKeyFromImport(encoded string, algorithm uint8) (crypto.PrivateKey, crypto.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, nil, fmt.Errorf("private key is not valid base64: %w", err)
	}
	switch algorithm {
	case 13:
		return ecdsaFromScalar(elliptic.P256(), raw)
	case 14:
		return ecdsaFromScalar(elliptic.P384(), raw)
	case 15:
		if len(raw) != ed25519.SeedSize {
			return nil, nil, fmt.Errorf("ED25519 private key must be a 32-byte seed")
		}
		priv := ed25519.NewKeyFromSeed(raw)
		return priv, priv.Public(), nil
	default:
		return nil, nil, fmt.Errorf("private key import for algorithm %d is not implemented", algorithm)
	}
}

func importedPublicKeyToDNS(pub crypto.PublicKey, algorithm uint8) ([]byte, error) {
	switch algorithm {
	case 13:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok || k.X == nil || k.Y == nil {
			return nil, fmt.Errorf("invalid ECDSA public key")
		}
		x := k.X.Bytes()
		y := k.Y.Bytes()
		return append(append(make([]byte, 32-len(x)), x...), append(make([]byte, 32-len(y)), y...)...), nil
	case 14:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok || k.X == nil || k.Y == nil {
			return nil, fmt.Errorf("invalid ECDSA P-384 public key")
		}
		x := k.X.Bytes()
		y := k.Y.Bytes()
		return append(append(make([]byte, 48-len(x)), x...), append(make([]byte, 48-len(y)), y...)...), nil
	default:
		return PublicKeyToDNS(pub, algorithm)
	}
}

func ecdsaFromScalar(curve elliptic.Curve, scalar []byte) (*ecdsa.PrivateKey, crypto.PublicKey, error) {
	d := new(big.Int).SetBytes(scalar)
	if d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 {
		return nil, nil, fmt.Errorf("ECDSA private scalar is out of range")
	}
	x, y := curve.ScalarBaseMult(scalar)
	if x == nil || y == nil {
		return nil, nil, fmt.Errorf("failed to derive ECDSA public key")
	}
	priv := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}
	return priv, &priv.PublicKey, nil
}

func algorithmNameFromNumber(number uint8) string {
	switch number {
	case 8:
		return "RSASHA256"
	case 10:
		return "RSASHA512"
	case 13:
		return "ECDSAP256SHA256"
	case 14:
		return "ECDSAP384SHA384"
	case 15:
		return "ED25519"
	default:
		return ""
	}
}

func algorithmNumberByName(name string) (uint8, bool) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "RSASHA256":
		return 8, true
	case "RSASHA512":
		return 10, true
	case "ECDSAP256SHA256":
		return 13, true
	case "ECDSAP384SHA384":
		return 14, true
	case "ED25519":
		return 15, true
	default:
		return 0, false
	}
}
