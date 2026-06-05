package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"go53/storage"
	"hash"
	"log"
	"strings"
	"sync"
)

var TSIGSecrets map[string]TSIGKey
var tsigMu sync.RWMutex

type TSIGKey struct {
	Algorithm string `json:"algorithm"`
	Secret    string `json:"secret"`
}

func LoadTSIGKeysFromStorage() error {
	tableData, err := storage.Backend.LoadTable("tsig-keys")
	if err != nil {
		return fmt.Errorf("failed to load TSIG keys from storage: %w", err)
	}

	log.Printf("TSIG raw data loaded: %+v", tableData)

	secrets := make(map[string]TSIGKey)

	for name, raw := range tableData {
		var key TSIGKey
		if err := json.Unmarshal(raw, &key); err != nil {
			return fmt.Errorf("failed to unmarshal TSIG key %s: %w", name, err)
		}

		secrets[canonicalTSIGName(name)] = key
	}

	tsigMu.Lock()
	TSIGSecrets = secrets
	tsigMu.Unlock()

	log.Printf("TSIGSecrets loaded: %+v", TSIGSecrets)
	return nil
}

func GetTSIGKey(name string) (TSIGKey, bool) {
	tsigMu.RLock()
	defer tsigMu.RUnlock()

	key, ok := TSIGSecrets[canonicalTSIGName(name)]
	return key, ok
}

func SetTSIGKey(name string, key TSIGKey) {
	tsigMu.Lock()
	defer tsigMu.Unlock()

	if TSIGSecrets == nil {
		TSIGSecrets = make(map[string]TSIGKey)
	}
	TSIGSecrets[canonicalTSIGName(name)] = key
}

func DeleteTSIGKey(name string) {
	tsigMu.Lock()
	defer tsigMu.Unlock()

	delete(TSIGSecrets, canonicalTSIGName(name))
}

func ListTSIGKeys() map[string]TSIGKey {
	tsigMu.RLock()
	defer tsigMu.RUnlock()

	out := make(map[string]TSIGKey, len(TSIGSecrets))
	for name, key := range TSIGSecrets {
		out[name] = key
	}
	return out
}

type DynamicTSIGProvider struct{}

func (DynamicTSIGProvider) Generate(msg []byte, t *dns.TSIG) ([]byte, error) {
	key, ok := GetTSIGKey(t.Hdr.Name)
	if !ok {
		return nil, dns.ErrSecret
	}
	return generateTSIGHMAC(msg, key.Secret, t.Algorithm)
}

func (DynamicTSIGProvider) Verify(msg []byte, t *dns.TSIG) error {
	key, ok := GetTSIGKey(t.Hdr.Name)
	if !ok {
		return dns.ErrSecret
	}
	expected, err := generateTSIGHMAC(msg, key.Secret, t.Algorithm)
	if err != nil {
		return err
	}
	actual, err := hex.DecodeString(t.MAC)
	if err != nil {
		return err
	}
	if !hmac.Equal(expected, actual) {
		return dns.ErrSig
	}
	return nil
}

func canonicalTSIGName(name string) string {
	return dns.CanonicalName(strings.TrimSpace(name))
}

func generateTSIGHMAC(msg []byte, secret string, algorithm string) ([]byte, error) {
	rawSecret, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, err
	}

	var h hash.Hash
	switch dns.CanonicalName(algorithm) {
	case dns.HmacSHA1:
		h = hmac.New(sha1.New, rawSecret)
	case dns.HmacSHA224:
		h = hmac.New(sha256.New224, rawSecret)
	case dns.HmacSHA256:
		h = hmac.New(sha256.New, rawSecret)
	case dns.HmacSHA384:
		h = hmac.New(sha512.New384, rawSecret)
	case dns.HmacSHA512:
		h = hmac.New(sha512.New, rawSecret)
	default:
		return nil, dns.ErrKeyAlg
	}

	h.Write(msg)
	return h.Sum(nil), nil
}

func GenerateTSIGSecret() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}
