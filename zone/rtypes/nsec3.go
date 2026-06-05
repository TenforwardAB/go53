package rtypes

import (
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"go53/internal"
	"go53/types"
	"sort"
	"strings"
)

type NSEC3 struct{}

func (NSEC3) Add(zone, name string, value interface{}, ttl *uint32) error {
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN Sanitize check failed")
	}

	m, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("NSEC3Record expects value to be a JSON object, got %T", value)
	}

	getUint8 := func(k string) (uint8, error) {
		v, ok := m[k].(float64)
		if !ok {
			return 0, fmt.Errorf("field '%s' must be number", k)
		}
		return uint8(v), nil
	}

	getUint16 := func(k string) (uint16, error) {
		v, ok := m[k].(float64)
		if !ok {
			return 0, fmt.Errorf("field '%s' must be number", k)
		}
		return uint16(v), nil
	}

	hashAlg, err := getUint8("hash_algorithm")
	if err != nil {
		return err
	}
	flags, err := getUint8("flags")
	if err != nil {
		return err
	}
	if flags&^1 != 0 {
		return fmt.Errorf("NSEC3 flags contains unsupported bits: %d", flags)
	}
	iterations, err := getUint16("iterations")
	if err != nil {
		return err
	}
	salt, ok := m["salt"].(string)
	if !ok {
		return fmt.Errorf("field 'salt' must be string")
	}
	if strings.TrimSpace(salt) == "-" {
		salt = ""
	}
	nextHashed, ok := m["next_hashed"].(string)
	if !ok {
		return fmt.Errorf("field 'next_hashed' must be string")
	}
	if !validNSEC3Hash(nextHashed) {
		return fmt.Errorf("field 'next_hashed' must be an unpadded base32hex NSEC3 hash")
	}
	if name != "" && name != "@" && !validNSEC3Hash(name) {
		return fmt.Errorf("NSEC3 owner name must be an unpadded base32hex hash")
	}
	if !validNSEC3Salt(salt) {
		return fmt.Errorf("field 'salt' must be empty, '-', or hex-encoded")
	}
	typeList, ok := m["types"].([]interface{})
	if !ok {
		return fmt.Errorf("field 'types' must be array of strings")
	}
	var typesStr []string
	for _, v := range typeList {
		if s, ok := v.(string); ok {
			typesStr = append(typesStr, s)
		}
	}

	ttlVal := uint32(3600)
	if ttl != nil {
		ttlVal = *ttl
	}
	if t, ok := m["ttl"].(float64); ok {
		ttlVal = uint32(t)
	}

	rec := types.NSEC3Record{
		HashAlg:    hashAlg,
		Flags:      flags,
		Iterations: iterations,
		Salt:       salt,
		NextHashed: nextHashed,
		Types:      typesStr,
		TTL:        ttlVal,
	}

	if memStore == nil {
		return errors.New("memory store not initialized")
	}

	key := name
	if key == "" {
		key = "@"
	}

	return memStore.AddRecord(sanitizedZone, string(types.TypeNSEC3), key, rec)
}

func (NSEC3) Lookup(host string) ([]dns.RR, bool) {
	zone, name, ok := internal.SplitName(host)
	if !ok {
		return nil, false
	}
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil || memStore == nil {
		return nil, false
	}

	_, _, raw, found := memStore.GetRecord(sanitizedZone, string(types.TypeNSEC3), name)
	if !found {
		return nil, false
	}

	var rec types.NSEC3Record
	switch v := raw.(type) {
	case types.NSEC3Record:
		rec = v
	case map[string]interface{}:
		// Decode the JSON-shaped map used by the storage layer.
		if s, ok := v["next_hashed"].(string); ok {
			rec.NextHashed = s
		}
		if s, ok := v["salt"].(string); ok {
			rec.Salt = s
		}
		if f, ok := v["hash_algorithm"].(float64); ok {
			rec.HashAlg = uint8(f)
		}
		if f, ok := v["flags"].(float64); ok {
			rec.Flags = uint8(f)
		}
		if f, ok := v["iterations"].(float64); ok {
			rec.Iterations = uint16(f)
		}
		if f, ok := v["ttl"].(float64); ok {
			rec.TTL = uint32(f)
		}
		if arr, ok := v["types"].([]interface{}); ok {
			for _, t := range arr {
				if s, ok := t.(string); ok {
					rec.Types = append(rec.Types, s)
				}
			}
		}
	default:
		return nil, false
	}
	if !validNSEC3Hash(rec.NextHashed) {
		return nil, false
	}

	var bitmap []uint16
	for _, t := range rec.Types {
		if code, ok := dns.StringToType[t]; ok {
			bitmap = append(bitmap, code)
		}
	}
	sort.Slice(bitmap, func(i, j int) bool {
		return bitmap[i] < bitmap[j]
	})

	return []dns.RR{
		&dns.NSEC3{
			Hdr: dns.RR_Header{
				Name:   host,
				Rrtype: dns.TypeNSEC3,
				Class:  dns.ClassINET,
				Ttl:    rec.TTL,
			},
			Hash:       rec.HashAlg,
			Flags:      rec.Flags,
			Iterations: rec.Iterations,
			SaltLength: uint8(nsec3SaltLength(rec.Salt)),
			Salt:       rec.Salt,
			HashLength: uint8(nsec3HashLength(rec.NextHashed)),
			NextDomain: rec.NextHashed,
			TypeBitMap: bitmap,
		},
	}, true
}

func (NSEC3) Delete(host string, _ interface{}) error {
	zone, name, ok := internal.SplitName(host)
	if !ok {
		return errors.New("invalid host format")
	}
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN Sanitize check failed")
	}
	if memStore == nil {
		return errors.New("memory store not initialized")
	}

	return memStore.DeleteRecord(sanitizedZone, string(types.TypeNSEC3), name)
}

func (NSEC3) Type() uint16 {
	return dns.TypeNSEC3
}

func init() {
	Register(NSEC3{})
}

func validNSEC3Hash(value string) bool {
	return nsec3HashLength(value) > 0
}

func validNSEC3Salt(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || value == "-" {
		return true
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func nsec3HashLength(value string) int {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" {
		return 0
	}
	decoded, err := base32.HexEncoding.WithPadding(base32.NoPadding).DecodeString(value)
	if err != nil {
		return 0
	}
	return len(decoded)
}

func nsec3SaltLength(value string) int {
	value = strings.TrimSpace(value)
	if value == "" || value == "-" {
		return 0
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return 0
	}
	return len(decoded)
}
