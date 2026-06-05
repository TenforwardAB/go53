package rtypes

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"go53/internal"
	"go53/types"
)

type NSEC3PARAM struct{}

func (NSEC3PARAM) Add(zone, name string, value interface{}, ttl *uint32) error {
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN sanitize failed")
	}
	if memStore == nil {
		return errors.New("memory store not initialized")
	}

	m, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("NSEC3PARAM expects value to be a JSON object, got %T", value)
	}

	getUint8 := func(key string) (uint8, error) {
		if v, ok := m[key].(float64); ok {
			return uint8(v), nil
		}
		return 0, fmt.Errorf("field '%s' must be a number", key)
	}
	getUint16 := func(key string) (uint16, error) {
		if v, ok := m[key].(float64); ok {
			return uint16(v), nil
		}
		return 0, fmt.Errorf("field '%s' must be a number", key)
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
		return fmt.Errorf("NSEC3PARAM flags contains unsupported bits: %d", flags)
	}
	iterations, err := getUint16("iterations")
	if err != nil {
		return err
	}
	salt, ok := m["salt"].(string)
	if !ok {
		return fmt.Errorf("field 'salt' must be string")
	}
	if salt == "-" {
		salt = ""
	}

	ttlVal := uint32(3600)
	if ttl != nil {
		ttlVal = *ttl
	}
	if t, ok := m["ttl"].(float64); ok {
		ttlVal = uint32(t)
	}

	rec := types.NSEC3ParamRecord{
		HashAlgorithm: hashAlg,
		Flags:         flags,
		Iterations:    iterations,
		Salt:          salt,
		TTL:           ttlVal,
	}

	// name always "@" to indicate "one per zon"
	if name == "" {
		name = "@"
	}

	return memStore.AddRecord(sanitizedZone, "NSEC3PARAM", name, rec)
}

func (NSEC3PARAM) Lookup(host string) ([]dns.RR, bool) {
	zone, _, ok := internal.SplitName(host)
	if !ok {
		return nil, false
	}
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil || memStore == nil {
		return nil, false
	}

	// name always "@"
	_, _, raw, found := memStore.GetRecord(sanitizedZone, "NSEC3PARAM", "@")
	if !found {
		return nil, false
	}

	var rec types.NSEC3ParamRecord
	switch v := raw.(type) {
	case types.NSEC3ParamRecord:
		rec = v
	case map[string]interface{}:
		if f, ok := v["hash_algorithm"].(float64); ok {
			rec.HashAlgorithm = uint8(f)
		}
		if f, ok := v["flags"].(float64); ok {
			rec.Flags = uint8(f)
		}
		if f, ok := v["iterations"].(float64); ok {
			rec.Iterations = uint16(f)
		}
		if s, ok := v["salt"].(string); ok {
			rec.Salt = s
		}
		if f, ok := v["ttl"].(float64); ok {
			rec.TTL = uint32(f)
		}
	default:
		return nil, false
	}

	return []dns.RR{
		&dns.NSEC3PARAM{
			Hdr: dns.RR_Header{
				Name:   sanitizedZone,
				Rrtype: dns.TypeNSEC3PARAM,
				Class:  dns.ClassINET,
				Ttl:    rec.TTL,
			},
			Hash:       rec.HashAlgorithm,
			Flags:      rec.Flags,
			Iterations: rec.Iterations,
			SaltLength: uint8(nsec3ParamSaltLength(rec.Salt)),
			Salt:       rec.Salt,
		},
	}, true
}

func (NSEC3PARAM) Delete(host string, _ interface{}) error {
	zone, _, ok := internal.SplitName(host)
	if !ok {
		return errors.New("invalid host format")
	}
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN sanitize failed")
	}
	if memStore == nil {
		return errors.New("memory store not initialized")
	}
	return memStore.DeleteRecord(sanitizedZone, "NSEC3PARAM", "@")
}

func (NSEC3PARAM) Type() uint16 {
	return dns.TypeNSEC3PARAM
}

func init() {
	Register(NSEC3PARAM{})
}

func nsec3ParamSaltLength(value string) int {
	if value == "" || value == "-" {
		return 0
	}
	return len(value) / 2
}
