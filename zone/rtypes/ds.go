package rtypes

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"go53/internal"
	"go53/types"
)

type DSRecord struct{}

func (DSRecord) Add(zone, name string, value interface{}, ttl *uint32) error {
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN sanitize check failed")
	}
	if memStore == nil {
		return errors.New("memory store not initialized")
	}

	m, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("DSRecord expects value to be a JSON object, got %T", value)
	}

	keyTag, err := uint16Field(m, "key_tag")
	if err != nil {
		return err
	}
	algorithm, err := uint8Field(m, "algorithm")
	if err != nil {
		return err
	}
	digestType, err := uint8Field(m, "digest_type")
	if err != nil {
		return err
	}
	digest, ok := m["digest"].(string)
	if !ok || strings.TrimSpace(digest) == "" {
		return fmt.Errorf("DSRecord expects field 'digest' as non-empty string")
	}

	ttlVal := uint32(3600)
	if ttl != nil {
		ttlVal = *ttl
	}
	if t, ok := m["ttl"].(float64); ok {
		ttlVal = uint32(t)
	}

	key := name
	if key == "" {
		key = "@"
	}

	var current []types.DSRecord
	_, _, existing, found := memStore.GetRecord(sanitizedZone, string(types.TypeDS), key)
	if found {
		current = dsRecordsFromRaw(existing)
	}

	rec := types.DSRecord{
		KeyTag:     keyTag,
		Algorithm:  algorithm,
		DigestType: digestType,
		Digest:     strings.ToUpper(strings.TrimSpace(digest)),
		TTL:        ttlVal,
	}
	for _, existing := range current {
		if existing.KeyTag == rec.KeyTag && existing.Algorithm == rec.Algorithm && existing.DigestType == rec.DigestType && strings.EqualFold(existing.Digest, rec.Digest) {
			return nil
		}
	}

	current = append(current, rec)
	return memStore.AddRecord(sanitizedZone, string(types.TypeDS), key, current)
}

func (DSRecord) Lookup(host string) ([]dns.RR, bool) {
	zone, name, ok := internal.SplitName(host)
	if !ok {
		return nil, false
	}
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil || memStore == nil {
		return nil, false
	}

	_, _, raw, found := memStore.GetRecord(sanitizedZone, string(types.TypeDS), name)
	if !found {
		return nil, false
	}

	records := dsRecordsFromRaw(raw)
	if len(records) == 0 {
		return nil, false
	}

	out := make([]dns.RR, 0, len(records))
	for _, rec := range records {
		out = append(out, &dns.DS{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(host),
				Rrtype: dns.TypeDS,
				Class:  dns.ClassINET,
				Ttl:    rec.TTL,
			},
			KeyTag:     rec.KeyTag,
			Algorithm:  rec.Algorithm,
			DigestType: rec.DigestType,
			Digest:     strings.ToUpper(rec.Digest),
		})
	}
	return out, true
}

func (DSRecord) Delete(host string, value interface{}) error {
	zone, name, ok := internal.SplitName(host)
	if !ok {
		return errors.New("invalid host format")
	}
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN sanitize check failed")
	}
	if memStore == nil {
		return errors.New("memory store not initialized")
	}
	if value == nil {
		return memStore.DeleteRecord(sanitizedZone, string(types.TypeDS), name)
	}
	return errors.New("DSRecord Delete only supports deleting the full RRSet")
}

func (DSRecord) Type() uint16 {
	return dns.TypeDS
}

func init() {
	Register(DSRecord{})
}

func dsRecordsFromRaw(raw any) []types.DSRecord {
	switch v := raw.(type) {
	case []types.DSRecord:
		return append([]types.DSRecord(nil), v...)
	case []interface{}:
		var records []types.DSRecord
		for _, item := range v {
			obj, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			records = append(records, types.DSRecord{
				KeyTag:     uint16(rawFloat64(obj["key_tag"])),
				Algorithm:  uint8(rawFloat64(obj["algorithm"])),
				DigestType: uint8(rawFloat64(obj["digest_type"])),
				Digest:     strings.ToUpper(strings.TrimSpace(fmt.Sprint(obj["digest"]))),
				TTL:        rawTTL(obj),
			})
		}
		return records
	default:
		return nil
	}
}

func uint16Field(m map[string]interface{}, key string) (uint16, error) {
	v, ok := m[key].(float64)
	if !ok {
		return 0, fmt.Errorf("DSRecord expects numeric field '%s'", key)
	}
	return uint16(v), nil
}

func uint8Field(m map[string]interface{}, key string) (uint8, error) {
	v, ok := m[key].(float64)
	if !ok {
		return 0, fmt.Errorf("DSRecord expects numeric field '%s'", key)
	}
	return uint8(v), nil
}

func rawFloat64(v interface{}) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case uint16:
		return float64(n)
	case uint8:
		return float64(n)
	default:
		return 0
	}
}

func rawTTL(m map[string]interface{}) uint32 {
	if ttl := rawFloat64(m["ttl"]); ttl > 0 {
		return uint32(ttl)
	}
	return 3600
}
