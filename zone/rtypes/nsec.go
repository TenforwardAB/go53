package rtypes

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"go53/internal"
	"go53/types"
	"sort"
)

type NSEC struct{}

func (NSEC) Add(zone, name string, value interface{}, ttl *uint32) error {
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN Sanitize check failed")
	}

	m, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("NSECRecord expects value to be a JSON object, got %T", value)
	}

	next, ok := m["next_domain"].(string)
	if !ok {
		return fmt.Errorf("NSECRecord expects field 'next_domain' as string")
	}

	typesList, ok := m["types"].([]interface{})
	if !ok {
		return fmt.Errorf("NSECRecord expects field 'types' as array of strings")
	}

	var typeStrs []string
	for _, t := range typesList {
		s, ok := t.(string)
		if !ok {
			return fmt.Errorf("NSECRecord.types must be array of strings")
		}
		typeStrs = append(typeStrs, s)
	}

	ttlVal := uint32(3600)
	if ttl != nil {
		ttlVal = *ttl
	}
	if v, ok := m["ttl"].(float64); ok {
		ttlVal = uint32(v)
	}

	rec := types.NSECRecord{
		NextDomain: next,
		Types:      typeStrs,
		TTL:        ttlVal,
	}

	if memStore == nil {
		return errors.New("memory store not initialized")
	}

	key := normalizeRecordKey(sanitizedZone, name)

	return memStore.AddRecord(sanitizedZone, string(types.TypeNSEC), key, rec)
}

func (NSEC) Lookup(host string) ([]dns.RR, bool) {
	zone, name, ok := internal.SplitName(host)
	if !ok {
		return nil, false
	}
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil || memStore == nil {
		return nil, false
	}

	_, _, raw, found := memStore.GetRecord(sanitizedZone, string(types.TypeNSEC), name)
	if !found {
		return nil, false
	}

	var rec types.NSECRecord
	switch v := raw.(type) {
	case types.NSECRecord:
		rec = v
	case map[string]interface{}:
		rec.NextDomain, _ = v["next_domain"].(string)
		rec.TTL = 3600
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
		&dns.NSEC{
			Hdr: dns.RR_Header{
				Name:   host,
				Rrtype: dns.TypeNSEC,
				Class:  dns.ClassINET,
				Ttl:    rec.TTL,
			},
			NextDomain: dns.Fqdn(rec.NextDomain),
			TypeBitMap: bitmap,
		},
	}, true
}

func (NSEC) Delete(host string, _ interface{}) error {
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

	return memStore.DeleteRecord(sanitizedZone, string(types.TypeNSEC), name)
}

func (NSEC) Type() uint16 {
	return dns.TypeNSEC
}

func init() {
	Register(NSEC{})
}
