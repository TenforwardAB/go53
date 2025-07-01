package rtypes

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"go53/internal"
	"go53/types"
)

type DNSKEYRecord struct{}

func (DNSKEYRecord) Add(zone, name string, value interface{}, ttl *uint32) error {
	sz, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return fmt.Errorf("FQDN sanitize check failed: %w", err)
	}

	sn, err := internal.SanitizeFQDN(name)
	if err != nil {
		return fmt.Errorf("FQDN sanitize check failed for name: %w", err)
	}

	key := sn
	if sz == sn {
		key = "@"
	}

	m, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("DNSKEYRecord expects value to be a JSON object, got %T", value)
	}

	rec := types.DNSKEYRecord{
		TTL:      3600,
		Protocol: 3,
	}

	if ttl != nil {
		rec.TTL = *ttl
	}

	if f, ok := m["flags"]; ok {
		switch v := f.(type) {
		case float64:
			rec.Flags = uint16(v)
		case int:
			rec.Flags = uint16(v)
		case uint16:
			rec.Flags = v
		default:
			return fmt.Errorf("DNSKEYRecord: invalid 'flags' type %T", v)
		}
	} else {
		return errors.New("DNSKEYRecord: missing 'flags'")
	}

	if p, ok := m["protocol"]; ok {
		switch v := p.(type) {
		case float64:
			rec.Protocol = uint8(v)
		case int:
			rec.Protocol = uint8(v)
		case uint8:
			rec.Protocol = v
		}
	}

	if a, ok := m["algorithm"]; ok {
		switch v := a.(type) {
		case float64:
			rec.Algorithm = uint8(v)
		case int:
			rec.Algorithm = uint8(v)
		case uint8:
			rec.Algorithm = v
		default:
			return fmt.Errorf("DNSKEYRecord: invalid 'algorithm' type %T", v)
		}
	} else {
		return errors.New("DNSKEYRecord: missing 'algorithm'")
	}

	if pk, ok := m["public_key"].(string); ok {
		rec.PublicKey = pk
	} else {
		return errors.New("DNSKEYRecord: missing or invalid 'public_key'")
	}

	if memStore == nil {
		return errors.New("memory store not initialized")
	}

	_, _, existing, found := memStore.GetRecord(sz, string(types.TypeDNSKEY), key)

	var current []types.DNSKEYRecord
	if found {
		switch v := existing.(type) {
		case []types.DNSKEYRecord:
			current = v
		case []interface{}:
			for _, item := range v {
				if obj, ok := item.(map[string]interface{}); ok {
					parsed, ok := parseToDNSKEYRecord(obj)
					if ok {
						current = append(current, parsed)
					}
				}
			}
		}
	}

	for _, r := range current {
		if r.PublicKey == rec.PublicKey && r.Algorithm == rec.Algorithm && r.Flags == rec.Flags {
			return nil // duplicate
		}
	}

	current = append(current, rec)
	return memStore.AddRecord(sz, string(types.TypeDNSKEY), key, current)
}

func (DNSKEYRecord) Lookup(host string) ([]dns.RR, bool) {
	zone, name, ok := internal.SplitName(host)
	if !ok {
		return nil, false
	}

	sz, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return nil, false
	}

	if memStore == nil {
		return nil, false
	}

	_, _, val, ok := memStore.GetRecord(sz, string(types.TypeDNSKEY), name)
	if !ok {
		return nil, false
	}

	var records []types.DNSKEYRecord
	switch v := val.(type) {
	case []types.DNSKEYRecord:
		records = v
	case []interface{}:
		for _, item := range v {
			if obj, ok := item.(map[string]interface{}); ok {
				if rec, ok := parseToDNSKEYRecord(obj); ok {
					records = append(records, rec)
				}
			}
		}
	case map[string]interface{}:
		if rec, ok := parseToDNSKEYRecord(v); ok {
			records = append(records, rec)
		}
	case types.DNSKEYRecord:
		records = append(records, v)
	}

	var out []dns.RR
	for _, rec := range records {
		out = append(out, &dns.DNSKEY{
			Hdr: dns.RR_Header{
				Name:   host,
				Rrtype: dns.TypeDNSKEY,
				Class:  dns.ClassINET,
				Ttl:    rec.TTL,
			},
			Flags:     rec.Flags,
			Protocol:  rec.Protocol,
			Algorithm: rec.Algorithm,
			PublicKey: rec.PublicKey,
		})
	}

	return out, len(out) > 0
}

func (DNSKEYRecord) Delete(host string, value interface{}) error {
	zone, name, ok := internal.SplitName(host)
	if !ok {
		return errors.New("invalid host format")
	}

	sz, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN sanitize check failed")
	}

	if memStore == nil {
		return errors.New("memory store not initialized")
	}

	if value == nil {
		return memStore.DeleteRecord(sz, string(types.TypeDNSKEY), name)
	}

	obj, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("DNSKEYRecord Delete expects a JSON object, got %T", value)
	}

	target, ok := parseToDNSKEYRecord(obj)
	if !ok {
		return errors.New("DNSKEYRecord Delete: invalid DNSKEY structure")
	}

	_, _, existing, found := memStore.GetRecord(sz, string(types.TypeDNSKEY), name)
	if !found {
		return nil
	}

	var remaining []types.DNSKEYRecord
	switch v := existing.(type) {
	case []types.DNSKEYRecord:
		for _, r := range v {
			if r.PublicKey != target.PublicKey || r.Algorithm != target.Algorithm || r.Flags != target.Flags {
				remaining = append(remaining, r)
			}
		}
	case []interface{}:
		for _, item := range v {
			if obj, ok := item.(map[string]interface{}); ok {
				rec, ok := parseToDNSKEYRecord(obj)
				if ok && (rec.PublicKey != target.PublicKey || rec.Algorithm != target.Algorithm || rec.Flags != target.Flags) {
					remaining = append(remaining, rec)
				}
			}
		}
	}

	if len(remaining) == 0 {
		return memStore.DeleteRecord(sz, string(types.TypeDNSKEY), name)
	}
	return memStore.AddRecord(sz, string(types.TypeDNSKEY), name, remaining)
}

func (DNSKEYRecord) Type() uint16 {
	return dns.TypeDNSKEY
}

func init() {
	Register(DNSKEYRecord{})
}

func parseToDNSKEYRecord(m map[string]interface{}) (types.DNSKEYRecord, bool) {
	rec := types.DNSKEYRecord{
		TTL:      3600,
		Protocol: 3,
	}

	if f, ok := m["flags"].(float64); ok {
		rec.Flags = uint16(f)
	}
	if p, ok := m["protocol"].(float64); ok {
		rec.Protocol = uint8(p)
	}
	if a, ok := m["algorithm"].(float64); ok {
		rec.Algorithm = uint8(a)
	}
	if pk, ok := m["public_key"].(string); ok {
		rec.PublicKey = pk
	}
	if t, ok := m["ttl"].(float64); ok {
		rec.TTL = uint32(t)
	}

	return rec, rec.PublicKey != ""
}
