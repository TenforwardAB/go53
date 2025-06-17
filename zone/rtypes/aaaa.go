package rtypes

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"go53/internal"
	"go53/types"
	"net"
)

type AAAARecord struct{}

func (AAAARecord) Add(zone, name string, value interface{}, ttl *uint32) error {
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN sanitize check failed")
	}

	m, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("AAAARecord expects value to be a JSON object, got %T", value)
	}

	rawIP, ok := m["ip"]
	if !ok {
		return fmt.Errorf("AAAARecord expects field 'ip'")
	}

	ip, ok := rawIP.(string)
	if !ok {
		return fmt.Errorf("AAAARecord: field 'ip' must be a string, got %T", rawIP)
	}

	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To16() == nil || parsed.To4() != nil {
		return fmt.Errorf("AAAARecord: invalid IPv6 address %q", ip)
	}

	TTL := uint32(3600)
	if ttl != nil {
		TTL = *ttl
	}

	if memStore == nil {
		return errors.New("memory store not initialized")
	}

	key := name
	if key == "" {
		key = "@"
	}

	_, _, val, found := memStore.GetRecord(sanitizedZone, string(types.TypeAAAA), key)

	var currentList []types.AAAARecord
	if found {
		switch v := val.(type) {
		case []types.AAAARecord:
			currentList = v
		case []interface{}:
			for _, item := range v {
				if obj, ok := item.(map[string]interface{}); ok {
					if ipStr, ok := obj["ip"].(string); ok {
						ttlVal := uint32(3600)
						if t, ok := obj["ttl"].(float64); ok {
							ttlVal = uint32(t)
						}
						currentList = append(currentList, types.AAAARecord{IP: ipStr, TTL: ttlVal})
					}
				}
			}
		}
	}

	for _, existing := range currentList {
		if existing.IP == ip {
			return nil
		}
	}

	currentList = append(currentList, types.AAAARecord{IP: ip, TTL: TTL})
	return memStore.AddRecord(sanitizedZone, string(types.TypeAAAA), key, currentList)
}

func (AAAARecord) Lookup(host string) ([]dns.RR, bool) {
	zone, name, ok := internal.SplitName(host)
	if !ok {
		return nil, false
	}

	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return nil, false
	}
	if memStore == nil {
		return nil, false
	}

	_, _, val, ok := memStore.GetRecord(sanitizedZone, string(types.TypeAAAA), name)
	if !ok {
		return nil, false
	}

	var recs []types.AAAARecord
	switch v := val.(type) {
	case []types.AAAARecord:
		recs = v
	case []interface{}:
		for _, item := range v {
			if obj, ok := item.(map[string]interface{}); ok {
				if ipStr, ok := obj["ip"].(string); ok {
					ttl := uint32(3600)
					if t, ok := obj["ttl"].(float64); ok {
						ttl = uint32(t)
					}
					recs = append(recs, types.AAAARecord{IP: ipStr, TTL: ttl})
				}
			}
		}
	default:
		return nil, false
	}

	var results []dns.RR
	for _, rec := range recs {
		ip := net.ParseIP(rec.IP)
		if ip == nil || ip.To4() != nil {
			continue
		}
		results = append(results, &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   host,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    rec.TTL,
			},
			AAAA: ip,
		})
	}

	return results, len(results) > 0
}

func (AAAARecord) Delete(host string, value interface{}) error {
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
		return memStore.DeleteRecord(sanitizedZone, string(types.TypeAAAA), name)
	}

	targetIP, ok := value.(string)
	if !ok {
		return fmt.Errorf("AAAARecord Delete: expected string IP, got %T", value)
	}

	_, _, raw, found := memStore.GetRecord(sanitizedZone, string(types.TypeAAAA), name)
	if !found {
		return nil
	}

	var records []types.AAAARecord
	switch v := raw.(type) {
	case []types.AAAARecord:
		records = v
	case []interface{}:
		for _, item := range v {
			if obj, ok := item.(map[string]interface{}); ok {
				if ipStr, ok := obj["ip"].(string); ok {
					ttl := uint32(3600)
					if t, ok := obj["ttl"].(float64); ok {
						ttl = uint32(t)
					}
					records = append(records, types.AAAARecord{IP: ipStr, TTL: ttl})
				}
			}
		}
	}

	var filtered []types.AAAARecord
	for _, r := range records {
		if r.IP != targetIP {
			filtered = append(filtered, r)
		}
	}

	if len(filtered) == 0 {
		return memStore.DeleteRecord(sanitizedZone, string(types.TypeAAAA), name)
	}
	return memStore.AddRecord(sanitizedZone, string(types.TypeAAAA), name, filtered)
}

func (AAAARecord) Type() uint16 {
	return dns.TypeAAAA
}

func init() {
	Register(AAAARecord{})
}
