package rtypes

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"go53/internal"
	"go53/types"
	"net"
)

type ARecord struct{}

func (ARecord) Add(zone, name string, value interface{}, ttl *uint32) error {
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN Sanitize check failed")
	}

	m, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("ARecord expects value to be a JSON object, got %T", value)
	}

	rawIP, ok := m["ip"]
	if !ok {
		return fmt.Errorf("ARecord expects field 'ip'")
	}

	ip, ok := rawIP.(string)
	if !ok {
		return fmt.Errorf("ARecord: field 'ip' must be a string, got %T", rawIP)
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("ARecord: invalid IP address %q", ip)
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

	_, _, val, found := memStore.GetRecord(sanitizedZone, string(types.TypeA), key)

	var currentList []types.ARecord
	if found {
		switch v := val.(type) {
		case []types.ARecord:
			currentList = v
		case []interface{}:
			for _, item := range v {
				if obj, ok := item.(map[string]interface{}); ok {
					if ipStr, ok := obj["ip"].(string); ok {
						ttlVal := uint32(3600)
						if t, ok := obj["ttl"].(float64); ok {
							ttlVal = uint32(t)
						}
						currentList = append(currentList, types.ARecord{IP: ipStr, TTL: ttlVal})
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

	currentList = append(currentList, types.ARecord{IP: ip, TTL: TTL})
	return memStore.AddRecord(sanitizedZone, string(types.TypeA), key, currentList)
}

func (ARecord) Lookup(host string) ([]dns.RR, bool) {
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

	_, _, val, ok := memStore.GetRecord(sanitizedZone, string(types.TypeA), name)
	if !ok {
		return nil, false
	}

	var recs []types.ARecord
	switch v := val.(type) {
	case []types.ARecord:
		recs = v
	case []interface{}:
		for _, item := range v {
			if obj, ok := item.(map[string]interface{}); ok {
				if ipStr, ok := obj["ip"].(string); ok {
					ttl := uint32(3600)
					if t, ok := obj["ttl"].(float64); ok {
						ttl = uint32(t)
					}
					recs = append(recs, types.ARecord{IP: ipStr, TTL: ttl})
				}
			}
		}
	default:
		return nil, false
	}

	var results []dns.RR
	for _, rec := range recs {
		ip := net.ParseIP(rec.IP)
		if ip == nil {
			continue
		}
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		results = append(results, &dns.A{
			Hdr: dns.RR_Header{
				Name:   host,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    rec.TTL,
			},
			A: v4,
		})
	}

	return results, len(results) > 0
}

func (ARecord) Delete(host string, value interface{}) error {
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

	if value == nil {
		// Delete all
		return memStore.DeleteRecord(sanitizedZone, string(types.TypeA), name)
	}

	targetIP, ok := value.(string)
	if !ok {
		return fmt.Errorf("ARecord Delete: expected string IP, got %T", value)
	}

	// Get existing
	_, _, raw, found := memStore.GetRecord(sanitizedZone, string(types.TypeA), name)
	if !found {
		return nil
	}

	var records []types.ARecord
	switch v := raw.(type) {
	case []types.ARecord:
		records = v
	case []interface{}:
		for _, item := range v {
			if obj, ok := item.(map[string]interface{}); ok {
				if ipStr, ok := obj["ip"].(string); ok {
					ttl := uint32(3600)
					if t, ok := obj["ttl"].(float64); ok {
						ttl = uint32(t)
					}
					records = append(records, types.ARecord{IP: ipStr, TTL: ttl})
				}
			}
		}
	}

	// Filter
	var filtered []types.ARecord
	for _, r := range records {
		if r.IP != targetIP {
			filtered = append(filtered, r)
		}
	}

	if len(filtered) == 0 {
		return memStore.DeleteRecord(sanitizedZone, string(types.TypeA), name)
	}
	return memStore.AddRecord(sanitizedZone, string(types.TypeA), name, filtered)
}

func (ARecord) Type() uint16 {
	return dns.TypeA
}

func init() {
	Register(ARecord{})
}
