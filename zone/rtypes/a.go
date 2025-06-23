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
				switch obj := item.(type) {
				case map[string]interface{}:
					ipStr, _ := obj["ip"].(string)
					ttlVal := uint32(3600)
					if t, ok := obj["ttl"].(float64); ok {
						ttlVal = uint32(t)
					}
					currentList = append(currentList, types.ARecord{IP: ipStr, TTL: ttlVal})
				case types.ARecord: // ← detta behövs om det finns gamla records kvar som struct
					currentList = append(currentList, obj)
				}
			}
		case []map[string]interface{}: // ← NYTT CASE
			for _, obj := range v {
				ipStr, _ := obj["ip"].(string)
				ttlVal := uint32(3600)
				if t, ok := obj["ttl"].(float64); ok {
					ttlVal = uint32(t)
				}
				currentList = append(currentList, types.ARecord{IP: ipStr, TTL: ttlVal})
			}
		}
	}

	for _, existing := range currentList {
		if existing.IP == ip {
			return nil
		}
	}

	currentList = append(currentList, types.ARecord{IP: ip, TTL: TTL})

	var listToStore []map[string]interface{}
	for _, r := range currentList {
		listToStore = append(listToStore, map[string]interface{}{
			"ip":  r.IP,
			"ttl": r.TTL,
		})
	}

	return memStore.AddRecord(sanitizedZone, string(types.TypeA), key, listToStore)
}

func (ARecord) Lookup(host string) ([]dns.RR, bool) {
	zone, name, ok := internal.SplitName(host)
	if !ok {
		return nil, false
	}

	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil || memStore == nil {
		return nil, false
	}

	_, _, val, ok := memStore.GetRecord(sanitizedZone, string(types.TypeA), name)
	if !ok {
		return nil, false
	}

	var results []dns.RR

	switch v := val.(type) {
	case []map[string]interface{}:
		for _, item := range v {
			ipStr, _ := item["ip"].(string)
			ip := net.ParseIP(ipStr).To4()
			if ip == nil {
				continue
			}
			ttl := uint32(3600)
			if t, ok := item["ttl"].(float64); ok {
				ttl = uint32(t)
			}
			results = append(results, &dns.A{
				Hdr: dns.RR_Header{
					Name:   host,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    ttl,
				},
				A: ip,
			})
		}

	default:
		return nil, false
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
		return memStore.DeleteRecord(sanitizedZone, string(types.TypeA), name)
	}

	targetIP, ok := value.(string)
	if !ok {
		return fmt.Errorf("ARecord Delete: expected string IP, got %T", value)
	}

	_, _, raw, found := memStore.GetRecord(sanitizedZone, string(types.TypeA), name)
	if !found {
		return nil
	}

	records, ok := raw.([]map[string]interface{})
	if !ok {
		return fmt.Errorf("Delete: invalid data format for A record")
	}

	var filtered []map[string]interface{}
	for _, rec := range records {
		ipStr, _ := rec["ip"].(string)
		if ipStr != targetIP {
			filtered = append(filtered, rec)
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
