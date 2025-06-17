package rtypes

import (
	"errors"
	"fmt"
	"go53/internal"
	"go53/types"

	"github.com/miekg/dns"
)

type NSRecord struct{}

func (NSRecord) Add(zone, name string, value interface{}, ttl *uint32) error {
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN sanitize check failed")
	}

	m, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("NSRecord expects value to be a JSON object, got %T", value)
	}

	rawNS, ok := m["ns"]
	if !ok {
		return fmt.Errorf("NSRecord expects field 'ns'")
	}
	nsHost, ok := rawNS.(string)
	if !ok {
		return fmt.Errorf("NSRecord: field 'ns' must be a string, got %T", rawNS)
	}
	sanitizedNS, err := internal.SanitizeFQDN(nsHost)
	if err != nil {
		return fmt.Errorf("NSRecord: invalid NS FQDN %q", nsHost)
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

	var current []types.NSRecord
	_, _, existing, found := memStore.GetRecord(sanitizedZone, string(types.TypeNS), key)
	if found {
		if list, ok := existing.([]types.NSRecord); ok {
			current = list
		}
	}

	for _, item := range current {
		if item.NS == sanitizedNS {
			return nil
		}
	}

	current = append(current, types.NSRecord{
		NS:  sanitizedNS,
		TTL: TTL,
	})

	return memStore.AddRecord(sanitizedZone, string(types.TypeNS), key, current)
}

func (NSRecord) Lookup(host string) ([]dns.RR, bool) {
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

	key := name
	if key == "" {
		key = "@"
	}

	_, _, val, ok := memStore.GetRecord(sanitizedZone, string(types.TypeNS), key)
	if !ok {
		return nil, false
	}

	records, ok := val.([]types.NSRecord)
	if !ok || len(records) == 0 {
		return nil, false
	}

	var result []dns.RR
	for _, rec := range records {
		result = append(result, &dns.NS{
			Hdr: dns.RR_Header{
				Name:   host,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    rec.TTL,
			},
			Ns: rec.NS,
		})
	}
	return result, true
}

func (NSRecord) Delete(host string, value interface{}) error {
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

	key := name
	if key == "" {
		key = "@"
	}

	if value == nil {
		// Ta bort hela NS-listan
		return memStore.DeleteRecord(sanitizedZone, string(types.TypeNS), key)
	}

	nsToRemove, ok := value.(string)
	if !ok {
		return fmt.Errorf("NSRecord Delete: expected string NS, got %T", value)
	}
	sanitizedNS, err := internal.SanitizeFQDN(nsToRemove)
	if err != nil {
		return fmt.Errorf("NSRecord Delete: invalid FQDN %q", nsToRemove)
	}

	_, _, raw, found := memStore.GetRecord(sanitizedZone, string(types.TypeNS), key)
	if !found {
		return nil
	}

	var records []types.NSRecord
	switch v := raw.(type) {
	case []types.NSRecord:
		records = v
	case []interface{}:
		for _, item := range v {
			if obj, ok := item.(map[string]interface{}); ok {
				if nsStr, ok := obj["ns"].(string); ok {
					ttl := uint32(3600)
					if t, ok := obj["ttl"].(float64); ok {
						ttl = uint32(t)
					}
					records = append(records, types.NSRecord{NS: nsStr, TTL: ttl})
				}
			}
		}
	}

	var filtered []types.NSRecord
	for _, r := range records {
		if r.NS != sanitizedNS {
			filtered = append(filtered, r)
		}
	}

	if len(filtered) == 0 {
		return memStore.DeleteRecord(sanitizedZone, string(types.TypeNS), key)
	}
	return memStore.AddRecord(sanitizedZone, string(types.TypeNS), key, filtered)
}

func (NSRecord) Type() uint16 {
	return dns.TypeNS
}

func init() {
	Register(NSRecord{})
}
