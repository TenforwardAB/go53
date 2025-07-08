package rtypes

import (
	"errors"
	"fmt"
	"github.com/TenforwardAB/slog"
	"github.com/miekg/dns"
	"go53/internal"
	"go53/types"
)

type MXRecord struct{}

func (MXRecord) Add(zone, name string, value interface{}, ttl *uint32) error {
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN sanitize check failed")
	}

	m, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("MXRecord expects value to be a JSON object, got %T", value)
	}

	rawHost, ok := m["host"]
	if !ok {
		return fmt.Errorf("MXRecord expects field 'host'")
	}
	host, ok := rawHost.(string)
	if !ok {
		return fmt.Errorf("MXRecord: field 'host' must be a string, got %T", rawHost)
	}
	sanitizedHost, err := internal.SanitizeFQDN(host)
	if err != nil {
		return fmt.Errorf("MXRecord: invalid host FQDN %q", host)
	}

	rawPrio, ok := m["priority"]
	if !ok {
		return fmt.Errorf("MXRecord expects field 'priority'")
	}
	prioFloat, ok := rawPrio.(float64)
	if !ok {
		return fmt.Errorf("MXRecord: field 'priority' must be a number, got %T", rawPrio)
	}
	priority := uint16(prioFloat)

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

	_, _, val, found := memStore.GetRecord(sanitizedZone, string(types.TypeMX), key)

	var currentList []types.MXRecord
	if found {
		switch v := val.(type) {
		case []types.MXRecord:
			currentList = v
		case []interface{}:
			for _, item := range v {
				if obj, ok := item.(map[string]interface{}); ok {
					h, _ := obj["host"].(string)
					p, _ := obj["priority"].(float64)
					t := uint32(3600)
					if tt, ok := obj["ttl"].(float64); ok {
						t = uint32(tt)
					}
					currentList = append(currentList, types.MXRecord{
						Host:     h,
						Priority: uint16(p),
						TTL:      t,
					})
				}
			}
		}
	}

	for _, rec := range currentList {
		if rec.Host == sanitizedHost && rec.Priority == priority {
			return nil
		}
	}

	currentList = append(currentList, types.MXRecord{
		Host:     sanitizedHost,
		Priority: priority,
		TTL:      TTL,
	})

	return memStore.AddRecord(sanitizedZone, string(types.TypeMX), key, currentList)
}

func (MXRecord) Lookup(host string) ([]dns.RR, bool) {
	slog.Crazy("[mx.go:Lookup] host: %s", host)
	zone, name, ok := internal.SplitName(host)
	slog.Crazy("[mx.go:Lookup] Name: %s", name)
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

	_, _, val, ok := memStore.GetRecord(sanitizedZone, string(types.TypeMX), name)
	if !ok {
		return nil, false
	}

	var recs []types.MXRecord
	switch v := val.(type) {
	case []types.MXRecord:
		recs = v
	case []interface{}:
		for _, item := range v {
			if obj, ok := item.(map[string]interface{}); ok {
				h, _ := obj["host"].(string)
				p, _ := obj["priority"].(float64)
				t := uint32(3600)
				if tt, ok := obj["ttl"].(float64); ok {
					t = uint32(tt)
				}
				recs = append(recs, types.MXRecord{
					Host:     h,
					Priority: uint16(p),
					TTL:      t,
				})
			}
		}
	default:
		return nil, false
	}

	var results []dns.RR
	for _, rec := range recs {
		results = append(results, &dns.MX{
			Hdr: dns.RR_Header{
				Name:   host,
				Rrtype: dns.TypeMX,
				Class:  dns.ClassINET,
				Ttl:    rec.TTL,
			},
			Preference: rec.Priority,
			Mx:         rec.Host,
		})
	}

	return results, len(results) > 0
}

func (MXRecord) Delete(host string, value interface{}) error {
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
		return memStore.DeleteRecord(sanitizedZone, string(types.TypeMX), name)
	}

	obj, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("MXRecord Delete expects value to be a JSON object, got %T", value)
	}

	rawHost, ok := obj["host"].(string)
	if !ok {
		return fmt.Errorf("MXRecord Delete expects 'host' string")
	}
	sanitizedHost, err := internal.SanitizeFQDN(rawHost)
	if err != nil {
		return fmt.Errorf("MXRecord Delete: invalid host %q", rawHost)
	}

	priority := uint16(0)
	if p, ok := obj["priority"].(float64); ok {
		priority = uint16(p)
	}

	_, _, raw, found := memStore.GetRecord(sanitizedZone, string(types.TypeMX), name)
	if !found {
		return nil
	}

	var records []types.MXRecord
	switch v := raw.(type) {
	case []types.MXRecord:
		records = v
	case []interface{}:
		for _, item := range v {
			if o, ok := item.(map[string]interface{}); ok {
				h, _ := o["host"].(string)
				p, _ := o["priority"].(float64)
				t := uint32(3600)
				if tt, ok := o["ttl"].(float64); ok {
					t = uint32(tt)
				}
				records = append(records, types.MXRecord{
					Host:     h,
					Priority: uint16(p),
					TTL:      t,
				})
			}
		}
	}

	var filtered []types.MXRecord
	for _, r := range records {
		if r.Host != sanitizedHost || r.Priority != priority {
			filtered = append(filtered, r)
		}
	}

	if len(filtered) == 0 {
		return memStore.DeleteRecord(sanitizedZone, string(types.TypeMX), name)
	}
	return memStore.AddRecord(sanitizedZone, string(types.TypeMX), name, filtered)
}

func (MXRecord) Type() uint16 {
	return dns.TypeMX
}

func init() {
	Register(MXRecord{})
}
