package rtypes

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"go53/internal"
	"go53/recshape"
	"go53/types"
)

type SRV struct{}

func (SRV) Add(zone, name string, value interface{}, ttl *uint32) error {
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN Sanitize check failed")
	}

	m, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("SRVRecord expects value to be a JSON object, got %T", value)
	}

	var r types.SRVRecord

	priority, ok := m["priority"].(float64)
	if !ok {
		return fmt.Errorf("SRVRecord expects field 'priority' as number")
	}
	r.Priority = uint16(priority)

	weight, ok := m["weight"].(float64)
	if !ok {
		return fmt.Errorf("SRVRecord expects field 'weight' as number")
	}
	r.Weight = uint16(weight)

	port, ok := m["port"].(float64)
	if !ok {
		return fmt.Errorf("SRVRecord expects field 'port' as number")
	}
	r.Port = uint16(port)

	target, ok := m["target"].(string)
	if !ok {
		return fmt.Errorf("SRVRecord expects field 'target' as string")
	}
	r.Target = target

	r.TTL = 3600
	if ttl != nil {
		r.TTL = *ttl
	}

	if memStore == nil {
		return errors.New("memory store not initialized")
	}

	key := normalizeRecordKey(sanitizedZone, name)

	_, _, val, found := memStore.GetRecord(sanitizedZone, string(types.TypeSRV), key)

	var current []types.SRVRecord
	if found {
		current, _ = recshape.Decode(val, recshape.SRVRecord)
	}

	for _, existing := range current {
		if existing.Port == r.Port && existing.Target == r.Target {
			return nil
		}
	}

	current = append(current[:len(current):len(current)], r)
	return memStore.AddRecord(sanitizedZone, string(types.TypeSRV), key, current)
}

func (SRV) Lookup(host string) ([]dns.RR, bool) {
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

	_, _, val, ok := memStore.GetRecord(sanitizedZone, string(types.TypeSRV), name)
	if !ok {
		return nil, false
	}

	recs, ok := recshape.Decode(val, recshape.SRVRecord)
	if !ok {
		return nil, false
	}

	var results []dns.RR
	for _, rec := range recs {
		results = append(results, &dns.SRV{
			Hdr: dns.RR_Header{
				Name:   host,
				Rrtype: dns.TypeSRV,
				Class:  dns.ClassINET,
				Ttl:    rec.TTL,
			},
			Priority: rec.Priority,
			Weight:   rec.Weight,
			Port:     rec.Port,
			Target:   dns.Fqdn(rec.Target),
		})
	}

	return results, len(results) > 0
}

func (SRV) Delete(host string, value interface{}) error {
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
		return memStore.DeleteRecord(sanitizedZone, string(types.TypeSRV), name)
	}

	m, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("SRVRecord Delete: expected JSON object, got %T", value)
	}

	target, _ := m["target"].(string)
	port, _ := m["port"].(float64)

	_, _, raw, found := memStore.GetRecord(sanitizedZone, string(types.TypeSRV), name)
	if !found {
		return nil
	}

	recs, ok := recshape.Decode(raw, recshape.SRVRecord)
	if !ok {
		// Unknown shape: refuse rather than fall through to deleting the key.
		return fmt.Errorf("SRVRecord Delete: invalid data format: %T", raw)
	}

	var filtered []types.SRVRecord
	for _, r := range recs {
		if r.Target != target || r.Port != uint16(port) {
			filtered = append(filtered, r)
		}
	}

	if len(filtered) == 0 {
		return memStore.DeleteRecord(sanitizedZone, string(types.TypeSRV), name)
	}
	return memStore.AddRecord(sanitizedZone, string(types.TypeSRV), name, filtered)
}

func (SRV) Type() uint16 {
	return dns.TypeSRV
}

func init() {
	Register(SRV{})
}
