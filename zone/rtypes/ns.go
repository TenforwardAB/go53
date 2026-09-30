package rtypes

import (
	"errors"
	"fmt"
	"go53/internal"
	"go53/recshape"
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

	key := normalizeRecordKey(sanitizedZone, name)

	var current []types.NSRecord
	_, _, existing, found := memStore.GetRecord(sanitizedZone, string(types.TypeNS), key)
	if found {
		current, _ = recshape.Decode(existing, recshape.NSRecord)
	}

	for _, item := range current {
		if item.NS == sanitizedNS {
			return nil
		}
	}

	current = append(current[:len(current):len(current)], types.NSRecord{
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

	records, ok := recshape.Decode(val, recshape.NSRecord)
	if !ok {
		return nil, false
	}
	if len(records) == 0 {
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

	records, ok := recshape.Decode(raw, recshape.NSRecord)
	if !ok {
		// Unknown shape: refuse rather than fall through to deleting the key.
		return fmt.Errorf("NSRecord Delete: invalid data format: %T", raw)
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
