package rtypes

import (
	"errors"
	"fmt"

	"github.com/miekg/dns"
	"go53/internal"
	"go53/recshape"
	"go53/types"
)

type PTR struct{}

func (PTR) Add(zone, name string, value interface{}, ttl *uint32) error {
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN Sanitize check failed")
	}

	m, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("PTRRecord expects value to be a JSON object, got %T", value)
	}

	rawPtr, ok := m["ptr"]
	if !ok {
		return fmt.Errorf("PTRRecord expects field 'ptr'")
	}

	ptr, ok := rawPtr.(string)
	if !ok {
		return fmt.Errorf("PTRRecord: field 'ptr' must be a string, got %T", rawPtr)
	}

	TTL := uint32(3600)
	if ttl != nil {
		TTL = *ttl
	}

	if memStore == nil {
		return errors.New("memory store not initialized")
	}

	key := normalizeRecordKey(sanitizedZone, name)

	_, _, val, found := memStore.GetRecord(sanitizedZone, string(types.TypePTR), key)

	var currentList []types.PTRRecord
	if found {
		currentList, _ = recshape.Decode(val, recshape.PTRRecord)
	}

	for _, existing := range currentList {
		if existing.Ptr == ptr {
			return nil
		}
	}

	currentList = append(currentList[:len(currentList):len(currentList)], types.PTRRecord{Ptr: ptr, TTL: TTL})
	return memStore.AddRecord(sanitizedZone, string(types.TypePTR), key, currentList)
}

func (PTR) Lookup(host string) ([]dns.RR, bool) {
	zone, name, ok := internal.SplitName(host)
	if !ok {
		return nil, false
	}

	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil || memStore == nil {
		return nil, false
	}

	_, _, val, ok := memStore.GetRecord(sanitizedZone, string(types.TypePTR), name)
	if !ok {
		return nil, false
	}

	recs, ok := recshape.Decode(val, recshape.PTRRecord)
	if !ok {
		return nil, false
	}

	var results []dns.RR
	for _, rec := range recs {
		results = append(results, &dns.PTR{
			Hdr: dns.RR_Header{
				Name:   host,
				Rrtype: dns.TypePTR,
				Class:  dns.ClassINET,
				Ttl:    rec.TTL,
			},
			Ptr: rec.Ptr,
		})
	}

	return results, len(results) > 0
}

func (PTR) Delete(host string, value interface{}) error {
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
		return memStore.DeleteRecord(sanitizedZone, string(types.TypePTR), name)
	}

	ptrToRemove, ok := value.(string)
	if !ok {
		return fmt.Errorf("PTRRecord Delete: expected string ptr, got %T", value)
	}

	_, _, raw, found := memStore.GetRecord(sanitizedZone, string(types.TypePTR), name)
	if !found {
		return nil
	}

	records, ok := recshape.Decode(raw, recshape.PTRRecord)
	if !ok {
		// Unknown shape: refuse rather than fall through to deleting the key.
		return fmt.Errorf("PTRRecord Delete: invalid data format: %T", raw)
	}

	var filtered []types.PTRRecord
	for _, r := range records {
		if r.Ptr != ptrToRemove {
			filtered = append(filtered, r)
		}
	}

	if len(filtered) == 0 {
		return memStore.DeleteRecord(sanitizedZone, string(types.TypePTR), name)
	}
	return memStore.AddRecord(sanitizedZone, string(types.TypePTR), name, filtered)
}

func (PTR) Type() uint16 {
	return dns.TypePTR
}

func init() {
	Register(PTR{})
}
