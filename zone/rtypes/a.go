package rtypes

import (
	"errors"
	"fmt"
	"net"

	"github.com/miekg/dns"
	"go53/internal"
	"go53/recshape"
	"go53/types"
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

	key := normalizeRecordKey(sanitizedZone, name)

	_, _, val, found := memStore.GetRecord(sanitizedZone, string(types.TypeA), key)

	var currentList []types.ARecord
	if found {
		currentList, _ = recshape.Decode(val, recshape.ARecord)
	}

	for _, existing := range currentList {
		if existing.IP == ip {
			return nil
		}
	}

	// Full slice expression: never append into the slice the store still holds.
	currentList = append(currentList[:len(currentList):len(currentList)], types.ARecord{IP: ip, TTL: TTL})

	var listToStore []map[string]interface{}
	for _, r := range currentList {
		listToStore = append(listToStore, map[string]interface{}{
			"ip":  r.IP,
			"ttl": float64(r.TTL),
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

	recs, ok := recshape.Decode(val, recshape.ARecord)
	if !ok {
		return nil, false
	}

	results := make([]dns.RR, 0, len(recs))
	for _, rec := range recs {
		ip := net.ParseIP(rec.IP).To4()
		if ip == nil {
			continue
		}
		results = append(results, &dns.A{
			Hdr: dns.RR_Header{
				Name:   host,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    rec.TTL,
			},
			A: ip,
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

	records, ok := recshape.Decode(raw, recshape.ARecord)
	if !ok {
		// Unknown shape: refuse rather than fall through to deleting the key.
		return fmt.Errorf("Delete: invalid data format for A record: %T", raw)
	}

	var filtered []map[string]interface{}
	for _, rec := range records {
		if rec.IP != targetIP {
			filtered = append(filtered, map[string]interface{}{
				"ip":  rec.IP,
				"ttl": float64(rec.TTL),
			})
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
