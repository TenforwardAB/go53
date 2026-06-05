package rtypes

import (
	"errors"
	"fmt"

	"github.com/miekg/dns"
	"go53/internal"
	"go53/types"
)

type DNAMERecord struct{}

func (DNAMERecord) Add(zone, name string, value interface{}, ttl *uint32) error {
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN sanitize check failed")
	}
	if memStore == nil {
		return errors.New("memory store not initialized")
	}

	m, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("DNAMERecord expects value to be a JSON object, got %T", value)
	}
	rawTarget, ok := m["target"]
	if !ok {
		return fmt.Errorf("DNAMERecord expects field 'target'")
	}
	target, ok := rawTarget.(string)
	if !ok {
		return fmt.Errorf("DNAMERecord: field 'target' must be a string, got %T", rawTarget)
	}
	sanitizedTarget, err := internal.SanitizeFQDN(target)
	if err != nil {
		return fmt.Errorf("DNAMERecord: invalid target FQDN %q", target)
	}

	ttlVal := uint32(3600)
	if ttl != nil {
		ttlVal = *ttl
	}

	key := name
	if key == "" {
		key = "@"
	}
	if _, _, _, found := memStore.GetRecord(sanitizedZone, string(types.TypeCNAME), key); found {
		return errors.New("DNAME cannot coexist with CNAME at the same owner")
	}

	rec := types.DNAMERecord{
		Target: sanitizedTarget,
		TTL:    ttlVal,
	}
	return memStore.AddRecord(sanitizedZone, string(types.TypeDNAME), key, rec)
}

func (DNAMERecord) Lookup(host string) ([]dns.RR, bool) {
	zone, name, ok := internal.SplitName(host)
	if !ok {
		return nil, false
	}
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil || memStore == nil {
		return nil, false
	}

	_, _, val, ok := memStore.GetRecord(sanitizedZone, string(types.TypeDNAME), name)
	if !ok {
		return nil, false
	}

	var rec types.DNAMERecord
	switch v := val.(type) {
	case types.DNAMERecord:
		rec = v
	case map[string]interface{}:
		if tgt, ok := v["target"].(string); ok {
			rec.Target = tgt
		}
		if t, ok := v["ttl"].(float64); ok {
			rec.TTL = uint32(t)
		}
	default:
		return nil, false
	}
	if rec.Target == "" {
		return nil, false
	}

	return []dns.RR{&dns.DNAME{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(host),
			Rrtype: dns.TypeDNAME,
			Class:  dns.ClassINET,
			Ttl:    rec.TTL,
		},
		Target: dns.Fqdn(rec.Target),
	}}, true
}

func (DNAMERecord) Delete(host string, value interface{}) error {
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
	return memStore.DeleteRecord(sanitizedZone, string(types.TypeDNAME), name)
}

func (DNAMERecord) Type() uint16 {
	return dns.TypeDNAME
}

func init() {
	Register(DNAMERecord{})
}
