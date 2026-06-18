package rtypes

import (
	"errors"
	"fmt"

	"go53/internal"
	"go53/types"

	"github.com/TenforwardAB/slog"
	"github.com/miekg/dns"
)

type CAARecord struct{}

// caaFromAny normalizes a stored CAA value (typed slice or JSON-decoded
// freshly added records and records reloaded from disk behave identically.
func caaFromAny(val interface{}) []types.CAARecord {
	var recs []types.CAARecord
	switch v := val.(type) {
	case []types.CAARecord:
		recs = v
	case []interface{}:
		for _, item := range v {
			obj, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			flag, _ := obj["flag"].(float64)
			tag, _ := obj["tag"].(string)
			value, _ := obj["value"].(string)
			t := uint32(3600)
			if tt, ok := obj["ttl"].(float64); ok {
				t = uint32(tt)
			}
			recs = append(recs, types.CAARecord{
				Flag:  uint8(flag),
				Tag:   tag,
				Value: value,
				TTL:   t,
			})
		}
	}
	return recs
}

func (CAARecord) Add(zone, name string, value interface{}, ttl *uint32) error {
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN sanitize check failed")
	}

	m, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("CAARecord expects value to be a JSON object, got %T", value)
	}

	rawFlag, ok := m["flag"]
	if !ok {
		return fmt.Errorf("CAARecord expects field 'flag'")
	}
	flagFloat, ok := rawFlag.(float64)
	if !ok {
		return fmt.Errorf("CAARecord: field 'flag' must be a number, got %T", rawFlag)
	}
	if flagFloat < 0 || flagFloat > 255 {
		return fmt.Errorf("CAARecord: field 'flag' must be between 0 and 255")
	}
	flag := uint8(flagFloat)

	rawTag, ok := m["tag"]
	if !ok {
		return fmt.Errorf("CAARecord expects field 'tag'")
	}
	tag, ok := rawTag.(string)
	if !ok || tag == "" {
		return fmt.Errorf("CAARecord: field 'tag' must be a non-empty string")
	}

	rawValue, ok := m["value"]
	if !ok {
		return fmt.Errorf("CAARecord expects field 'value'")
	}
	val, ok := rawValue.(string)
	if !ok {
		return fmt.Errorf("CAARecord: field 'value' must be a string, got %T", rawValue)
	}

	TTL := uint32(3600)
	if ttl != nil {
		TTL = *ttl
	}

	if memStore == nil {
		return errors.New("memory store not initialized")
	}

	key := normalizeRecordKey(sanitizedZone, name)

	_, _, existing, found := memStore.GetRecord(sanitizedZone, string(types.TypeCAA), key)

	var currentList []types.CAARecord
	if found {
		currentList = caaFromAny(existing)
	}

	for _, rec := range currentList {
		if rec.Flag == flag && rec.Tag == tag && rec.Value == val {
			return nil
		}
	}

	currentList = append(currentList, types.CAARecord{
		Flag:  flag,
		Tag:   tag,
		Value: val,
		TTL:   TTL,
	})

	return memStore.AddRecord(sanitizedZone, string(types.TypeCAA), key, currentList)
}

func (CAARecord) Lookup(name string) ([]dns.RR, bool) {
	slog.Crazy("[caa.go:Lookup] name: %s", name)
	zone, label, ok := internal.SplitName(name)
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

	_, _, val, ok := memStore.GetRecord(sanitizedZone, string(types.TypeCAA), label)
	if !ok {
		return nil, false
	}

	recs := caaFromAny(val)

	var results []dns.RR
	for _, rec := range recs {
		results = append(results, &dns.CAA{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeCAA,
				Class:  dns.ClassINET,
				Ttl:    rec.TTL,
			},
			Flag:  rec.Flag,
			Tag:   rec.Tag,
			Value: rec.Value,
		})
	}

	return results, len(results) > 0
}

func (CAARecord) Delete(host string, value interface{}) error {
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
		return memStore.DeleteRecord(sanitizedZone, string(types.TypeCAA), name)
	}

	obj, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("CAARecord Delete expects value to be a JSON object, got %T", value)
	}

	flag := uint8(0)
	if f, ok := obj["flag"].(float64); ok {
		flag = uint8(f)
	}
	tag, _ := obj["tag"].(string)
	val, _ := obj["value"].(string)

	_, _, raw, found := memStore.GetRecord(sanitizedZone, string(types.TypeCAA), name)
	if !found {
		return nil
	}

	records := caaFromAny(raw)

	var filtered []types.CAARecord
	for _, r := range records {
		if r.Flag != flag || r.Tag != tag || r.Value != val {
			filtered = append(filtered, r)
		}
	}

	if len(filtered) == 0 {
		return memStore.DeleteRecord(sanitizedZone, string(types.TypeCAA), name)
	}
	return memStore.AddRecord(sanitizedZone, string(types.TypeCAA), name, filtered)
}

func (CAARecord) Type() uint16 {
	return dns.TypeCAA
}

func init() {
	Register(CAARecord{})
}
