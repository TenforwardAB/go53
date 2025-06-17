package rtypes

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"go53/internal"
	"go53/types"
)

type TXTRecord struct{}

func (TXTRecord) Add(zone, name string, value interface{}, ttl *uint32) error {
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN Sanitize check failed")
	}

	m, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("TXTRecord expects value to be a JSON object, got %T", value)
	}

	rawText, ok := m["text"]
	if !ok {
		return fmt.Errorf("TXTRecord expects field 'text'")
	}

	text, ok := rawText.(string)
	if !ok {
		return fmt.Errorf("TXTRecord: field 'text' must be a string, got %T", rawText)
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

	_, _, val, found := memStore.GetRecord(sanitizedZone, string(types.TypeTXT), key)

	var currentList []types.TXTRecord
	if found {
		switch v := val.(type) {
		case []types.TXTRecord:
			currentList = v
		case []interface{}:
			for _, item := range v {
				if obj, ok := item.(map[string]interface{}); ok {
					if txtStr, ok := obj["text"].(string); ok {
						ttlVal := uint32(3600)
						if t, ok := obj["ttl"].(float64); ok {
							ttlVal = uint32(t)
						}
						currentList = append(currentList, types.TXTRecord{Text: txtStr, TTL: ttlVal})
					}
				}
			}
		}
	}

	for _, existing := range currentList {
		if existing.Text == text {
			return nil
		}
	}

	currentList = append(currentList, types.TXTRecord{Text: text, TTL: TTL})
	return memStore.AddRecord(sanitizedZone, string(types.TypeTXT), key, currentList)
}

func (TXTRecord) Lookup(host string) ([]dns.RR, bool) {
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

	_, _, val, ok := memStore.GetRecord(sanitizedZone, string(types.TypeTXT), name)
	if !ok {
		return nil, false
	}

	var recs []types.TXTRecord
	switch v := val.(type) {
	case []types.TXTRecord:
		recs = v
	case []interface{}:
		for _, item := range v {
			if obj, ok := item.(map[string]interface{}); ok {
				if txtStr, ok := obj["text"].(string); ok {
					ttl := uint32(3600)
					if t, ok := obj["ttl"].(float64); ok {
						ttl = uint32(t)
					}
					recs = append(recs, types.TXTRecord{Text: txtStr, TTL: ttl})
				}
			}
		}
	default:
		return nil, false
	}

	var results []dns.RR
	for _, rec := range recs {
		results = append(results, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   host,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    rec.TTL,
			},
			Txt: []string{rec.Text},
		})
	}

	return results, len(results) > 0
}

func (TXTRecord) Delete(host string, value interface{}) error {
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
		return memStore.DeleteRecord(sanitizedZone, string(types.TypeTXT), name)
	}

	textToRemove, ok := value.(string)
	if !ok {
		return fmt.Errorf("TXTRecord Delete: expected string text, got %T", value)
	}

	_, _, raw, found := memStore.GetRecord(sanitizedZone, string(types.TypeTXT), name)
	if !found {
		return nil
	}

	var records []types.TXTRecord
	switch v := raw.(type) {
	case []types.TXTRecord:
		records = v
	case []interface{}:
		for _, item := range v {
			if obj, ok := item.(map[string]interface{}); ok {
				if txtStr, ok := obj["text"].(string); ok {
					ttl := uint32(3600)
					if t, ok := obj["ttl"].(float64); ok {
						ttl = uint32(t)
					}
					records = append(records, types.TXTRecord{Text: txtStr, TTL: ttl})
				}
			}
		}
	}

	var filtered []types.TXTRecord
	for _, r := range records {
		if r.Text != textToRemove {
			filtered = append(filtered, r)
		}
	}

	if len(filtered) == 0 {
		return memStore.DeleteRecord(sanitizedZone, string(types.TypeTXT), name)
	}
	return memStore.AddRecord(sanitizedZone, string(types.TypeTXT), name, filtered)
}

func (TXTRecord) Type() uint16 {
	return dns.TypeTXT
}

func init() {
	Register(TXTRecord{})
}
