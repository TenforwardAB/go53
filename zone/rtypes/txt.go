package rtypes

import (
	"errors"
	"fmt"
	"go53/internal"
	"go53/recshape"
	"go53/types"

	"github.com/miekg/dns"
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

	key := normalizeRecordKey(sanitizedZone, name)

	_, _, val, found := memStore.GetRecord(sanitizedZone, string(types.TypeTXT), key)

	var currentList []types.TXTRecord
	if found {
		currentList, _ = recshape.Decode(val, recshape.TXTRecord)
	}

	for _, existing := range currentList {
		if existing.Text == text {
			return nil
		}
	}

	currentList = append(currentList[:len(currentList):len(currentList)], types.TXTRecord{Text: text, TTL: TTL, Chunks: internal.ChunkTXT(text)})
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

	recs, ok := recshape.Decode(val, recshape.TXTRecord)
	if !ok {
		return nil, false
	}

	var results []dns.RR
	for _, rec := range recs {
		chunks := rec.Chunks
		if len(chunks) == 0 {
			chunks = internal.ChunkTXT(rec.Text)
		}
		results = append(results, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   host,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    rec.TTL,
			},
			Txt: chunks,
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

	records, ok := recshape.Decode(raw, recshape.TXTRecord)
	if !ok {
		// Unknown shape: refuse rather than fall through to deleting the key.
		return fmt.Errorf("TXTRecord Delete: invalid data format: %T", raw)
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
