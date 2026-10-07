package rtypes

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"go53/internal"
	"go53/recshape"
	"go53/security"
	"go53/types"
)

type CDSRecord struct{}

func (CDSRecord) Add(zone, name string, value interface{}, ttl *uint32) error {
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN sanitize check failed")
	}
	if memStore == nil {
		return errors.New("memory store not initialized")
	}

	m, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("CDSRecord expects value to be a JSON object, got %T", value)
	}
	keyTag, err := uint16Field(m, "key_tag")
	if err != nil {
		return err
	}
	algorithm, err := uint8Field(m, "algorithm")
	if err != nil {
		return err
	}
	digestType, err := uint8Field(m, "digest_type")
	if err != nil {
		return err
	}
	digest, ok := m["digest"].(string)
	if !ok || strings.TrimSpace(digest) == "" {
		return fmt.Errorf("CDSRecord expects field 'digest' as non-empty string")
	}

	ttlVal := uint32(3600)
	if ttl != nil {
		ttlVal = *ttl
	}
	if t, ok := m["ttl"].(float64); ok {
		ttlVal = uint32(t)
	}

	key := normalizeRecordKey(sanitizedZone, name)

	var current []types.CDSRecord
	_, _, existing, found := memStore.GetRecord(sanitizedZone, string(types.TypeCDS), key)
	if found {
		current, _ = cdsRecordsFromRaw(existing)
	}

	rec := types.CDSRecord{
		KeyTag:     keyTag,
		Algorithm:  algorithm,
		DigestType: digestType,
		Digest:     strings.ToUpper(strings.TrimSpace(digest)),
		TTL:        ttlVal,
	}
	for _, existing := range current {
		if existing.KeyTag == rec.KeyTag && existing.Algorithm == rec.Algorithm && existing.DigestType == rec.DigestType && strings.EqualFold(existing.Digest, rec.Digest) {
			return nil
		}
	}

	current = append(current[:len(current):len(current)], rec)
	return memStore.AddRecord(sanitizedZone, string(types.TypeCDS), key, current)
}

func (CDSRecord) Lookup(host string) ([]dns.RR, bool) {
	zone, name, ok := internal.SplitName(host)
	if !ok {
		return nil, false
	}
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil || memStore == nil {
		return nil, false
	}

	var out []dns.RR
	if _, _, raw, found := memStore.GetRecord(sanitizedZone, string(types.TypeCDS), name); found {
		stored, _ := cdsRecordsFromRaw(raw)
		for _, rec := range stored {
			out = append(out, &dns.CDS{DS: dns.DS{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(host),
					Rrtype: dns.TypeCDS,
					Class:  dns.ClassINET,
					Ttl:    rec.TTL,
				},
				KeyTag:     rec.KeyTag,
				Algorithm:  rec.Algorithm,
				DigestType: rec.DigestType,
				Digest:     strings.ToUpper(rec.Digest),
			}})
		}
	}

	if name == "@" {
		if cdsList, err := security.GetCDS(sanitizedZone); err == nil {
			for _, cds := range cdsList {
				out = append(out, cds)
			}
		}
	}

	return dedupeDSLike(out), len(out) > 0
}

func (CDSRecord) Delete(host string, value interface{}) error {
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
		return memStore.DeleteRecord(sanitizedZone, string(types.TypeCDS), name)
	}
	return errors.New("CDSRecord Delete only supports deleting the full RRSet")
}

func (CDSRecord) Type() uint16 {
	return dns.TypeCDS
}

func init() {
	Register(CDSRecord{})
}

// cdsRecordsFromRaw decodes a stored CDS value; DS-typed values are accepted
// too (shared wire format). ok=false means the shape is unknown.
func cdsRecordsFromRaw(raw any) ([]types.CDSRecord, bool) {
	if recs, ok := recshape.Decode(raw, recshape.CDSRecord); ok {
		return recs, true
	}
	ds, ok := recshape.Decode(raw, recshape.DSRecord)
	if !ok {
		return nil, false
	}
	out := make([]types.CDSRecord, 0, len(ds))
	for _, rec := range ds {
		out = append(out, types.CDSRecord(rec))
	}
	return out, true
}
