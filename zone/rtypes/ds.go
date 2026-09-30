package rtypes

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"go53/internal"
	"go53/recshape"
	"go53/types"
)

type DSRecord struct{}

func (DSRecord) Add(zone, name string, value interface{}, ttl *uint32) error {
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN sanitize check failed")
	}
	if memStore == nil {
		return errors.New("memory store not initialized")
	}

	m, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("DSRecord expects value to be a JSON object, got %T", value)
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
		return fmt.Errorf("DSRecord expects field 'digest' as non-empty string")
	}

	ttlVal := uint32(3600)
	if ttl != nil {
		ttlVal = *ttl
	}
	if t, ok := m["ttl"].(float64); ok {
		ttlVal = uint32(t)
	}

	key := normalizeRecordKey(sanitizedZone, name)

	var current []types.DSRecord
	_, _, existing, found := memStore.GetRecord(sanitizedZone, string(types.TypeDS), key)
	if found {
		current, _ = dsRecordsFromRaw(existing)
	}

	rec := types.DSRecord{
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
	return memStore.AddRecord(sanitizedZone, string(types.TypeDS), key, current)
}

func (DSRecord) Lookup(host string) ([]dns.RR, bool) {
	zone, name, ok := internal.SplitName(host)
	if !ok {
		return nil, false
	}
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil || memStore == nil {
		return nil, false
	}

	_, _, raw, found := memStore.GetRecord(sanitizedZone, string(types.TypeDS), name)
	if !found {
		return nil, false
	}

	records, ok := dsRecordsFromRaw(raw)
	if !ok || len(records) == 0 {
		return nil, false
	}

	out := make([]dns.RR, 0, len(records))
	for _, rec := range records {
		out = append(out, &dns.DS{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(host),
				Rrtype: dns.TypeDS,
				Class:  dns.ClassINET,
				Ttl:    rec.TTL,
			},
			KeyTag:     rec.KeyTag,
			Algorithm:  rec.Algorithm,
			DigestType: rec.DigestType,
			Digest:     strings.ToUpper(rec.Digest),
		})
	}
	return out, true
}

func (DSRecord) Delete(host string, value interface{}) error {
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
		return memStore.DeleteRecord(sanitizedZone, string(types.TypeDS), name)
	}
	return errors.New("DSRecord Delete only supports deleting the full RRSet")
}

func (DSRecord) Type() uint16 {
	return dns.TypeDS
}

func init() {
	Register(DSRecord{})
}

// dsRecordsFromRaw decodes a stored DS value; CDS-typed values are accepted
// too (shared wire format). ok=false means the shape is unknown.
func dsRecordsFromRaw(raw any) ([]types.DSRecord, bool) {
	if recs, ok := recshape.Decode(raw, recshape.DSRecord); ok {
		return recs, true
	}
	cds, ok := recshape.Decode(raw, recshape.CDSRecord)
	if !ok {
		return nil, false
	}
	out := make([]types.DSRecord, 0, len(cds))
	for _, rec := range cds {
		out = append(out, types.DSRecord(rec))
	}
	return out, true
}

func uint16Field(m map[string]interface{}, key string) (uint16, error) {
	v, ok := recshape.Row(m).Uint16(key)
	if !ok {
		return 0, fmt.Errorf("DSRecord expects numeric field '%s'", key)
	}
	return v, nil
}

func uint8Field(m map[string]interface{}, key string) (uint8, error) {
	v, ok := recshape.Row(m).Uint8(key)
	if !ok {
		return 0, fmt.Errorf("DSRecord expects numeric field '%s'", key)
	}
	return v, nil
}

func dedupeDSLike(rrs []dns.RR) []dns.RR {
	seen := make(map[string]bool)
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		var key string
		switch v := rr.(type) {
		case *dns.DS:
			key = fmt.Sprintf("%s/%d/%d/%d/%s", strings.ToLower(v.Hdr.Name), v.KeyTag, v.Algorithm, v.DigestType, strings.ToUpper(v.Digest))
		case *dns.CDS:
			key = fmt.Sprintf("%s/%d/%d/%d/%s", strings.ToLower(v.Hdr.Name), v.KeyTag, v.Algorithm, v.DigestType, strings.ToUpper(v.Digest))
		default:
			key = rr.String()
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, rr)
	}
	return out
}
