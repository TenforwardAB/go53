package rtypes

import (
	"errors"
	"fmt"
	"github.com/TenforwardAB/slog"
	"github.com/miekg/dns"
	"go53/internal"
	"go53/recshape"
	"go53/security"
	"go53/types"
	"strings"
	"time"
)

type DNSKEYRecord struct{}

func (DNSKEYRecord) Add(zone, name string, value interface{}, ttl *uint32) error {
	sz, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return fmt.Errorf("FQDN sanitize check failed: %w", err)
	}

	sn, err := internal.SanitizeFQDN(name)
	slog.Crazy("[dnskey.go:Add] FQDN name to Sanitize", name)
	if err != nil {
		return fmt.Errorf("FQDN sanitize check failed for name: %w", err)
	}

	key := sn
	if sz == sn {
		key = "@"
	}

	m, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("DNSKEYRecord expects value to be a JSON object, got %T", value)
	}

	rec, err := dnskeyRecordFromMap(m, ttl)
	if err != nil {
		return err
	}

	if memStore == nil {
		return errors.New("memory store not initialized")
	}

	_, _, existing, found := memStore.GetRecord(sz, string(types.TypeDNSKEY), key)

	var current []types.DNSKEYRecord
	if found {
		current, _ = dnskeyRecordsFromRaw(existing)
	}

	for _, r := range current {
		if r.PublicKey == rec.PublicKey && r.Algorithm == rec.Algorithm && r.Flags == rec.Flags {
			return nil // duplicate
		}
	}

	current = append(current[:len(current):len(current)], rec)
	return memStore.AddRecord(sz, string(types.TypeDNSKEY), key, current)
}

func (DNSKEYRecord) Lookup(host string) ([]dns.RR, bool) {
	zone, name, ok := internal.SplitName(host)
	if !ok {
		return nil, false
	}

	sz, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return nil, false
	}

	if memStore == nil {
		return nil, false
	}

	var records []types.DNSKEYRecord
	if _, _, val, ok := memStore.GetRecord(sz, string(types.TypeDNSKEY), name); ok {
		records, _ = dnskeyRecordsFromRaw(val)
	}

	if name == "@" {
		if keys, err := security.LoadPublishedKeysForZone(sz, time.Now().Unix()); err == nil {
			for _, key := range keys {
				records = append(records, types.DNSKEYRecord{
					Flags:     security.DNSKEYFlags(key),
					Protocol:  3,
					Algorithm: security.AlgorithmNumberFromName(key.Algorithm),
					PublicKey: key.PublicKey,
					TTL:       3600,
				})
			}
		}
	}

	var out []dns.RR
	seen := make(map[string]bool)
	for _, rec := range records {
		key := fmt.Sprintf("%d/%d/%s", rec.Flags, rec.Algorithm, rec.PublicKey)
		if seen[key] {
			continue
		}
		seen[key] = true
		rr := &dns.DNSKEY{
			Hdr: dns.RR_Header{
				Name:   host,
				Rrtype: dns.TypeDNSKEY,
				Class:  dns.ClassINET,
				Ttl:    rec.TTL,
			},
			Flags:     rec.Flags,
			Protocol:  rec.Protocol,
			Algorithm: rec.Algorithm,
			PublicKey: rec.PublicKey,
		}
		out = append(out, rr)
	}

	return out, len(out) > 0
}

func (DNSKEYRecord) Delete(host string, value interface{}) error {
	zone, name, ok := internal.SplitName(host)
	if !ok {
		return errors.New("invalid host format")
	}

	sz, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN sanitize check failed")
	}

	if memStore == nil {
		return errors.New("memory store not initialized")
	}

	if value == nil {
		return memStore.DeleteRecord(sz, string(types.TypeDNSKEY), name)
	}

	obj, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("DNSKEYRecord Delete expects a JSON object, got %T", value)
	}

	target, ok := recshape.DNSKEYRecord(obj)
	if !ok {
		return errors.New("DNSKEYRecord Delete: invalid DNSKEY structure")
	}

	_, _, existing, found := memStore.GetRecord(sz, string(types.TypeDNSKEY), name)
	if !found {
		return nil
	}

	stored, ok := dnskeyRecordsFromRaw(existing)
	if !ok {
		// Unknown shape: refuse rather than fall through to deleting the key.
		return fmt.Errorf("DNSKEYRecord Delete: invalid data format: %T", existing)
	}
	var remaining []types.DNSKEYRecord
	for _, r := range stored {
		if r.PublicKey != target.PublicKey || r.Algorithm != target.Algorithm || r.Flags != target.Flags {
			remaining = append(remaining, r)
		}
	}

	if len(remaining) == 0 {
		return memStore.DeleteRecord(sz, string(types.TypeDNSKEY), name)
	}
	return memStore.AddRecord(sz, string(types.TypeDNSKEY), name, remaining)
}

func (DNSKEYRecord) Type() uint16 {
	return dns.TypeDNSKEY
}

func init() {
	Register(DNSKEYRecord{})
}

// dnskeyRecordFromMap validates an API payload. Field parsing goes through
// recshape's getters so a payload accepts the same numeric kinds as a stored
// value; a present field of the wrong type or out of range is an error.
func dnskeyRecordFromMap(m map[string]interface{}, ttl *uint32) (types.DNSKEYRecord, error) {
	row := recshape.Row(m)
	rec := types.DNSKEYRecord{
		TTL:      3600,
		Protocol: 3,
	}
	if ttl != nil {
		rec.TTL = *ttl
	}

	flags, ok := row.Uint16("flags")
	if !ok {
		if _, present := m["flags"]; !present {
			return rec, errors.New("DNSKEYRecord: missing 'flags'")
		}
		return rec, fmt.Errorf("DNSKEYRecord: invalid 'flags' type %T", m["flags"])
	}
	rec.Flags = flags

	if _, present := m["protocol"]; present {
		if p, ok := row.Uint8("protocol"); ok {
			rec.Protocol = p
		}
	}

	algorithm, ok := row.Uint8("algorithm")
	if !ok {
		if _, present := m["algorithm"]; !present {
			return rec, errors.New("DNSKEYRecord: missing 'algorithm'")
		}
		return rec, fmt.Errorf("DNSKEYRecord: invalid 'algorithm' type %T", m["algorithm"])
	}
	rec.Algorithm = algorithm

	pk, ok := row.String("public_key")
	if !ok || strings.TrimSpace(pk) == "" {
		return rec, errors.New("DNSKEYRecord: missing or invalid 'public_key'")
	}
	rec.PublicKey = pk

	if t, ok := row.Uint32("ttl"); ok {
		rec.TTL = t
	}
	return rec, nil
}

// dnskeyRecordsFromRaw decodes a stored DNSKEY value. CDNSKEY-typed values
// are accepted too: the two types share a wire format and cdnskey.go reads
// through this helper. ok=false means the shape is unknown.
func dnskeyRecordsFromRaw(raw any) ([]types.DNSKEYRecord, bool) {
	if recs, ok := recshape.Decode(raw, recshape.DNSKEYRecord); ok {
		return recs, true
	}
	cd, ok := recshape.Decode(raw, recshape.CDNSKEYRecord)
	if !ok {
		return nil, false
	}
	out := make([]types.DNSKEYRecord, 0, len(cd))
	for _, rec := range cd {
		out = append(out, types.DNSKEYRecord(rec))
	}
	return out, true
}

func dedupeDNSKEYLike(rrs []dns.RR) []dns.RR {
	seen := make(map[string]bool)
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		var key string
		switch v := rr.(type) {
		case *dns.DNSKEY:
			key = fmt.Sprintf("%s/%d/%d/%s", strings.ToLower(v.Hdr.Name), v.Flags, v.Algorithm, v.PublicKey)
		case *dns.CDNSKEY:
			key = fmt.Sprintf("%s/%d/%d/%s", strings.ToLower(v.Hdr.Name), v.Flags, v.Algorithm, v.PublicKey)
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
