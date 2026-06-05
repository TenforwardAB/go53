package rtypes

import (
	"errors"
	"fmt"

	"github.com/TenforwardAB/slog"
	"github.com/miekg/dns"
	"go53/internal"
	"go53/security"
	"go53/types"
)

type CDNSKEYRecord struct{}

func (CDNSKEYRecord) Add(zone, name string, value interface{}, ttl *uint32) error {
	sz, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return fmt.Errorf("FQDN sanitize check failed: %w", err)
	}
	sn, err := internal.SanitizeFQDN(name)
	slog.Crazy("[cdnskey.go:Add] FQDN name to Sanitize", name)
	if err != nil {
		return fmt.Errorf("FQDN sanitize check failed for name: %w", err)
	}

	key := sn
	if sz == sn {
		key = "@"
	}

	m, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("CDNSKEYRecord expects value to be a JSON object, got %T", value)
	}
	rec, err := dnskeyRecordFromMap(m, ttl)
	if err != nil {
		return err
	}

	if memStore == nil {
		return errors.New("memory store not initialized")
	}

	var current []types.CDNSKEYRecord
	_, _, existing, found := memStore.GetRecord(sz, string(types.TypeCDNSKEY), key)
	if found {
		current = cdnskeyRecordsFromRaw(existing)
	}

	for _, r := range current {
		if r.PublicKey == rec.PublicKey && r.Algorithm == rec.Algorithm && r.Flags == rec.Flags {
			return nil
		}
	}

	current = append(current, types.CDNSKEYRecord(rec))
	return memStore.AddRecord(sz, string(types.TypeCDNSKEY), key, current)
}

func (CDNSKEYRecord) Lookup(host string) ([]dns.RR, bool) {
	zone, name, ok := internal.SplitName(host)
	if !ok {
		return nil, false
	}
	sz, err := internal.SanitizeFQDN(zone)
	if err != nil || memStore == nil {
		return nil, false
	}

	var records []types.CDNSKEYRecord
	if _, _, val, ok := memStore.GetRecord(sz, string(types.TypeCDNSKEY), name); ok {
		records = append(records, cdnskeyRecordsFromRaw(val)...)
	}

	var out []dns.RR
	if name == "@" {
		if cdnskeys, err := security.GetCDNSKEY(sz); err == nil {
			for _, cdnskey := range cdnskeys {
				out = append(out, cdnskey)
			}
		}
	}

	for _, rec := range records {
		out = append(out, &dns.CDNSKEY{DNSKEY: dns.DNSKEY{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(host),
				Rrtype: dns.TypeCDNSKEY,
				Class:  dns.ClassINET,
				Ttl:    rec.TTL,
			},
			Flags:     rec.Flags,
			Protocol:  rec.Protocol,
			Algorithm: rec.Algorithm,
			PublicKey: rec.PublicKey,
		}})
	}

	return dedupeDNSKEYLike(out), len(out) > 0
}

func (CDNSKEYRecord) Delete(host string, value interface{}) error {
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
		return memStore.DeleteRecord(sz, string(types.TypeCDNSKEY), name)
	}

	obj, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("CDNSKEYRecord Delete expects a JSON object, got %T", value)
	}
	target, ok := internal.ParseToDNSKEYRecord(obj)
	if !ok {
		return errors.New("CDNSKEYRecord Delete: invalid CDNSKEY structure")
	}

	_, _, existing, found := memStore.GetRecord(sz, string(types.TypeCDNSKEY), name)
	if !found {
		return nil
	}

	var remaining []types.CDNSKEYRecord
	for _, rec := range cdnskeyRecordsFromRaw(existing) {
		if rec.PublicKey != target.PublicKey || rec.Algorithm != target.Algorithm || rec.Flags != target.Flags {
			remaining = append(remaining, rec)
		}
	}

	if len(remaining) == 0 {
		return memStore.DeleteRecord(sz, string(types.TypeCDNSKEY), name)
	}
	return memStore.AddRecord(sz, string(types.TypeCDNSKEY), name, remaining)
}

func (CDNSKEYRecord) Type() uint16 {
	return dns.TypeCDNSKEY
}

func init() {
	Register(CDNSKEYRecord{})
}

func cdnskeyRecordsFromRaw(raw any) []types.CDNSKEYRecord {
	dnskeyRecords := dnskeyRecordsFromRaw(raw)
	out := make([]types.CDNSKEYRecord, 0, len(dnskeyRecords))
	for _, rec := range dnskeyRecords {
		out = append(out, types.CDNSKEYRecord(rec))
	}
	return out
}
