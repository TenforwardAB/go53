package rtypes

import (
	"encoding/json"
	"fmt"
	"github.com/TenforwardAB/slog"
	"go53/internal"
	"go53/internal/errors"
	"go53/types"
	"strings"

	"github.com/miekg/dns"
)

type RRSIGRecord struct{}

func (RRSIGRecord) Add(zone, name string, value interface{}, ttl *uint32) error {
	valMap, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("RRSIGRecord.Add: value is not a map[string]interface{}")
	}

	// Normalize/map to struct
	var rec types.RRSIGRecord
	b, err := json.Marshal(valMap)
	if err != nil {
		return fmt.Errorf("RRSIGRecord.Add: marshal: %w", err)
	}
	if err := json.Unmarshal(b, &rec); err != nil {
		return fmt.Errorf("RRSIGRecord.Add: unmarshal: %w", err)
	}
	if ttl != nil {
		rec.TTL = *ttl
	}

	recMap := map[string]interface{}{
		"type_covered": rec.TypeCovered,
		"algorithm":    rec.Algorithm,
		"labels":       rec.Labels,
		"original_ttl": rec.OrigTTL,
		"expiration":   rec.Expiration,
		"inception":    rec.Inception,
		"key_tag":      rec.KeyTag,
		"signer_name":  rec.SignerName,
		"signature":    rec.Signature,
		"ttl":          rec.TTL,
	}

	// Now: fetch existing map for the covered type ("DNSKEY", etc)
	_, _, current, ok := memStore.GetRecord(zone, "RRSIG", rec.TypeCovered)
	var nameMap map[string][]map[string]interface{}
	if ok {
		// Defensive: attempt to type-assert and use if map[string][]map[string]interface{}
		switch v := current.(type) {
		case map[string][]map[string]interface{}:
			nameMap = v
		case map[string]interface{}:
			// Convert if possible
			nameMap = map[string][]map[string]interface{}{}
			for k, vv := range v {
				switch slice := vv.(type) {
				case []map[string]interface{}:
					nameMap[k] = slice
				case []interface{}:
					for _, item := range slice {
						if mm, ok := item.(map[string]interface{}); ok {
							nameMap[k] = append(nameMap[k], mm)
						}
					}
				}
			}
		}
	}
	if nameMap == nil {
		nameMap = map[string][]map[string]interface{}{}
	}

	// Deduplication (optional)
	for _, existing := range nameMap[name] {
		if existing["signature"] == rec.Signature && existing["key_tag"] == rec.KeyTag && existing["expiration"] == rec.Expiration {
			return nil // Already present, skip
		}
	}

	nameMap[name] = append(nameMap[name], recMap)

	return memStore.AddRecord(zone, "RRSIG", rec.TypeCovered, nameMap)
}

func (RRSIGRecord) Lookup(host string) ([]dns.RR, bool) {
	parts := strings.SplitN(host, "___", 2)
	if len(parts) != 2 {
		return nil, false
	}

	name := parts[0]
	rtypeStr := parts[1]
	slog.Crazy("[handleRequest] rtype is: %s", rtypeStr)

	zone, shortName, ok := internal.SplitName(name)
	//shortName, _ = internal.SanitizeFQDN(shortName)
	if !ok {
		return nil, false
	}
	slog.Crazy("[handleRequest] zone is: %s", zone)
	slog.Crazy("[handleRequest] short name is: %s", shortName)

	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil || memStore == nil {
		return nil, false
	}

	_, _, val, ok := memStore.GetRecord(sanitizedZone, "RRSIG", rtypeStr)
	slog.Crazy("[handleRequest] val is: %#v", val)
	if !ok {
		return nil, false
	}

	var rrsigList []interface{}

	switch vv := val.(type) {
	case map[string]interface{}:
		// e.g. "@": []interface{}{(*types.RRSIGRecord), ...}
		if raw, found := vv[shortName]; found {
			switch lst := raw.(type) {
			case []interface{}:
				rrsigList = lst
			case []*types.RRSIGRecord:
				for _, rec := range lst {
					rrsigList = append(rrsigList, rec)
				}
			}
		}
	case map[string][]interface{}:
		if list, found := vv[shortName]; found {
			rrsigList = list
		}
	case map[string][]map[string]interface{}:
		if list, found := vv[shortName]; found {
			for _, m := range list {
				rrsigList = append(rrsigList, m)
			}
		}
	default:
		slog.Crazy("[handleRequest] val has unexpected type: %T", val)
		return nil, false
	}

	if len(rrsigList) == 0 {
		slog.Crazy("[handleRequest] no RRSIGs for %q", shortName)
		return nil, false
	}

	var results []dns.RR
	for _, item := range rrsigList {
		var sig types.RRSIGRecord
		switch v := item.(type) {
		case *types.RRSIGRecord:
			sig = *v
		case types.RRSIGRecord:
			sig = v
		case map[string]interface{}:
			b, err := json.Marshal(v)
			if err != nil {
				slog.Crazy("[handleRequest] marshal fail: %v", err)
				continue
			}
			if err := json.Unmarshal(b, &sig); err != nil {
				slog.Crazy("[handleRequest] unmarshal fail: %v", err)
				continue
			}
		default:
			slog.Crazy("[handleRequest] unknown type: %T", item)
			continue
		}

		covered, ok := dns.StringToType[sig.TypeCovered]
		if !ok {
			slog.Crazy("[handleRequest] unknown TypeCovered: %q", sig.TypeCovered)
			continue
		}
		fqdn, _ := internal.SanitizeFQDN(name)

		s := &dns.RRSIG{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(fqdn),
				Rrtype: dns.TypeRRSIG,
				Class:  dns.ClassINET,
				Ttl:    sig.TTL,
			},
			TypeCovered: uint16(covered),
			Algorithm:   sig.Algorithm,
			Labels:      sig.Labels,
			OrigTtl:     sig.OrigTTL,
			Expiration:  sig.Expiration,
			Inception:   sig.Inception,
			KeyTag:      sig.KeyTag,
			SignerName:  sig.SignerName,
			Signature:   sig.Signature,
		}
		results = append(results, s)
	}

	slog.Crazy("[handleRequest] final RRSIG count: %d", len(results))
	return results, len(results) > 0

}

func (RRSIGRecord) Delete(host string, value interface{}) error {
	return errors.NotImplemented("RRSIGRecord.Delete")
}

func (RRSIGRecord) Type() uint16 {
	return dns.TypeRRSIG
}

func init() {
	Register(RRSIGRecord{})
}
