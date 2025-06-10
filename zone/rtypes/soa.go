package rtypes

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"go53/internal"
	"go53/types"
	"log"
)

type SOARecord struct{}

func (SOARecord) Add(zone, name string, value interface{}, ttl *uint32) error {
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN Sanitize check failed")
	}
	if memStore == nil {
		return errors.New("memory store not initialized")
	}

	var existing types.SOARecord
	_, _, raw, found := memStore.GetRecord(sanitizedZone, string(types.TypeSOA), sanitizedZone)
	if found {
		rawMap, ok := raw.(map[string]interface{})
		if !ok {
			return fmt.Errorf("expected SOARecord map but got %T", raw)
		}

		jsonBytes, err := json.Marshal(rawMap)
		if err != nil {
			return fmt.Errorf("failed to marshal SOA record: %w", err)
		}

		if err := json.Unmarshal(jsonBytes, &existing); err != nil {
			return fmt.Errorf("failed to unmarshal SOA record: %w", err)
		}
	}

	rec := existing
	if !found {
		rec = types.SOARecord{
			Ns:      "ns.default.",
			Mbox:    "hostmaster.default.",
			Serial:  internal.NextSerial(0),
			Refresh: 3600,
			Retry:   900,
			Expire:  1209600,
			Minimum: 300,
			TTL:     3600,
		}
	}

	cfg, ok := value.(map[string]interface{})
	log.Printf("cfg in soa is %v\n", cfg)
	if !ok {
		return fmt.Errorf("SOA Add expects a JSON object")
	}

	if v, ok := cfg["Ns"].(string); ok {
		rec.Ns = v
	}
	if v, ok := cfg["Mbox"].(string); ok {
		rec.Mbox = v
	}
	if v, ok := cfg["Refresh"].(float64); ok {
		rec.Refresh = uint32(v)
	}
	if v, ok := cfg["Retry"].(float64); ok {
		rec.Retry = uint32(v)
	}
	if v, ok := cfg["Expire"].(float64); ok {
		rec.Expire = uint32(v)
	}
	if v, ok := cfg["Minimum"].(float64); ok {
		rec.Minimum = uint32(v)
	}
	if ttl != nil {
		rec.TTL = *ttl
	}

	rec.Serial = internal.NextSerial(existing.Serial)

	return memStore.AddRecord(sanitizedZone, string(types.TypeSOA), sanitizedZone, rec)
}

func (SOARecord) Lookup(host string) (dns.RR, bool) {
	zone, _, ok := internal.SplitName(host)
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return nil, false
	}
	if memStore == nil {
		return nil, false
	}
	_, _, val, ok := memStore.GetRecord(sanitizedZone, string(types.TypeSOA), sanitizedZone)
	log.Printf("soaRec zone in SOA.go: %v\n", sanitizedZone)
	if !ok {
		return nil, false
	}

	var rec types.SOARecord
	switch v := val.(type) {
	case types.SOARecord:
		rec = v
	case map[string]interface{}:
		rec = types.SOARecord{
			Ns:      v["ns"].(string),
			Mbox:    v["mbox"].(string),
			Serial:  uint32(v["serial"].(float64)),
			Refresh: uint32(v["refresh"].(float64)),
			Retry:   uint32(v["retry"].(float64)),
			Expire:  uint32(v["expire"].(float64)),
			Minimum: uint32(v["minimum"].(float64)),
			TTL:     uint32(v["ttl"].(float64)),
		}
	default:
		return nil, false
	}

	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   sanitizedZone,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    rec.TTL,
		},
		Ns:      rec.Ns,
		Mbox:    rec.Mbox,
		Serial:  rec.Serial,
		Refresh: rec.Refresh,
		Retry:   rec.Retry,
		Expire:  rec.Expire,
		Minttl:  rec.Minimum,
	}, true
}

func (SOARecord) Delete(host string) error {
	zone, _, ok := internal.SplitName(host)
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN Sanitize check failed")
	}
	if !ok {
		return errors.New("invalid host format")
	}
	if memStore == nil {
		return errors.New("memory store not initialized")
	}
	return memStore.DeleteRecord(sanitizedZone, string(types.TypeSOA), sanitizedZone)
}

func (SOARecord) Type() uint16 {
	return dns.TypeSOA
}

func init() {
	Register(SOARecord{})
}
