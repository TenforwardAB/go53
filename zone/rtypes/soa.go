package rtypes

import (
	"errors"
	"fmt"
	"github.com/TenforwardAB/slog"
	"github.com/miekg/dns"
	"go53/config"
	"go53/internal"
	"go53/types"
)

type SOARecord struct{}

func (SOARecord) Add(zone, name string, value interface{}, ttl *uint32) error {
	slog.Crazy("[soa.go:Add] Adding SOA record for zone: ", zone, "with value: ", value)
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
		switch v := raw.(type) {
		case types.SOARecord:
			existing = v
		case map[string]interface{}:
			existing = types.SOARecord{
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
			return fmt.Errorf("unexpected SOA record format: %T", v)
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
	slog.Crazy("[soa.go:Add] Cfg is: ", cfg)
	for k, val := range cfg {
		slog.Crazy("[soa.go:Add] cfg key: ", k, " ,and value is: ", val)
	}
	if !ok {
		return fmt.Errorf("SOA Add expects a JSON object")
	}

	if v, ok := cfg["ns"].(string); ok {

		rec.Ns = dns.Fqdn(v)
	}
	if v, ok := cfg["mbox"].(string); ok {
		rec.Mbox = dns.Fqdn(v)
	}
	if v, ok := cfg["refresh"].(float64); ok {
		rec.Refresh = uint32(v)
	}
	if v, ok := cfg["retry"].(float64); ok {
		rec.Retry = uint32(v)
	}
	if v, ok := cfg["expire"].(float64); ok {
		rec.Expire = uint32(v)
	}
	if v, ok := cfg["minimum"].(float64); ok {
		rec.Minimum = uint32(v)
	}
	if ttl != nil {
		rec.TTL = *ttl
	}

	slog.Crazy("[soa.go:Add] SOA record from cfg: ", rec)

	if config.AppConfig.GetLive().Mode == "secondary" {
		if v, ok := cfg["serial"].(float64); ok {
			rec.Serial = uint32(v)
		}
	} else {
		rec.Serial = internal.NextSerial(existing.Serial)
	}

	slog.Crazy("[soa.go:Add] Actually Adding SOA record: ", rec)
	return memStore.AddRecord(sanitizedZone, string(types.TypeSOA), "@", rec)
}

func (SOARecord) Lookup(host string) ([]dns.RR, bool) {
	zone, _, ok := internal.SplitName(host)
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
	_, _, val, ok := memStore.GetRecord(sanitizedZone, string(types.TypeSOA), "@")
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

	rr := &dns.SOA{
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
	}

	return []dns.RR{rr}, true
}

func (SOARecord) Delete(host string, value interface{}) error {
	zone, _, ok := internal.SplitName(host)
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

	// SOA only supports one record, delete unconditionally
	return memStore.DeleteRecord(sanitizedZone, string(types.TypeSOA), "@")
}

func (SOARecord) Type() uint16 {
	return dns.TypeSOA
}

func init() {
	Register(SOARecord{})
}
