package rtypes

import (
	"errors"
	"fmt"
	"github.com/TenforwardAB/slog"
	"github.com/miekg/dns"
	"go53/config"
	"go53/internal"
	"go53/types"
	"strings"
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
	_, _, raw, found := memStore.GetRecord(sanitizedZone, string(types.TypeSOA), "@")
	if found {
		var ok bool
		existing, ok = soaRecordFromRaw(raw)
		if !ok {
			return fmt.Errorf("unexpected SOA record format: %T", raw)
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

	if v, ok := soaString(cfg, "ns"); ok {
		rec.Ns = dns.Fqdn(v)
	}
	if v, ok := soaString(cfg, "mbox"); ok {
		rec.Mbox = dns.Fqdn(v)
	}
	if v, ok := soaUint32(cfg, "refresh"); ok {
		rec.Refresh = v
	}
	if v, ok := soaUint32(cfg, "retry"); ok {
		rec.Retry = v
	}
	if v, ok := soaUint32(cfg, "expire"); ok {
		rec.Expire = v
	}
	if v, ok := soaUint32(cfg, "minimum"); ok {
		rec.Minimum = v
	}
	if ttl != nil {
		rec.TTL = *ttl
	} else if v, ok := soaUint32(cfg, "ttl"); ok {
		rec.TTL = v
	}

	slog.Crazy("[soa.go:Add] SOA record from cfg: ", rec)

	if config.AppConfig.GetLive().Mode == "secondary" {
		if v, ok := soaUint32(cfg, "serial"); ok {
			rec.Serial = v
		}
	} else {
		rec.Serial = internal.NextSerial(existing.Serial)
	}

	slog.Crazy("[soa.go:Add] Actually Adding SOA record: ", rec)
	return memStore.AddRecord(sanitizedZone, string(types.TypeSOA), "@", rec)
}

func (SOARecord) Lookup(host string) ([]dns.RR, bool) {
	zone, name, ok := internal.SplitName(host)
	if !ok {
		return nil, false
	}
	if name != "@" {
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

	rec, ok := soaRecordFromRaw(val)
	if !ok {
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

func soaRecordFromRaw(raw interface{}) (types.SOARecord, bool) {
	switch v := raw.(type) {
	case types.SOARecord:
		return v, true
	case map[string]interface{}:
		rec := types.SOARecord{}
		if ns, ok := soaString(v, "ns"); ok {
			rec.Ns = dns.Fqdn(ns)
		}
		if mbox, ok := soaString(v, "mbox"); ok {
			rec.Mbox = dns.Fqdn(mbox)
		}
		if serial, ok := soaUint32(v, "serial"); ok {
			rec.Serial = serial
		}
		if refresh, ok := soaUint32(v, "refresh"); ok {
			rec.Refresh = refresh
		}
		if retry, ok := soaUint32(v, "retry"); ok {
			rec.Retry = retry
		}
		if expire, ok := soaUint32(v, "expire"); ok {
			rec.Expire = expire
		}
		if minimum, ok := soaUint32(v, "minimum"); ok {
			rec.Minimum = minimum
		}
		if ttl, ok := soaUint32(v, "ttl"); ok {
			rec.TTL = ttl
		}
		return rec, rec.Ns != "" && rec.Mbox != ""
	default:
		return types.SOARecord{}, false
	}
}

func soaString(cfg map[string]interface{}, key string) (string, bool) {
	for _, candidate := range soaKeyCandidates(key) {
		if value, ok := cfg[candidate].(string); ok && value != "" {
			return value, true
		}
	}
	return "", false
}

func soaUint32(cfg map[string]interface{}, key string) (uint32, bool) {
	var raw interface{}
	var ok bool
	for _, candidate := range soaKeyCandidates(key) {
		raw, ok = cfg[candidate]
		if ok {
			break
		}
	}
	if !ok {
		return 0, false
	}
	switch v := raw.(type) {
	case float64:
		return uint32(v), true
	case float32:
		return uint32(v), true
	case int:
		return uint32(v), true
	case int64:
		return uint32(v), true
	case int32:
		return uint32(v), true
	case uint:
		return uint32(v), true
	case uint64:
		return uint32(v), true
	case uint32:
		return v, true
	default:
		return 0, false
	}
}

func soaKeyCandidates(key string) []string {
	if key == "" {
		return []string{key}
	}
	return []string{key, strings.ToUpper(key[:1]) + key[1:]}
}

func init() {
	Register(SOARecord{})
}
