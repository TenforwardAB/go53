package rtypes

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"go53/internal"
	"go53/types"
	"net"
)

type ARecord struct{}

func (ARecord) Add(zone, name string, value interface{}, ttl *uint32) error {
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN Sanitize check failed")
	}
	m, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("ARecord expects value to be a JSON object, got %T", value)
	}

	rawIP, ok := m["ip"]
	if !ok {
		return fmt.Errorf("ARecord expects field 'ip'")
	}

	ip, ok := rawIP.(string)
	if !ok {
		return fmt.Errorf("ARecord: field 'ip' must be a string, got %T", rawIP)
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("ARecord: invalid IP address %q", ip)
	}

	TTL := uint32(3600)
	if ttl != nil {
		TTL = *ttl
	}
	if memStore == nil {
		return errors.New("memory store not initialized")
	}
	rec := types.ARecord{
		IP:  ip,
		TTL: TTL,
	}
	return memStore.AddRecord(sanitizedZone, string(types.TypeA), name, rec)
}

func (ARecord) Lookup(host string) (dns.RR, bool) {
	zone, name, ok := internal.SplitName(host)
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return nil, false
	}
	if memStore == nil {
		return nil, false
	}
	_, _, val, ok := memStore.GetRecord(sanitizedZone, string(types.TypeA), name)
	if !ok {
		return nil, false
	}

	var rec types.ARecord
	switch v := val.(type) {
	case types.ARecord:
		rec = v
	case map[string]interface{}:
		rec = types.ARecord{
			IP:  v["ip"].(string),
			TTL: uint32(v["ttl"].(float64)),
		}
	default:
		return nil, false
	}

	return &dns.A{
		Hdr: dns.RR_Header{
			Name:   host,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    rec.TTL,
		},
		A: net.ParseIP(rec.IP),
	}, true
}

func (ARecord) Delete(host string) error {
	zone, name, ok := internal.SplitName(host)
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
	return memStore.DeleteRecord(sanitizedZone, string(types.TypeA), name)
}

func (ARecord) Type() uint16 {
	return dns.TypeA
}

func init() {
	Register(ARecord{})
}
