package types

import (
	"errors"
	"github.com/miekg/dns"
	"go53/internal"
	"go53/types"
	"net"
)

func AddAAAA(zone, name, ip string, ttl *uint32) error {
	TTL := uint32(3600)
	if ttl != nil {
		TTL = *ttl
	}
	if memStore == nil {
		return errors.New("memory store not initialized")
	}
	rec := types.AAAARecord{
		Name: name,
		IP:   ip,
		TTL:  TTL,
	}
	return memStore.AddRecord(zone, string(types.TypeAAAA), name, rec)
}

func LookupAAAA(host string) (*dns.AAAA, bool) {
	zone, name, ok := internal.SplitName(host)
	if memStore == nil {
		return nil, false
	}
	_, _, val, ok := memStore.GetRecord(zone, string(types.TypeAAAA), name)
	if !ok {
		return nil, false
	}

	var rec types.AAAARecord
	switch v := val.(type) {
	case types.AAAARecord:
		rec = v
	case map[string]interface{}:
		rec = types.AAAARecord{
			Name: v["name"].(string),
			IP:   v["ip"].(string),
			TTL:  uint32(v["ttl"].(float64)),
		}
	default:
		return nil, false
	}

	return &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   host,
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    rec.TTL,
		},
		AAAA: net.ParseIP(rec.IP),
	}, true
}

func DeleteAAAA(host string) error {
	zone, name, ok := internal.SplitName(host)
	if !ok {
		return errors.New("invalid host format")
	}
	if memStore == nil {
		return errors.New("memory store not initialized")
	}
	return memStore.DeleteRecord(zone, string(types.TypeAAAA), name)
}
