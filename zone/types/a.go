package types

import (
	"errors"
	"github.com/miekg/dns"
	"go53/internal"
	"go53/types"
	"net"
)

func AddA(zone, name, ip string, ttl *uint32) error {
	TTL := uint32(3600)
	if ttl != nil {
		TTL = *ttl
	}
	if memStore == nil {
		return errors.New("memory store not initialized")
	}
	rec := types.ARecord{
		Name: name,
		IP:   ip,
		TTL:  TTL,
	}
	return memStore.AddRecord(zone, string(types.TypeA), name, rec)
}

func LookupA(host string) (*dns.A, bool) {
	zone, name, ok := internal.SplitName(host)
	if memStore == nil {
		return nil, false
	}
	_, _, val, ok := memStore.GetRecord(zone, string(types.TypeA), name)
	if !ok {
		return nil, false
	}

	var rec types.ARecord
	switch v := val.(type) {
	case types.ARecord:
		rec = v
	case map[string]interface{}:
		rec = types.ARecord{
			Name: v["name"].(string),
			IP:   v["ip"].(string),
			TTL:  uint32(v["ttl"].(float64)),
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

func DeleteA(host string) error {
	zone, name, ok := internal.SplitName(host)
	if !ok {
		return errors.New("invalid host format")
	}

	if memStore == nil {
		return errors.New("memory store not initialized")
	}
	return memStore.DeleteRecord(zone, string(types.TypeA), name)
}
