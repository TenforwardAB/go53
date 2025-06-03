package types

import (
	"errors"
	"github.com/miekg/dns"
	"go53/internal"
	"go53/types"
)

func AddMX(zone, name string, records []types.MXRecord) error {
	if memStore == nil {
		return errors.New("memory store not initialized")
	}
	return memStore.AddRecord(zone, string(types.TypeMX), name, records)
}

// keep of we need it?
func AddSingleMX(zone, name string, preference uint16, mx string, ttl uint32) error {
	return AddMX(zone, name, []types.MXRecord{
		{Name: name, Priority: preference, Server: mx, TTL: ttl},
	})
}

func LookupMX(host string) ([]*dns.MX, bool) {
	zone, name, ok := internal.SplitName(host)
	if memStore == nil {
		return nil, false
	}
	_, _, val, ok := memStore.GetRecord(zone, string(types.TypeMX), name)
	if !ok {
		return nil, false
	}

	var mxlist []types.MXRecord
	switch v := val.(type) {
	case []types.MXRecord:
		mxlist = v
	case []interface{}:
		// unmarshal case
		for _, rec := range v {
			if mxmap, ok := rec.(map[string]interface{}); ok {
				mxlist = append(mxlist, types.MXRecord{
					Name:     mxmap["name"].(string),
					Priority: uint16(mxmap["priority"].(float64)),
					Server:   mxmap["server"].(string),
					TTL:      uint32(mxmap["ttl"].(float64)),
				})
			}
		}
	default:
		return nil, false
	}

	result := make([]*dns.MX, 0, len(mxlist))
	for _, rec := range mxlist {
		result = append(result, &dns.MX{
			Hdr: dns.RR_Header{
				Name:   host,
				Rrtype: dns.TypeMX,
				Class:  dns.ClassINET,
				Ttl:    rec.TTL,
			},
			Preference: rec.Priority,
			Mx:         rec.Server,
		})
	}
	return result, true
}

func DeleteMX(host string) error {
	zone, name, ok := internal.SplitName(host)
	if !ok {
		return errors.New("invalid host format")
	}
	if memStore == nil {
		return errors.New("memory store not initialized")
	}
	return memStore.DeleteRecord(zone, string(types.TypeMX), name)
}
