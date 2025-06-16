package zone

import (
	"fmt"
	"github.com/miekg/dns"
	"go53/zone/rtypes"
)

func AddRecord(rrtype uint16, zone, name string, value interface{}, ttl *uint32) error {
	rr, ok := rtypes.Get(rrtype)
	if !ok {
		return fmt.Errorf("unknown rrtype: %d", rrtype)
	}
	return rr.Add(zone, name, value, ttl)
}

func LookupRecord(rrtype uint16, name string) ([]dns.RR, bool) {
	rr, ok := rtypes.Get(rrtype)
	if !ok {
		return nil, false
	}
	return rr.Lookup(name)
}

func DeleteRecord(rrtype uint16, name string, value interface{}) error {
	rr, ok := rtypes.Get(rrtype)
	if !ok {
		return fmt.Errorf("unknown rrtype: %d", rrtype)
	}
	return rr.Delete(name, value)
}
