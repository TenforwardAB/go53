package rtypes

import (
	"github.com/miekg/dns"
	"go53/internal"
	"go53/internal/errors"
)

type AXFRRecord struct{}

func (AXFRRecord) Add(zone, name string, value interface{}, ttl *uint32) error {
	return errors.NotImplemented("AXFRRecord.Add")
}

func (AXFRRecord) Delete(host string, value interface{}) error {
	return errors.NotImplemented("AXFRRecord.Delete")
}

func (AXFRRecord) Lookup(host string) ([]dns.RR, bool) {
	zone, _, ok := internal.SplitName(host)
	if !ok {
		return nil, false
	}

	recs, err := memStore.GetZone(zone)
	if err != nil || len(recs) == 0 {
		return nil, false
	}

	return recs, true
}

func (AXFRRecord) Type() uint16 {
	return dns.TypeAXFR
}

func init() {
	Register(AXFRRecord{})
}
