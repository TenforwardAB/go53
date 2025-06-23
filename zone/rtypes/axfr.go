package rtypes

import (
	"github.com/miekg/dns"
	"go53/internal"
	"go53/internal/errors"
	"log"
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

	log.Println("AXFRRecord.Lookup", zone)
	recs, err := memStore.GetZone(zone)
	log.Println("We have the recs: ", recs)
	if err != nil || len(recs) == 0 {
		return nil, false
	}

	var soa dns.RR
	var result []dns.RR

	for _, rr := range recs {
		if rr.Header().Rrtype == dns.TypeSOA && soa == nil {
			soa = rr
			continue
		}
		result = append(result, rr)
	}

	if soa == nil {
		return nil, false
	}

	// prepend SOA and append SOA
	final := make([]dns.RR, 0, len(result)+2)
	final = append(final, soa)
	final = append(final, result...)
	final = append(final, soa)

	log.Println("full zone as RR:")
	log.Println(final)

	return final, true
}

func (AXFRRecord) Type() uint16 {
	return dns.TypeAXFR
}

func init() {
	Register(AXFRRecord{})
}
