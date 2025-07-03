package rtypes

import (
	"github.com/TenforwardAB/slog"
	"go53/internal"
	"go53/internal/errors"
	"go53/types"
	"strings"

	"github.com/miekg/dns"
)

type RRSIGRecord struct{}

func (RRSIGRecord) Add(zone, name string, value interface{}, ttl *uint32) error {
	return errors.NotImplemented("RRSIGRecord.Add")
}

func (RRSIGRecord) Delete(host string, value interface{}) error {
	return errors.NotImplemented("RRSIGRecord.Delete")
}

func (RRSIGRecord) Lookup(host string) ([]dns.RR, bool) {
	parts := strings.SplitN(host, "___", 2)
	if len(parts) != 2 {
		return nil, false
	}

	name := parts[0]
	rtypeStr := parts[1]
	slog.Crazy("[handleRequest] rtype is: %s", rtypeStr)

	zone, shortName, ok := internal.SplitName(name)
	shortName = dns.Fqdn(shortName)
	if !ok {
		return nil, false
	}
	slog.Crazy("[handleRequest] zone is: %s", zone)
	slog.Crazy("[handleRequest] short name is: %s", shortName)

	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil || memStore == nil {
		return nil, false
	}

	_, _, val, ok := memStore.GetRecord(sanitizedZone, "RRSIG", rtypeStr)
	slog.Crazy("[handleRequest] val is: %#v", val)
	if !ok {
		return nil, false
	}

	valMap, ok := val.(map[string]any)
	if !ok {
		slog.Crazy("[handleRequest] val is not a map[string]any")
		return nil, false
	}

	raw, ok := valMap[shortName]
	if !ok {
		slog.Crazy("[handleRequest] no entry for shortName %q", shortName)
		return nil, false
	}

	rawSlice, ok := raw.([]interface{})
	if !ok {
		slog.Crazy("[handleRequest] shortName %q did not contain []interface{}", shortName)
		return nil, false
	}

	var results []dns.RR
	for _, item := range rawSlice {
		sig, ok := item.(*types.RRSIGRecord)
		if !ok {
			slog.Crazy("[handleRequest] item is not *types.RRSIGRecord: %#v", item)
			continue
		}

		covered, ok := dns.StringToType[sig.TypeCovered]
		if !ok {
			slog.Crazy("[handleRequest] unknown TypeCovered: %q", sig.TypeCovered)
			continue
		}

		s := &dns.RRSIG{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(name),
				Rrtype: dns.TypeRRSIG,
				Class:  dns.ClassINET,
				Ttl:    sig.TTL,
			},
			TypeCovered: uint16(covered),
			Algorithm:   sig.Algorithm,
			Labels:      sig.Labels,
			OrigTtl:     sig.OrigTTL,
			Expiration:  sig.Expiration,
			Inception:   sig.Inception,
			KeyTag:      sig.KeyTag,
			SignerName:  sig.SignerName,
			Signature:   sig.Signature,
		}
		results = append(results, s)
	}

	slog.Crazy("[handleRequest] final RRSIG count: %d", len(results))
	return results, len(results) > 0

}

func (RRSIGRecord) Type() uint16 {
	return dns.TypeRRSIG
}

func init() {
	Register(RRSIGRecord{})
}
