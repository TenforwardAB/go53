package security

import (
	"crypto"
	"errors"
	"fmt"
	"github.com/TenforwardAB/slog"
	"go53/internal"
	"go53/types"
	"reflect"
	"time"

	"github.com/miekg/dns"
)

func ToRRSet(name string, rtype string, raw any) ([]dns.RR, error) {
	if rtype == "DNSKEY" {
		name = "go53.test." //TODO: !!!!!!!NO HARDCODED DOMAIN!!!!!!!
	}

	switch r := raw.(type) {
	case []types.DNSKEYRecord:
		slog.Crazy("[ToRRSet] raw är []types.DNSKEYRecord med längd %d", len(r))
	default:
		slog.Crazy("[ToRRSet] raw är INTE []types.DNSKEYRecord utan %T", raw)
	}
	builder, ok := internal.RRBuilders[rtype]
	slog.Crazy("[ToRRSet] rtype is: ", rtype)
	slog.Crazy("[ToRRSet] name is:", name)
	slog.Crazy("[ToRRSet] raw is:", raw)
	slog.Crazy("[ToRRSet] reflect.TypeOf(raw): %v", reflect.TypeOf(raw))
	slog.Crazy("[ToRRSet] builder for type %s", builder)
	if !ok {
		return nil, fmt.Errorf("no RRBuilder for rtype %q", rtype)
	}

	fqdn, _ := internal.SanitizeFQDN(name)
	rrs := builder(fqdn, raw)
	slog.Crazy("[ToRRSet] name2 is:", fqdn)
	slog.Crazy("[ToRRSet] rrs is:", rrs)
	if len(rrs) == 0 {
		return nil, fmt.Errorf("no RRs built for %q", rtype)
	}

	return rrs, nil
}

func SignRRSet(rrs []dns.RR, key crypto.Signer, keyTag uint16, signerName string) (*dns.RRSIG, error) {
	slog.Crazy("[SignRRSet] len(rrs): %d", len(rrs))
	slog.Crazy("[SignRRSet] keyTag: %d", keyTag)
	if len(rrs) == 0 {
		return nil, errors.New("cannot sign empty RRSet")
	}

	SortRRCanonically(rrs)
	fqdn, _ := internal.SanitizeFQDN(signerName)

	hdr := rrs[0].Header()
	rrsig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   hdr.Name,
			Rrtype: dns.TypeRRSIG,
			Class:  hdr.Class,
			Ttl:    hdr.Ttl,
		},
		TypeCovered: hdr.Rrtype,
		Algorithm:   10, //TODO: Fix RSASHA512 for now

		Labels:     uint8(dns.CountLabel(hdr.Name)),
		OrigTtl:    hdr.Ttl,
		Expiration: uint32(time.Now().Add(7 * 24 * time.Hour).Unix()),
		Inception:  uint32(time.Now().Add(-1 * time.Hour).Unix()),
		KeyTag:     keyTag,
		SignerName: fqdn,
	}

	if err := rrsig.Sign(key, rrs); err != nil {
		return nil, err
	}

	slog.Crazy("[SignRRSet] signed RRSet %+v for the RR %s", rrsig, rrs)

	return rrsig, nil
}

func RRSIGFromDNS(rrsig *dns.RRSIG) *types.RRSIGRecord {
	if rrsig == nil {
		return nil
	}

	return &types.RRSIGRecord{
		TypeCovered: dns.TypeToString[rrsig.TypeCovered],
		Algorithm:   rrsig.Algorithm,
		Labels:      rrsig.Labels,
		OrigTTL:     rrsig.OrigTtl,
		Expiration:  rrsig.Expiration,
		Inception:   rrsig.Inception,
		KeyTag:      rrsig.KeyTag,
		SignerName:  rrsig.SignerName,
		Signature:   rrsig.Signature,
		TTL:         rrsig.Hdr.Ttl,
	}
}
