package security

import (
	"crypto"
	"errors"
	"fmt"
	"go53/types"
	"time"

	"github.com/miekg/dns"
)

func ToRRSet(rrs interface{}) ([]dns.RR, error) {
	switch v := rrs.(type) {
	case []dns.RR:
		return v, nil
	case dns.RR:
		return []dns.RR{v}, nil
	case *dns.RR:
		return []dns.RR{*v}, nil
	default:
		return nil, fmt.Errorf("unsupported RRSet type: %T", rrs)
	}
}

func SignRRSet(rrs []dns.RR, key crypto.Signer, keyTag uint16, signerName string) (*dns.RRSIG, error) {
	if len(rrs) == 0 {
		return nil, errors.New("cannot sign empty RRSet")
	}

	SortRRCanonically(rrs)

	hdr := rrs[0].Header()
	rrsig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   hdr.Name,
			Rrtype: dns.TypeRRSIG,
			Class:  hdr.Class,
			Ttl:    hdr.Ttl,
		},
		TypeCovered: hdr.Rrtype,
		Algorithm:   13, // ECDSAP256 for now

		Labels:     uint8(dns.CountLabel(hdr.Name)),
		OrigTtl:    hdr.Ttl,
		Expiration: uint32(time.Now().Add(7 * 24 * time.Hour).Unix()),
		Inception:  uint32(time.Now().Add(-1 * time.Hour).Unix()),
		KeyTag:     keyTag,
		SignerName: dns.Fqdn(signerName),
	}

	if err := rrsig.Sign(key, rrs); err != nil {
		return nil, err
	}

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

func ToDNSRRSIG(name string, r *types.RRSIGRecord) (*dns.RRSIG, error) {
	rrtype, ok := dns.StringToType[r.TypeCovered]
	if !ok {
		return nil, fmt.Errorf("invalid type_covered: %s", r.TypeCovered)
	}

	return &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(name),
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    r.TTL,
		},
		TypeCovered: rrtype,
		Algorithm:   r.Algorithm,
		Labels:      r.Labels,
		OrigTtl:     r.OrigTTL,
		Expiration:  r.Expiration,
		Inception:   r.Inception,
		KeyTag:      r.KeyTag,
		SignerName:  dns.Fqdn(r.SignerName),
		Signature:   r.Signature,
	}, nil
}
