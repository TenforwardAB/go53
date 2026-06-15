package security

import (
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/TenforwardAB/slog"
	"go53/config"
	"go53/internal"
	"go53/types"
	"reflect"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func ToRRSet(name string, rtype string, raw any) ([]dns.RR, error) {
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

	fqdn, err := internal.SanitizeFQDN(name)
	if err != nil {
		return nil, err
	}
	rrs := builder(fqdn, raw)
	slog.Crazy("[ToRRSet] name2 is:", fqdn)
	slog.Crazy("[ToRRSet] rrs is:", rrs)
	if len(rrs) == 0 {
		return nil, fmt.Errorf("no RRs built for %q", rtype)
	}

	return rrs, nil
}

type SignaturePolicy struct {
	Validity      time.Duration
	RefreshBefore time.Duration
	Jitter        time.Duration
	InceptionSkew time.Duration
}

func PolicyForRRType(rrtype uint16) SignaturePolicy {
	cfg := config.AppConfig.GetLive().DNSSEC
	validity := secondsOrDefault(cfg.ValiditySeconds, 7*24*3600)
	if rrtype == dns.TypeDNSKEY {
		validity = secondsOrDefault(cfg.DNSKEYValiditySeconds, 14*24*3600)
	}
	refreshBefore := secondsOrDefault(cfg.RefreshBeforeSeconds, 24*3600)
	jitter := secondsOrDefault(cfg.JitterSeconds, 3600)
	inceptionSkew := secondsOrDefault(cfg.InceptionSkewSeconds, 3600)
	if refreshBefore >= validity {
		refreshBefore = validity / 3
	}
	if jitter >= refreshBefore {
		jitter = refreshBefore / 2
	}
	return SignaturePolicy{
		Validity:      time.Duration(validity) * time.Second,
		RefreshBefore: time.Duration(refreshBefore) * time.Second,
		Jitter:        time.Duration(jitter) * time.Second,
		InceptionSkew: time.Duration(inceptionSkew) * time.Second,
	}
}

func SignRRSet(rrs []dns.RR, key crypto.Signer, keyTag uint16, signerName string, algorithm uint8) (*dns.RRSIG, error) {
	slog.Crazy("[SignRRSet] len(rrs): %d", len(rrs))
	slog.Crazy("[SignRRSet] keyTag: %d", keyTag)
	if len(rrs) == 0 {
		return nil, errors.New("cannot sign empty RRSet")
	}

	SortRRCanonically(rrs)
	fqdn, _ := internal.SanitizeFQDN(signerName)

	hdr := rrs[0].Header()
	policy := PolicyForRRType(hdr.Rrtype)
	now := time.Now()
	jitter := signatureJitterSeconds(hdr.Name, hdr.Rrtype, keyTag, policy.Jitter)
	rrsig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   hdr.Name,
			Rrtype: dns.TypeRRSIG,
			Class:  hdr.Class,
			Ttl:    hdr.Ttl,
		},
		TypeCovered: hdr.Rrtype,
		Algorithm:   algorithm,

		Labels:     rrsigLabelCount(hdr.Name),
		OrigTtl:    hdr.Ttl,
		Expiration: uint32(now.Add(policy.Validity - jitter).Unix()),
		Inception:  uint32(now.Add(-policy.InceptionSkew).Unix()),
		KeyTag:     keyTag,
		SignerName: fqdn,
	}

	if err := rrsig.Sign(key, rrs); err != nil {
		return nil, err
	}

	slog.Crazy("[SignRRSet] signed RRSet %+v for the RR %s", rrsig, rrs)

	return rrsig, nil
}

func rrsigLabelCount(name string) uint8 {
	labels := dns.CountLabel(name)
	if strings.HasPrefix(dns.Fqdn(name), "*.") && labels > 0 {
		labels--
	}
	return uint8(labels)
}

func RRSIGFresh(owner string, sig *types.RRSIGRecord, covered uint16, now time.Time) bool {
	if sig == nil {
		return false
	}
	nowUnix := uint32(now.Unix())
	if sig.Inception > nowUnix || sig.Expiration <= nowUnix {
		return false
	}
	policy := PolicyForRRType(covered)
	refreshAt := time.Unix(int64(sig.Expiration), 0).Add(-policy.RefreshBefore - signatureJitterSeconds(owner, covered, sig.KeyTag, policy.Jitter))
	return now.Before(refreshAt)
}

func signatureJitterSeconds(owner string, rrtype uint16, keyTag uint16, max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	seed := fmt.Sprintf("%s|%d|%d", dns.CanonicalName(owner), rrtype, keyTag)
	sum := sha256.Sum256([]byte(seed))
	offset := binary.BigEndian.Uint64(sum[:8]) % uint64(max/time.Second+1)
	return time.Duration(offset) * time.Second
}

func secondsOrDefault(value int, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
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
