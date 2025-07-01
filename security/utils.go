package security

import (
	"sort"
	"strings"

	"github.com/miekg/dns"
)

func SortRRCanonically(rrs []dns.RR) {
	sort.SliceStable(rrs, func(i, j int) bool {
		return rrCompareCanonical(rrs[i], rrs[j]) < 0
	})
}

func rrCompareCanonical(a, b dns.RR) int {
	nameA := dns.CanonicalName(a.Header().Name)
	nameB := dns.CanonicalName(b.Header().Name)
	if cmp := strings.Compare(nameA, nameB); cmp != 0 {
		return cmp
	}

	if a.Header().Rrtype != b.Header().Rrtype {
		return int(a.Header().Rrtype) - int(b.Header().Rrtype)
	}

	if a.Header().Class != b.Header().Class {
		return int(a.Header().Class) - int(b.Header().Class)
	}

	if a.Header().Ttl != b.Header().Ttl {
		return int(a.Header().Ttl) - int(b.Header().Ttl)
	}
	rdataA := rdataCanonicalString(a)
	rdataB := rdataCanonicalString(b)
	return strings.Compare(rdataA, rdataB)
}

func rdataCanonicalString(rr dns.RR) string {
	return dns.CanonicalName(rr.String())
}
