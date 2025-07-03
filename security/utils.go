package security

import (
	"bytes"
	"github.com/miekg/dns"
	"sort"
)

func rrCanonicalLess(a, b dns.RR) bool {
	msgA := make([]byte, 4096)
	msgB := make([]byte, 4096)

	offA, errA := dns.PackRR(a, msgA, 0, nil, true)
	offB, errB := dns.PackRR(b, msgB, 0, nil, true)
	if errA != nil || errB != nil {
		return false // or decide how to handle packing errors
	}

	return bytes.Compare(msgA[:offA], msgB[:offB]) < 0
}

func SortRRCanonically(rrs []dns.RR) {
	sort.SliceStable(rrs, func(i, j int) bool {
		return rrCanonicalLess(rrs[i], rrs[j])
	})
}
