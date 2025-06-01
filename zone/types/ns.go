package types

import (
	"github.com/miekg/dns"
	"sync"
)

var (
	nsRecords = make(map[string][]*dns.NS)
	nsMu      sync.RWMutex
)

func AddNS(name, ns string) {
	nsMu.Lock()
	defer nsMu.Unlock()
	nsRecords[name] = append(nsRecords[name], &dns.NS{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
		Ns:  ns,
	})
}

func LookupNS(name string) []*dns.NS {
	nsMu.RLock()
	defer nsMu.RUnlock()
	return nsRecords[name]
}

func DeleteNS(name string) {
	nsMu.Lock()
	defer nsMu.Unlock()
	delete(nsRecords, name)
}
