package types

import (
	"github.com/miekg/dns"
	"sync"
)

var (
	dnameRecords = make(map[string]*dns.DNAME)
	dnameMu      sync.RWMutex
)

func AddDNAME(name, target string) {
	dnameMu.Lock()
	defer dnameMu.Unlock()
	dnameRecords[name] = &dns.DNAME{
		Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeDNAME, Class: dns.ClassINET, Ttl: 3600},
		Target: target,
	}
}

func LookupDNAME(name string) *dns.DNAME {
	dnameMu.RLock()
	defer dnameMu.RUnlock()
	return dnameRecords[name]
}

func DeleteDNAME(name string) {
	dnameMu.Lock()
	defer dnameMu.Unlock()
	delete(dnameRecords, name)
}
