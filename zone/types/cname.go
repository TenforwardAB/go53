package types

import (
	"github.com/miekg/dns"
	"sync"
)

var (
	cnameRecords = make(map[string]*dns.CNAME)
	cnameMu      sync.RWMutex
)

func AddCNAME(name, target string) {
	cnameMu.Lock()
	defer cnameMu.Unlock()
	cnameRecords[name] = &dns.CNAME{
		Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 3600},
		Target: target,
	}
}

func LookupCNAME(name string) *dns.CNAME {
	cnameMu.RLock()
	defer cnameMu.RUnlock()
	return cnameRecords[name]
}

func DeleteCNAME(name string) {
	cnameMu.Lock()
	defer cnameMu.Unlock()
	delete(cnameRecords, name)
}
