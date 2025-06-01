package types

import (
	"github.com/miekg/dns"
	"sync"
)

var (
	ptrRecords = make(map[string]*dns.PTR)
	ptrMu      sync.RWMutex
)

func AddPTR(name, ptr string) {
	ptrMu.Lock()
	defer ptrMu.Unlock()
	ptrRecords[name] = &dns.PTR{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 3600},
		Ptr: ptr,
	}
}

func LookupPTR(name string) *dns.PTR {
	ptrMu.RLock()
	defer ptrMu.RUnlock()
	return ptrRecords[name]
}

func DeletePTR(name string) {
	ptrMu.Lock()
	defer ptrMu.Unlock()
	delete(ptrRecords, name)
}
