package types

import (
	"github.com/miekg/dns"
	"net"
	"sync"
)

var (
	aRecords = make(map[string]*dns.A)
	aMu      sync.RWMutex
)

func AddA(name, ip string) {
	aMu.Lock()
	defer aMu.Unlock()
	aRecords[name] = &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   net.ParseIP(ip),
	}
}

func LookupA(name string) *dns.A {
	aMu.RLock()
	defer aMu.RUnlock()
	return aRecords[name]
}

func DeleteA(name string) {
	aMu.Lock()
	defer aMu.Unlock()
	delete(aRecords, name)
}
