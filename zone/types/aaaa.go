package types

import (
	"github.com/miekg/dns"
	"net"
	"sync"
)

var (
	aaaaRecords = make(map[string]*dns.AAAA)
	aaaaMu      sync.RWMutex
)

func AddAAAA(name, ip string) {
	aaaaMu.Lock()
	defer aaaaMu.Unlock()
	aaaaRecords[name] = &dns.AAAA{
		Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 3600},
		AAAA: net.ParseIP(ip),
	}
}

func LookupAAAA(name string) *dns.AAAA {
	aaaaMu.RLock()
	defer aaaaMu.RUnlock()
	return aaaaRecords[name]
}

func DeleteAAAA(name string) {
	aaaaMu.Lock()
	defer aaaaMu.Unlock()
	delete(aaaaRecords, name)
}
