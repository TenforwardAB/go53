package types

import (
	"github.com/miekg/dns"
	"sync"
)

var (
	soaRecords = make(map[string]*dns.SOA)
	soaMu      sync.RWMutex
)

func AddSOA(name, ns, mbox string, serial, refresh, retry, expire, minttl uint32) {
	soaMu.Lock()
	defer soaMu.Unlock()
	soaRecords[name] = &dns.SOA{
		Hdr:     dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      ns,
		Mbox:    mbox,
		Serial:  serial,
		Refresh: refresh,
		Retry:   retry,
		Expire:  expire,
		Minttl:  minttl,
	}
}

func LookupSOA(name string) *dns.SOA {
	soaMu.RLock()
	defer soaMu.RUnlock()
	return soaRecords[name]
}

func DeleteSOA(name string) {
	soaMu.Lock()
	defer soaMu.Unlock()
	delete(soaRecords, name)
}
