package types

import (
	"github.com/miekg/dns"
	"sync"
)

var (
	mxRecords = make(map[string][]*dns.MX)
	mxMu      sync.RWMutex
)

func AddMX(name string, preference uint16, mx string) {
	mxMu.Lock()
	defer mxMu.Unlock()
	mxRecords[name] = append(mxRecords[name], &dns.MX{
		Hdr:        dns.RR_Header{Name: name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 3600},
		Preference: preference,
		Mx:         mx,
	})
}

func LookupMX(name string) []*dns.MX {
	mxMu.RLock()
	defer mxMu.RUnlock()
	return mxRecords[name]
}

func DeleteMX(name string) {
	mxMu.Lock()
	defer mxMu.Unlock()
	delete(mxRecords, name)
}
