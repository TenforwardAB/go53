package types

import (
	"github.com/miekg/dns"
	"sync"
)

var (
	txtRecords = make(map[string][]*dns.TXT)
	txtMu      sync.RWMutex
)

func AddTXT(name string, texts ...string) {
	txtMu.Lock()
	defer txtMu.Unlock()
	txtRecords[name] = append(txtRecords[name], &dns.TXT{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
		Txt: texts,
	})
}

func LookupTXT(name string) []*dns.TXT {
	txtMu.RLock()
	defer txtMu.RUnlock()
	return txtRecords[name]
}

func DeleteTXT(name string) {
	txtMu.Lock()
	defer txtMu.Unlock()
	delete(txtRecords, name)
}
