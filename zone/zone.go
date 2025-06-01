package zone

import (
    "net"
    "sync"
    "github.com/miekg/dns"
)

var (
    records = make(map[string]*dns.A)
    mu      sync.RWMutex
)

func AddARecord(name, ip string) {
    mu.Lock()
    defer mu.Unlock()
    records[name] = &dns.A{
        Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
        A:   net.ParseIP(ip),
    }
}

func LookupA(name string) *dns.A {
    mu.RLock()
    defer mu.RUnlock()
    return records[name]
}
