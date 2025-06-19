package internal

import (
	"github.com/miekg/dns"
	"net"
)

type RRBuilder func(name string, data map[string]interface{}) dns.RR

var RRBuilders = map[string]RRBuilder{
	"A": func(name string, m map[string]interface{}) dns.RR {
		ip := net.ParseIP(m["ip"].(string)).To4()
		ttl := toTTL(m)
		return &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   ip,
		}
	},
	"MX": func(name string, m map[string]interface{}) dns.RR {
		ttl := toTTL(m)
		return &dns.MX{
			Hdr:        dns.RR_Header{Name: name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: ttl},
			Preference: uint16(m["priority"].(float64)),
			Mx:         m["host"].(string),
		}
	},
	"NS": func(name string, m map[string]interface{}) dns.RR {
		ttl := toTTL(m)
		return &dns.NS{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ttl},
			Ns:  m["ns"].(string),
		}
	},
	"TXT": func(name string, m map[string]interface{}) dns.RR {
		ttl := toTTL(m)
		return &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			Txt: []string{m["text"].(string)},
		}
	},

	"SRV": func(name string, m map[string]interface{}) dns.RR {
		ttl := toTTL(m)
		return &dns.SRV{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeSRV,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			Priority: uint16(m["priority"].(float64)),
			Weight:   uint16(m["weight"].(float64)),
			Port:     uint16(m["port"].(float64)),
			Target:   m["target"].(string),
		}
	},

	"SOA": func(name string, m map[string]interface{}) dns.RR {
		ttl := toTTL(m)
		return &dns.SOA{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			Ns:      m["ns"].(string),
			Mbox:    m["mbox"].(string),
			Serial:  uint32(m["serial"].(float64)),
			Refresh: uint32(m["refresh"].(float64)),
			Retry:   uint32(m["retry"].(float64)),
			Expire:  uint32(m["expire"].(float64)),
			Minttl:  uint32(m["minimum"].(float64)),
		}
	},

	"PTR": func(name string, m map[string]interface{}) dns.RR {
		ttl := toTTL(m)
		return &dns.PTR{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypePTR,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			Ptr: m["ptr"].(string),
		}
	},
	"CNAME": func(name string, m map[string]interface{}) dns.RR {
		ttl := toTTL(m)
		return &dns.CNAME{
			Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
			Target: m["target"].(string),
		}
	},
	// Lägg till fler typer här...
}

func toTTL(m map[string]interface{}) uint32 {
	if t, ok := m["ttl"].(float64); ok {
		return uint32(t)
	}
	return 3600
}
