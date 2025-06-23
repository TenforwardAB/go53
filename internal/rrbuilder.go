package internal

import (
	"github.com/miekg/dns"
	"go53/types"
	"net"
)

type RRBuilder func(name string, data any) []dns.RR

var RRBuilders = map[string]RRBuilder{
	"A": func(name string, data any) []dns.RR {
		var rrs []dns.RR

		switch v := data.(type) {
		case []types.ARecord:
			for _, rec := range v {
				rrs = append(rrs, &dns.A{
					Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rec.TTL},
					A:   net.ParseIP(rec.IP).To4(),
				})
			}
		case []map[string]interface{}:
			for _, rec := range v {
				ip := net.ParseIP(rec["ip"].(string)).To4()
				ttl := toTTL(rec)
				rrs = append(rrs, &dns.A{
					Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
					A:   ip,
				})
			}
		case []interface{}:
			for _, raw := range v {
				if rec, ok := raw.(map[string]interface{}); ok {
					ip := net.ParseIP(rec["ip"].(string)).To4()
					ttl := toTTL(rec)
					rrs = append(rrs, &dns.A{
						Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
						A:   ip,
					})
				}
			}
		}

		return rrs
	},

	"MX": func(name string, data any) []dns.RR {
		var rrs []dns.RR

		switch v := data.(type) {
		case []types.MXRecord:
			for _, rec := range v {
				rrs = append(rrs, &dns.MX{
					Hdr:        dns.RR_Header{Name: name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: rec.TTL},
					Preference: rec.Priority,
					Mx:         dns.Fqdn(rec.Host),
				})
			}
		case []map[string]interface{}:
			for _, rec := range v {
				host := rec["host"].(string)
				priority := uint16(getFloat64(rec["priority"]))
				ttl := toTTL(rec)
				rrs = append(rrs, &dns.MX{
					Hdr:        dns.RR_Header{Name: name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: ttl},
					Preference: priority,
					Mx:         dns.Fqdn(host),
				})
			}
		case []interface{}:
			for _, raw := range v {
				if rec, ok := raw.(map[string]interface{}); ok {
					host := rec["host"].(string)
					priority := uint16(getFloat64(rec["priority"]))
					ttl := toTTL(rec)
					rrs = append(rrs, &dns.MX{
						Hdr:        dns.RR_Header{Name: name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: ttl},
						Preference: priority,
						Mx:         dns.Fqdn(host),
					})
				}
			}
		}

		return rrs
	},

	"TXT": func(name string, data any) []dns.RR {
		var rrs []dns.RR

		switch v := data.(type) {
		case []map[string]interface{}:
			for _, rec := range v {
				text, ok := rec["text"].(string)
				if !ok {
					continue
				}
				ttl := toTTL(rec)
				rrs = append(rrs, &dns.TXT{
					Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
					Txt: []string{text},
				})
			}
		case []interface{}:
			for _, item := range v {
				switch rec := item.(type) {
				case map[string]interface{}:
					text, ok := rec["text"].(string)
					if !ok {
						continue
					}
					ttl := toTTL(rec)
					rrs = append(rrs, &dns.TXT{
						Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
						Txt: []string{text},
					})
				case types.TXTRecord:
					rrs = append(rrs, &dns.TXT{
						Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: rec.TTL},
						Txt: []string{rec.Text},
					})
				}
			}
		case []types.TXTRecord:
			for _, rec := range v {
				rrs = append(rrs, &dns.TXT{
					Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: rec.TTL},
					Txt: []string{rec.Text},
				})
			}
		}

		return rrs
	},

	"SRV": func(name string, data any) []dns.RR {
		var rrs []dns.RR

		switch v := data.(type) {
		case []map[string]interface{}:
			for _, m := range v {
				ttl := toTTL(m)
				priority, _ := m["priority"].(float64)
				weight, _ := m["weight"].(float64)
				port, _ := m["port"].(float64)
				target, _ := m["target"].(string)

				rrs = append(rrs, &dns.SRV{
					Hdr: dns.RR_Header{
						Name:   name,
						Rrtype: dns.TypeSRV,
						Class:  dns.ClassINET,
						Ttl:    ttl,
					},
					Priority: uint16(priority),
					Weight:   uint16(weight),
					Port:     uint16(port),
					Target:   dns.Fqdn(target),
				})
			}

		case []types.SRVRecord:
			for _, rec := range v {
				rrs = append(rrs, &dns.SRV{
					Hdr: dns.RR_Header{
						Name:   name,
						Rrtype: dns.TypeSRV,
						Class:  dns.ClassINET,
						Ttl:    rec.TTL,
					},
					Priority: rec.Priority,
					Weight:   rec.Weight,
					Port:     rec.Port,
					Target:   dns.Fqdn(rec.Target),
				})
			}

		case []interface{}:
			for _, item := range v {
				switch rec := item.(type) {
				case map[string]interface{}:
					ttl := toTTL(rec)
					priority, _ := rec["priority"].(float64)
					weight, _ := rec["weight"].(float64)
					port, _ := rec["port"].(float64)
					target, _ := rec["target"].(string)

					rrs = append(rrs, &dns.SRV{
						Hdr: dns.RR_Header{
							Name:   name,
							Rrtype: dns.TypeSRV,
							Class:  dns.ClassINET,
							Ttl:    ttl,
						},
						Priority: uint16(priority),
						Weight:   uint16(weight),
						Port:     uint16(port),
						Target:   dns.Fqdn(target),
					})

				case []interface{}:
					// Handle tuple-like form: [priority, weight, port, target, ttl]
					if len(rec) >= 5 {
						priority, _ := rec[0].(float64)
						weight, _ := rec[1].(float64)
						port, _ := rec[2].(float64)
						target, _ := rec[3].(string)
						ttl, _ := rec[4].(float64)

						rrs = append(rrs, &dns.SRV{
							Hdr: dns.RR_Header{
								Name:   name,
								Rrtype: dns.TypeSRV,
								Class:  dns.ClassINET,
								Ttl:    uint32(ttl),
							},
							Priority: uint16(priority),
							Weight:   uint16(weight),
							Port:     uint16(port),
							Target:   dns.Fqdn(target),
						})
					}
				}
			}
		}

		return rrs
	},

	"PTR": func(name string, data any) []dns.RR {
		var rrs []dns.RR

		switch v := data.(type) {
		case map[string]interface{}:
			ptr, _ := v["ptr"].(string)
			ttl := toTTL(v)
			rrs = append(rrs, &dns.PTR{
				Hdr: dns.RR_Header{
					Name:   name,
					Rrtype: dns.TypePTR,
					Class:  dns.ClassINET,
					Ttl:    ttl,
				},
				Ptr: dns.Fqdn(ptr),
			})

		case []map[string]interface{}:
			for _, rec := range v {
				ptr, _ := rec["ptr"].(string)
				ttl := toTTL(rec)
				rrs = append(rrs, &dns.PTR{
					Hdr: dns.RR_Header{
						Name:   name,
						Rrtype: dns.TypePTR,
						Class:  dns.ClassINET,
						Ttl:    ttl,
					},
					Ptr: dns.Fqdn(ptr),
				})
			}

		case []interface{}:
			for _, raw := range v {
				switch rec := raw.(type) {
				case map[string]interface{}:
					ptr, _ := rec["ptr"].(string)
					ttl := toTTL(rec)
					rrs = append(rrs, &dns.PTR{
						Hdr: dns.RR_Header{
							Name:   name,
							Rrtype: dns.TypePTR,
							Class:  dns.ClassINET,
							Ttl:    ttl,
						},
						Ptr: dns.Fqdn(ptr),
					})
				case []interface{}: // e.g. [{api.go53.test. 3600}]
					if len(rec) >= 2 {
						ptr, _ := rec[0].(string)
						ttlF, _ := rec[1].(float64)
						rrs = append(rrs, &dns.PTR{
							Hdr: dns.RR_Header{
								Name:   name,
								Rrtype: dns.TypePTR,
								Class:  dns.ClassINET,
								Ttl:    uint32(ttlF),
							},
							Ptr: dns.Fqdn(ptr),
						})
					}
				}
			}

		case []types.PTRRecord:
			for _, rec := range v {
				rrs = append(rrs, &dns.PTR{
					Hdr: dns.RR_Header{
						Name:   name,
						Rrtype: dns.TypePTR,
						Class:  dns.ClassINET,
						Ttl:    rec.TTL,
					},
					Ptr: dns.Fqdn(rec.Ptr),
				})
			}
		}

		return rrs
	},

	"CNAME": func(name string, data any) []dns.RR {
		switch v := data.(type) {
		case types.CNAMERecord:
			return []dns.RR{&dns.CNAME{
				Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: v.TTL},
				Target: dns.Fqdn(v.Target),
			}}
		case map[string]interface{}:
			target := v["target"].(string)
			ttl := toTTL(v)
			return []dns.RR{&dns.CNAME{
				Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
				Target: dns.Fqdn(target),
			}}
		default:
			return nil
		}
	},

	"SOA": func(name string, data any) []dns.RR {
		switch v := data.(type) {
		case types.SOARecord:
			return []dns.RR{&dns.SOA{
				Hdr:     dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: v.TTL},
				Ns:      dns.Fqdn(v.Ns),
				Mbox:    dns.Fqdn(v.Mbox),
				Serial:  v.Serial,
				Refresh: v.Refresh,
				Retry:   v.Retry,
				Expire:  v.Expire,
				Minttl:  v.Minimum,
			}}
		case map[string]interface{}:
			return []dns.RR{&dns.SOA{
				Hdr:     dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: toTTL(v)},
				Ns:      dns.Fqdn(v["ns"].(string)),
				Mbox:    dns.Fqdn(v["mbox"].(string)),
				Serial:  uint32(getFloat64(v["serial"])),
				Refresh: uint32(getFloat64(v["refresh"])),
				Retry:   uint32(getFloat64(v["retry"])),
				Expire:  uint32(getFloat64(v["expire"])),
				Minttl:  uint32(getFloat64(v["minimum"])),
			}}
		default:
			return nil
		}
	},
}

func toTTL(m map[string]interface{}) uint32 {
	if t, ok := m["ttl"].(float64); ok {
		return uint32(t)
	}
	return 3600
}

func getFloat64(v interface{}) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return 0
}
