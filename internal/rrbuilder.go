package internal

import (
	"encoding/json"
	"fmt"
	"github.com/TenforwardAB/slog"
	"github.com/miekg/dns"
	"go53/types"
	"net"
	"reflect"
	"strings"
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

	"NS": func(name string, data any) []dns.RR {
		//fqdn, _ := SanitizeFQDN(name)
		var rrs []dns.RR

		switch v := data.(type) {
		case []types.NSRecord:
			for _, rec := range v {
				rrs = append(rrs, &dns.NS{
					Hdr: dns.RR_Header{
						Name:   name,
						Rrtype: dns.TypeNS,
						Class:  dns.ClassINET,
						Ttl:    rec.TTL,
					},
					Ns: dns.Fqdn(rec.NS),
				})
			}
		case []map[string]interface{}:
			for _, rec := range v {
				ns := rec["ns"].(string)
				ttl := toTTL(rec)
				rrs = append(rrs, &dns.NS{
					Hdr: dns.RR_Header{
						Name:   name,
						Rrtype: dns.TypeNS,
						Class:  dns.ClassINET,
						Ttl:    ttl,
					},
					Ns: dns.Fqdn(ns),
				})
			}
		case []interface{}:
			for _, raw := range v {
				if rec, ok := raw.(map[string]interface{}); ok {
					ns := rec["ns"].(string)
					ttl := toTTL(rec)
					rrs = append(rrs, &dns.NS{
						Hdr: dns.RR_Header{
							Name:   name,
							Rrtype: dns.TypeNS,
							Class:  dns.ClassINET,
							Ttl:    ttl,
						},
						Ns: dns.Fqdn(ns),
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

	"SPF": func(name string, data any) []dns.RR {
		switch v := data.(type) {
		case types.SPFRecord:
			return []dns.RR{&dns.SPF{
				Hdr: dns.RR_Header{
					Name:   name,
					Rrtype: dns.TypeSPF,
					Class:  dns.ClassINET,
					Ttl:    v.TTL,
				},
				Txt: []string{v.Text},
			}}
		case map[string]interface{}:
			text := v["text"].(string)
			ttl := toTTL(v)
			return []dns.RR{&dns.SPF{
				Hdr: dns.RR_Header{
					Name:   name,
					Rrtype: dns.TypeSPF,
					Class:  dns.ClassINET,
					Ttl:    ttl,
				},
				Txt: []string{text},
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

	"DNSKEY": func(name string, data any) []dns.RR {
		switch v := data.(type) {
		case []types.DNSKEYRecord:
			var out []dns.RR
			for _, v := range data.([]types.DNSKEYRecord) {
				out = append(out, &dns.DNSKEY{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn(name),
						Rrtype: dns.TypeDNSKEY,
						Class:  dns.ClassINET,
						Ttl:    v.TTL,
					},
					Flags:     v.Flags,
					Protocol:  v.Protocol,
					Algorithm: v.Algorithm,
					PublicKey: v.PublicKey,
				})
			}
			return out

		case types.DNSKEYRecord:
			return []dns.RR{&dns.DNSKEY{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(name),
					Rrtype: dns.TypeDNSKEY,
					Class:  dns.ClassINET,
					Ttl:    v.TTL,
				},
				Flags:     v.Flags,
				Protocol:  v.Protocol,
				Algorithm: v.Algorithm,
				PublicKey: v.PublicKey,
			}}

		case map[string]interface{}:
			// single DNSKEY entry
			flags := uint16(v["flags"].(float64))
			protocol := uint8(3)
			if p, ok := v["protocol"].(float64); ok {
				protocol = uint8(p)
			}
			algorithm := uint8(v["algorithm"].(float64))
			publicKey := v["public_key"].(string)
			ttl := toTTL(v)

			return []dns.RR{&dns.DNSKEY{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn(name),
					Rrtype: dns.TypeDNSKEY,
					Class:  dns.ClassINET,
					Ttl:    ttl,
				},
				Flags:     flags,
				Protocol:  protocol,
				Algorithm: algorithm,
				PublicKey: publicKey,
			}}

		case []interface{}:
			// multiple DNSKEY entries
			var out []dns.RR
			for _, item := range v {
				m, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				flags := uint16(m["flags"].(float64))
				protocol := uint8(3)
				if p, ok := m["protocol"].(float64); ok {
					protocol = uint8(p)
				}
				algorithm := uint8(m["algorithm"].(float64))
				publicKey := m["public_key"].(string)
				ttl := toTTL(m)

				out = append(out, &dns.DNSKEY{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn(name),
						Rrtype: dns.TypeDNSKEY,
						Class:  dns.ClassINET,
						Ttl:    ttl,
					},
					Flags:     flags,
					Protocol:  protocol,
					Algorithm: algorithm,
					PublicKey: publicKey,
				})
			}
			return out
		}

		return nil
	},

	"RRSIG": func(name string, data any) []dns.RR {
		var rrs []dns.RR

		switch v := data.(type) {
		case []*types.RRSIGRecord:
			for _, rec := range v {
				rr, err := toDNSRRSIG(name, rec)
				if err == nil {
					rrs = append(rrs, rr)
				}
			}
		case []map[string]interface{}:
			for _, raw := range v {
				b, err := json.Marshal(raw)
				if err != nil {
					continue
				}
				var rec types.RRSIGRecord
				if err := json.Unmarshal(b, &rec); err != nil {
					continue
				}
				rr, err := toDNSRRSIG(name, &rec)
				if err == nil {
					rrs = append(rrs, rr)
				}
			}
		case []interface{}:
			for _, raw := range v {
				if rec, ok := raw.(map[string]interface{}); ok {
					b, err := json.Marshal(rec)
					if err != nil {
						continue
					}
					var rec types.RRSIGRecord
					if err := json.Unmarshal(b, &rec); err != nil {
						continue
					}
					rr, err := toDNSRRSIG(name, &rec)
					if err == nil {
						rrs = append(rrs, rr)
					}
				}
			}
		}

		return rrs
	},
}

func RRToZoneData(rrs []dns.RR) types.ZoneData {
	var zd types.ZoneData

	zd.A = map[string][]types.ARecord{}
	zd.AAAA = map[string][]types.AAAARecord{}
	zd.MX = map[string][]types.MXRecord{}
	zd.NS = map[string][]types.NSRecord{}
	zd.TXT = map[string][]types.TXTRecord{}
	zd.SRV = map[string][]types.SRVRecord{}
	zd.PTR = map[string][]types.PTRRecord{}
	zd.CNAME = map[string]types.CNAMERecord{}
	zd.CAA = map[string][]types.CAARecord{}
	zd.DNAME = map[string]types.DNAMERecord{}
	zd.NSEC = map[string]types.NSECRecord{}
	zd.NSEC3 = map[string]types.NSEC3Record{}
	zd.DNSKEY = map[string][]types.DNSKEYRecord{}
	zd.RRSIG = map[string][]*types.RRSIGRecord{}
	zd.DS = map[string][]types.DSRecord{}
	zd.NAPTR = map[string][]types.NAPTRRecord{}
	zd.SPF = map[string]types.SPFRecord{}
	zd.HTTPS = map[string][]types.HTTPSRecord{}
	zd.SVCB = map[string][]types.SVCBRecord{}
	zd.LOC = map[string][]types.LOCRecord{}
	zd.CERT = map[string][]types.CERTRecord{}
	zd.SSHFP = map[string][]types.SSHFPRecord{}
	zd.URI = map[string][]types.URIRecord{}
	zd.APL = map[string][]types.APLRecord{}
	zd.SOA = &types.SOARecord{}

	for _, rr := range rrs {
		name := strings.ToLower(strings.TrimSuffix(rr.Header().Name, "."))     // Normalize
		zone := strings.ToLower(strings.TrimSuffix(rrs[0].Header().Name, ".")) // Or use sanitizedZoneName passed in as arg!

		// Remove the zone suffix from the name
		if strings.HasSuffix(name, "."+zone) {
			name = strings.TrimSuffix(name, "."+zone)
		} else if name == zone {
			name = "@"
		}

		slog.Crazy("[rrbuilder.go:RRToZoneData] rr.(type) is: %v", reflect.TypeOf(rr))
		slog.Crazy("[rrbuilder.go:RRToZoneData] rr is: %v", rr)
		switch v := rr.(type) {
		case *dns.A:
			zd.A[name] = append(zd.A[name], types.ARecord{IP: v.A.String(), TTL: v.Hdr.Ttl})
		case *dns.AAAA:
			zd.AAAA[name] = append(zd.AAAA[name], types.AAAARecord{IP: v.AAAA.String(), TTL: v.Hdr.Ttl})
		case *dns.MX:
			zd.MX[name] = append(zd.MX[name], types.MXRecord{Priority: v.Preference, Host: strings.TrimSuffix(v.Mx, "."), TTL: v.Hdr.Ttl})
		case *dns.NS:
			zd.NS[name] = append(zd.NS[name], types.NSRecord{NS: strings.TrimSuffix(v.Ns, "."), TTL: v.Hdr.Ttl})
		case *dns.TXT:
			zd.TXT[name] = append(zd.TXT[name], types.TXTRecord{Text: strings.Join(v.Txt, " "), TTL: v.Hdr.Ttl})
		case *dns.SRV:
			zd.SRV[name] = append(zd.SRV[name], types.SRVRecord{Priority: v.Priority, Weight: v.Weight, Port: v.Port, Target: strings.TrimSuffix(v.Target, "."), TTL: v.Hdr.Ttl})
		case *dns.PTR:
			zd.PTR[name] = append(zd.PTR[name], types.PTRRecord{Ptr: strings.TrimSuffix(v.Ptr, "."), TTL: v.Hdr.Ttl})
		case *dns.CNAME:
			zd.CNAME[name] = types.CNAMERecord{Target: strings.TrimSuffix(v.Target, "."), TTL: v.Hdr.Ttl}
		case *dns.SPF:
			zd.SPF[name] = types.SPFRecord{Text: strings.Join(v.Txt, " "), TTL: v.Hdr.Ttl}
		case *dns.DNSKEY:
			zd.DNSKEY[name] = append(zd.DNSKEY[name], types.DNSKEYRecord{
				Flags:     v.Flags,
				Protocol:  v.Protocol,
				Algorithm: v.Algorithm,
				PublicKey: v.PublicKey,
				TTL:       v.Hdr.Ttl,
			})
		case *dns.SOA:
			zd.SOA = &types.SOARecord{
				Ns:      strings.TrimSuffix(v.Ns, "."),
				Mbox:    strings.TrimSuffix(v.Mbox, "."),
				Serial:  v.Serial,
				Refresh: v.Refresh,
				Retry:   v.Retry,
				Expire:  v.Expire,
				Minimum: v.Minttl,
				TTL:     v.Hdr.Ttl,
			}
			slog.Crazy("[rrbuilder.go:RRToZoneData] zd.SOA is: %v", zd.SOA)
			// TODO: Add remaining record types if needed
		}
	}
	slog.Crazy("[rrbuilder.go:RRToZoneData] zoneData: %v", zd)
	return zd
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

func toDNSRRSIG(name string, r *types.RRSIGRecord) (*dns.RRSIG, error) {
	rrtype, ok := dns.StringToType[r.TypeCovered]
	if !ok {
		return nil, fmt.Errorf("invalid type_covered: %s", r.TypeCovered)
	}

	return &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(name),
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    r.TTL,
		},
		TypeCovered: rrtype,
		Algorithm:   r.Algorithm,
		Labels:      r.Labels,
		OrigTtl:     r.OrigTTL,
		Expiration:  r.Expiration,
		Inception:   r.Inception,
		KeyTag:      r.KeyTag,
		SignerName:  dns.Fqdn(r.SignerName),
		Signature:   r.Signature,
	}, nil
}
