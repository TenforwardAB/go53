package internal

import (
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/TenforwardAB/slog"
	"github.com/miekg/dns"
	"go53/recshape"
	"go53/types"
	"net"
	"reflect"
	"sort"
	"strings"
)

type RRBuilder func(name string, data any) []dns.RR

// chunkTXT splits a TXT/SPF rdata string into DNS character-strings of at most
// 255 bytes each, as required on the wire. Strings of 255 bytes or less are
// returned unchanged. Consumers concatenate the character-strings without any
// separator, so long values (e.g. DKIM keys) round-trip correctly.
func chunkTXT(s string) []string {
	const maxLen = 255
	if len(s) <= maxLen {
		return []string{s}
	}
	out := make([]string, 0, len(s)/maxLen+1)
	for len(s) > maxLen {
		out = append(out, s[:maxLen])
		s = s[maxLen:]
	}
	if len(s) > 0 {
		out = append(out, s)
	}
	return out
}

// ChunkTXT is the exported entry point for chunkTXT. The serve path
// (zone/rtypes) must split long TXT/SPF rdata identically to the zone-build and
// DNSSEC-signing paths, otherwise long records fail to pack (query dropped) or
// their signatures fail to validate. Both sides call this one implementation.
func ChunkTXT(s string) []string {
	return chunkTXT(s)
}

// Every builder decodes the stored value through recshape, so AXFR and DNSSEC
// signing read exactly the shapes the query path (zone/rtypes) reads. Only the
// dns.RR construction is per type. Targets are made absolute here as they
// always were on this path.
var RRBuilders = map[string]RRBuilder{
	"A": func(name string, data any) []dns.RR {
		recs, _ := recshape.Decode(data, recshape.ARecord)
		rrs := make([]dns.RR, 0, len(recs))
		for _, rec := range recs {
			ip := net.ParseIP(rec.IP).To4()
			if ip == nil {
				continue
			}
			rrs = append(rrs, &dns.A{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: rec.TTL},
				A:   ip,
			})
		}
		return rrs
	},

	"AAAA": func(name string, data any) []dns.RR {
		recs, _ := recshape.Decode(data, recshape.AAAARecord)
		rrs := make([]dns.RR, 0, len(recs))
		for _, rec := range recs {
			ip := net.ParseIP(rec.IP)
			if ip == nil || ip.To4() != nil {
				continue
			}
			rrs = append(rrs, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: rec.TTL},
				AAAA: ip,
			})
		}
		return rrs
	},

	"NS": func(name string, data any) []dns.RR {
		recs, _ := recshape.Decode(data, recshape.NSRecord)
		rrs := make([]dns.RR, 0, len(recs))
		for _, rec := range recs {
			rrs = append(rrs, &dns.NS{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: rec.TTL},
				Ns:  dns.Fqdn(rec.NS),
			})
		}
		return rrs
	},

	"DS": func(name string, data any) []dns.RR {
		recs, _ := recshape.Decode(data, recshape.DSRecord)
		rrs := make([]dns.RR, 0, len(recs))
		for _, rec := range recs {
			rrs = append(rrs, &dns.DS{
				Hdr:        dns.RR_Header{Name: name, Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: rec.TTL},
				KeyTag:     rec.KeyTag,
				Algorithm:  rec.Algorithm,
				DigestType: rec.DigestType,
				Digest:     strings.ToUpper(rec.Digest),
			})
		}
		return rrs
	},

	"CDS": func(name string, data any) []dns.RR {
		recs, _ := recshape.Decode(data, recshape.CDSRecord)
		rrs := make([]dns.RR, 0, len(recs))
		for _, rec := range recs {
			rrs = append(rrs, &dns.CDS{DS: dns.DS{
				Hdr:        dns.RR_Header{Name: name, Rrtype: dns.TypeCDS, Class: dns.ClassINET, Ttl: rec.TTL},
				KeyTag:     rec.KeyTag,
				Algorithm:  rec.Algorithm,
				DigestType: rec.DigestType,
				Digest:     strings.ToUpper(rec.Digest),
			}})
		}
		return rrs
	},

	"MX": func(name string, data any) []dns.RR {
		recs, _ := recshape.Decode(data, recshape.MXRecord)
		rrs := make([]dns.RR, 0, len(recs))
		for _, rec := range recs {
			rrs = append(rrs, &dns.MX{
				Hdr:        dns.RR_Header{Name: name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: rec.TTL},
				Preference: rec.Priority,
				Mx:         dns.Fqdn(rec.Host),
			})
		}
		return rrs
	},

	"TXT": func(name string, data any) []dns.RR {
		recs, _ := recshape.Decode(data, recshape.TXTRecord)
		rrs := make([]dns.RR, 0, len(recs))
		for _, rec := range recs {
			rrs = append(rrs, &dns.TXT{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: rec.TTL},
				Txt: chunkTXT(rec.Text),
			})
		}
		return rrs
	},

	"SRV": func(name string, data any) []dns.RR {
		recs, _ := recshape.Decode(data, recshape.SRVRecord)
		rrs := make([]dns.RR, 0, len(recs))
		for _, rec := range recs {
			rrs = append(rrs, &dns.SRV{
				Hdr:      dns.RR_Header{Name: name, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: rec.TTL},
				Priority: rec.Priority,
				Weight:   rec.Weight,
				Port:     rec.Port,
				Target:   dns.Fqdn(rec.Target),
			})
		}
		return rrs
	},

	"PTR": func(name string, data any) []dns.RR {
		recs, _ := recshape.Decode(data, recshape.PTRRecord)
		rrs := make([]dns.RR, 0, len(recs))
		for _, rec := range recs {
			rrs = append(rrs, &dns.PTR{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: rec.TTL},
				Ptr: dns.Fqdn(rec.Ptr),
			})
		}
		return rrs
	},

	"CNAME": func(name string, data any) []dns.RR {
		rec, ok := recshape.Single(data, recshape.CNAMERecord)
		if !ok {
			return nil
		}
		return []dns.RR{&dns.CNAME{
			Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: rec.TTL},
			Target: dns.Fqdn(rec.Target),
		}}
	},

	"DNAME": func(name string, data any) []dns.RR {
		rec, ok := recshape.Single(data, recshape.DNAMERecord)
		if !ok {
			return nil
		}
		return []dns.RR{&dns.DNAME{
			Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeDNAME, Class: dns.ClassINET, Ttl: rec.TTL},
			Target: dns.Fqdn(rec.Target),
		}}
	},

	"CAA": func(name string, data any) []dns.RR {
		recs, _ := recshape.Decode(data, recshape.CAARecord)
		rrs := make([]dns.RR, 0, len(recs))
		for _, rec := range recs {
			rrs = append(rrs, &dns.CAA{
				Hdr:   dns.RR_Header{Name: name, Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: rec.TTL},
				Flag:  rec.Flag,
				Tag:   rec.Tag,
				Value: rec.Value,
			})
		}
		return rrs
	},

	"SPF": func(name string, data any) []dns.RR {
		rec, ok := recshape.Single(data, recshape.SPFRecord)
		if !ok {
			return nil
		}
		return []dns.RR{&dns.SPF{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeSPF, Class: dns.ClassINET, Ttl: rec.TTL},
			Txt: chunkTXT(rec.Text),
		}}
	},

	"SOA": func(name string, data any) []dns.RR {
		rec, ok := recshape.Single(data, recshape.SOARecord)
		if !ok {
			return nil
		}
		return []dns.RR{&dns.SOA{
			Hdr:     dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: rec.TTL},
			Ns:      dns.Fqdn(rec.Ns),
			Mbox:    dns.Fqdn(rec.Mbox),
			Serial:  rec.Serial,
			Refresh: rec.Refresh,
			Retry:   rec.Retry,
			Expire:  rec.Expire,
			Minttl:  rec.Minimum,
		}}
	},

	"NSEC": func(name string, data any) []dns.RR {
		rec, ok := recshape.Single(data, recshape.NSECRecord)
		if !ok {
			return nil
		}
		return []dns.RR{&dns.NSEC{
			Hdr:        dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: rec.TTL},
			NextDomain: dns.Fqdn(rec.NextDomain),
			TypeBitMap: typeBitmap(rec.Types),
		}}
	},

	"NSEC3": func(name string, data any) []dns.RR {
		rec, ok := recshape.Single(data, recshape.NSEC3Record)
		if !ok || !validNSEC3Hash(rec.NextHashed) {
			return nil
		}
		return []dns.RR{&dns.NSEC3{
			Hdr:        dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: rec.TTL},
			Hash:       rec.HashAlg,
			Flags:      rec.Flags,
			Iterations: rec.Iterations,
			SaltLength: uint8(nsec3SaltLength(rec.Salt)),
			Salt:       rec.Salt,
			HashLength: uint8(nsec3HashLength(rec.NextHashed)),
			NextDomain: rec.NextHashed,
			TypeBitMap: typeBitmap(rec.Types),
		}}
	},

	"NSEC3PARAM": func(name string, data any) []dns.RR {
		rec, ok := recshape.Single(data, recshape.NSEC3ParamRecord)
		if !ok {
			return nil
		}
		return []dns.RR{&dns.NSEC3PARAM{
			Hdr:        dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeNSEC3PARAM, Class: dns.ClassINET, Ttl: rec.TTL},
			Hash:       rec.HashAlgorithm,
			Flags:      rec.Flags,
			Iterations: rec.Iterations,
			SaltLength: uint8(nsec3SaltLength(rec.Salt)),
			Salt:       rec.Salt,
		}}
	},

	"DNSKEY": func(name string, data any) []dns.RR {
		recs, _ := recshape.Decode(data, recshape.DNSKEYRecord)
		rrs := make([]dns.RR, 0, len(recs))
		for _, rec := range recs {
			rrs = append(rrs, &dns.DNSKEY{
				Hdr:       dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: rec.TTL},
				Flags:     rec.Flags,
				Protocol:  rec.Protocol,
				Algorithm: rec.Algorithm,
				PublicKey: rec.PublicKey,
			})
		}
		return rrs
	},

	"CDNSKEY": func(name string, data any) []dns.RR {
		recs, _ := recshape.Decode(data, recshape.CDNSKEYRecord)
		rrs := make([]dns.RR, 0, len(recs))
		for _, rec := range recs {
			rrs = append(rrs, &dns.CDNSKEY{DNSKEY: dns.DNSKEY{
				Hdr:       dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeCDNSKEY, Class: dns.ClassINET, Ttl: rec.TTL},
				Flags:     rec.Flags,
				Protocol:  rec.Protocol,
				Algorithm: rec.Algorithm,
				PublicKey: rec.PublicKey,
			}})
		}
		return rrs
	},

	"RRSIG": func(name string, data any) []dns.RR {
		var rrs []dns.RR
		slog.Crazy("[rrbuilder.go:RRBuilder] data for RSIG is: %+v", data)

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
			// <--- THIS CASE IS WHAT YOU ACTUALLY GET!
			for _, item := range v {
				switch rec := item.(type) {
				case *types.RRSIGRecord:
					rr, err := toDNSRRSIG(name, rec)
					if err == nil {
						rrs = append(rrs, rr)
					}
				case map[string]interface{}:
					// Defensive: convert to struct
					b, err := json.Marshal(rec)
					if err != nil {
						continue
					}
					var recObj types.RRSIGRecord
					if err := json.Unmarshal(b, &recObj); err != nil {
						continue
					}
					rr, err := toDNSRRSIG(name, &recObj)
					if err == nil {
						rrs = append(rrs, rr)
					}
				default:
					slog.Warn("[rrbuilder.go:RRBuilder] unknown type in []interface{}: %T", rec)
				}
			}
		case map[string][]*types.RRSIGRecord:
			for _, records := range v {
				for _, rec := range records {
					rr, err := toDNSRRSIG(name, rec)
					slog.Crazy("[rrbuilder.go:RRBuilder] rr for RSIG is: %+v", rr)
					if err == nil {
						rrs = append(rrs, rr)
					}
				}
			}
		default:
			slog.Warn("[rrbuilder.go:RRBuilder] unknown type for data: %T", v)
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
	zd.CDNSKEY = map[string][]types.CDNSKEYRecord{}
	zd.RRSIG = map[string][]*types.RRSIGRecord{}
	zd.DS = map[string][]types.DSRecord{}
	zd.CDS = map[string][]types.CDSRecord{}
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
			zd.TXT[name] = append(zd.TXT[name], types.TXTRecord{Text: strings.Join(v.Txt, ""), TTL: v.Hdr.Ttl})
		case *dns.SRV:
			zd.SRV[name] = append(zd.SRV[name], types.SRVRecord{Priority: v.Priority, Weight: v.Weight, Port: v.Port, Target: strings.TrimSuffix(v.Target, "."), TTL: v.Hdr.Ttl})
		case *dns.PTR:
			zd.PTR[name] = append(zd.PTR[name], types.PTRRecord{Ptr: strings.TrimSuffix(v.Ptr, "."), TTL: v.Hdr.Ttl})
		case *dns.CNAME:
			zd.CNAME[name] = types.CNAMERecord{Target: strings.TrimSuffix(v.Target, "."), TTL: v.Hdr.Ttl}
		case *dns.DNAME:
			zd.DNAME[name] = types.DNAMERecord{Target: strings.TrimSuffix(v.Target, "."), TTL: v.Hdr.Ttl}
		case *dns.CAA:
			zd.CAA[name] = append(zd.CAA[name], types.CAARecord{Flag: v.Flag, Tag: v.Tag, Value: v.Value, TTL: v.Hdr.Ttl})
		case *dns.SPF:
			zd.SPF[name] = types.SPFRecord{Text: strings.Join(v.Txt, ""), TTL: v.Hdr.Ttl}
		case *dns.DNSKEY:
			zd.DNSKEY[name] = append(zd.DNSKEY[name], types.DNSKEYRecord{
				Flags:     v.Flags,
				Protocol:  v.Protocol,
				Algorithm: v.Algorithm,
				PublicKey: v.PublicKey,
				TTL:       v.Hdr.Ttl,
			})
		case *dns.CDNSKEY:
			zd.CDNSKEY[name] = append(zd.CDNSKEY[name], types.CDNSKEYRecord{
				Flags:     v.Flags,
				Protocol:  v.Protocol,
				Algorithm: v.Algorithm,
				PublicKey: v.PublicKey,
				TTL:       v.Hdr.Ttl,
			})
		case *dns.DS:
			zd.DS[name] = append(zd.DS[name], types.DSRecord{
				KeyTag:     v.KeyTag,
				Algorithm:  v.Algorithm,
				DigestType: v.DigestType,
				Digest:     strings.ToUpper(v.Digest),
				TTL:        v.Hdr.Ttl,
			})
		case *dns.CDS:
			zd.CDS[name] = append(zd.CDS[name], types.CDSRecord{
				KeyTag:     v.KeyTag,
				Algorithm:  v.Algorithm,
				DigestType: v.DigestType,
				Digest:     strings.ToUpper(v.Digest),
				TTL:        v.Hdr.Ttl,
			})
		case *dns.RRSIG:
			// Use .TypeCovered to group RRSIGs for different RRsets
			covered := dns.TypeToString[v.TypeCovered]
			if covered == "" {
				covered = "UNKNOWN"
			}
			rec := &types.RRSIGRecord{
				Name:        name,
				TypeCovered: covered,
				Algorithm:   v.Algorithm,
				Labels:      v.Labels,
				OrigTTL:     v.OrigTtl,
				Expiration:  v.Expiration,
				Inception:   v.Inception,
				KeyTag:      v.KeyTag,
				SignerName:  v.SignerName,
				Signature:   v.Signature,
				TTL:         v.Hdr.Ttl,
			}
			zd.RRSIG[covered] = append(zd.RRSIG[covered], rec)

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

func typeBitmap(types []string) []uint16 {
	var bitmap []uint16
	for _, t := range types {
		if code, ok := dns.StringToType[strings.ToUpper(t)]; ok {
			bitmap = append(bitmap, code)
		}
	}
	sort.Slice(bitmap, func(i, j int) bool {
		return bitmap[i] < bitmap[j]
	})
	return bitmap
}

func validNSEC3Hash(value string) bool {
	return nsec3HashLength(value) > 0
}

func nsec3HashLength(value string) int {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" {
		return 0
	}
	decoded, err := base32.HexEncoding.WithPadding(base32.NoPadding).DecodeString(value)
	if err != nil {
		return 0
	}
	return len(decoded)
}

func nsec3SaltLength(value string) int {
	value = strings.TrimSpace(value)
	if value == "" || value == "-" {
		return 0
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return 0
	}
	return len(decoded)
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
