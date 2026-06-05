package dns

import (
	"github.com/TenforwardAB/slog"
	"github.com/miekg/dns"
	"go53/config"
	"go53/dns/dnsutils"
	"go53/internal"
	"go53/security"
	"go53/zone"
	"log"
	"net"
	"strings"
)

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	log.Println("Incomming DNS request")
	live := config.AppConfig.GetLive()
	opt := r.IsEdns0()
	wantsDNSSEC := config.AppConfig.GetLive().DNSSECEnabled && opt != nil && opt.Do()

	if r.Opcode == dns.OpcodeNotify && (live.Mode == "secondary" || live.Dev.DualMode) {
		remoteIP, _, err := net.SplitHostPort(w.RemoteAddr().String())
		if err != nil {
			log.Println("Invalid remote address:", w.RemoteAddr())
			return
		}

		if !strings.HasPrefix(remoteIP, live.Primary.Ip) {
			log.Println("Refusing NOTIFY from unknown IP:", remoteIP)
			return
		}

		tsig := r.IsTsig()
		enforceTSIG := live.EnforceTSIG

		switch {
		case tsig != nil:
			// TSIG is present — must be validated regardless of config is (RFC 2845  §4.6)
			if _, ok := security.GetTSIGKey(tsig.Hdr.Name); !ok {
				log.Printf("TSIG key not recognized: %s — rejecting", tsig.Hdr.Name)
				m := new(dns.Msg)
				m.SetRcode(r, dns.RcodeRefused)
				_ = w.WriteMsg(m)
				return
			}
			if w.TsigStatus() != nil {
				log.Printf("TSIG validation failed: %v", w.TsigStatus())
				m := new(dns.Msg)
				m.SetRcode(r, dns.RcodeRefused)
				_ = w.WriteMsg(m)
				return
			}
			log.Printf("TSIG validated. Key: %s", tsig.Hdr.Name)

		case tsig == nil && enforceTSIG:
			// TSIG is required but not present — reject per RFC 2845 §4.5
			log.Println("TSIG required but not present — rejecting")
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeRefused)
			_ = w.WriteMsg(m)
			return

		case tsig == nil && !enforceTSIG:
			// TSIG is not  required — continue (RFC 2845  §4.5)
			log.Println("TSIG not present, but not required — continuing")
		}

		dnsutils.HandleNotify(w, r)
		return
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	for _, q := range r.Question {
		var answered bool
		answered = false
		log.Println("Type is :", q.Qtype)

		if q.Qclass == dns.ClassCHAOS && q.Qtype == dns.TypeTXT && strings.ToLower(q.Name) == "version.bind." {
			version := live.Version
			if version != "" {
				txt := &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassCHAOS,
						Ttl:    0,
					},
					Txt: []string{version},
				}
				m.Answer = append(m.Answer, txt)
				answered = true
				continue
			}
		}

		if delegation, ns, ok := zone.DelegationFor(q.Name); ok && shouldReturnReferral(q, delegation) {
			m.Authoritative = false
			m.Ns = append(m.Ns, ns...)
			m.Extra = append(m.Extra, glueRecords(ns)...)
			answered = true
		}

		if answered {
			if wantsDNSSEC {
				slog.Crazy("Using DNSSEC")
				m.Answer = appendRRSIGs(m.Answer)
				m.Ns = appendRRSIGs(m.Ns)
			}
			continue
		}

		switch q.Qtype {
		case dns.TypeA:
			if rec, ok := zone.LookupRecord(q.Qtype, q.Name); ok {
				log.Println("A record found:", rec)
				m.Answer = append(m.Answer, rec...)
				answered = true
				break
			}
			if cnameRec, ok := zone.LookupRecord(dns.TypeCNAME, q.Name); ok {
				m.Answer = append(m.Answer, cnameRec[0])
				target := cnameRec[0].(*dns.CNAME).Target
				if rec2, ok := zone.LookupRecord(q.Qtype, target); ok {
					m.Answer = append(m.Answer, rec2...)
				}
				answered = true
			}

		case dns.TypeDNSKEY:
			zoneApex, _ := internal.SanitizeFQDN(q.Name) //TODO: manage error
			if rec, ok := zone.LookupRecord(dns.TypeDNSKEY, zoneApex); ok {
				log.Println("DNSKEY record found:", rec)
				m.Answer = append(m.Answer, rec...)
				answered = true
			} else {
				log.Println("DNSKEY record NOT FOUND OR ERROR:")
			}

		case dns.TypeCNAME, dns.TypeNS:
			if rec, ok := zone.LookupRecord(q.Qtype, q.Name); ok {
				m.Answer = append(m.Answer, rec...)
				answered = true
			}

		case dns.TypeAXFR, dns.TypeIXFR:
			if !live.AllowAXFR {
				log.Println("AXFR/IXFR disabled by configuration")
				m.SetRcode(r, dns.RcodeRefused)
				_ = w.WriteMsg(m)
				return
			}

			if !transferClientAllowed(w.RemoteAddr().String(), live.AllowTransfer) {
				log.Printf("AXFR/IXFR refused for unauthorized client %s", w.RemoteAddr().String())
				m.SetRcode(r, dns.RcodeRefused)
				_ = w.WriteMsg(m)
				return
			}

			// RFC 2845 §4.5: If TSIG is present, it MUST be validated. If not present, only require it if EnforceTSIG is true.
			tsig := r.IsTsig()
			enforceTSIG := config.AppConfig.GetLive().EnforceTSIG

			switch {
			case tsig != nil:
				// TSIG present: validate it
				if _, ok := security.GetTSIGKey(tsig.Hdr.Name); !ok {
					log.Printf("TSIG key not recognized: %s — rejecting", tsig.Hdr.Name)
					m.SetRcode(r, dns.RcodeRefused)
					_ = w.WriteMsg(m)
					return
				}
				if w.TsigStatus() != nil {
					log.Printf("TSIG validation failed: %v", w.TsigStatus())
					m.SetRcode(r, dns.RcodeRefused)
					_ = w.WriteMsg(m)
					return
				}
				log.Printf("TSIG validated for AXFR/IXFR. Key: %s", tsig.Hdr.Name)

			case tsig == nil && enforceTSIG:
				// TSIG required but missing
				log.Println("AXFR/IXFR request is not TSIG-signed — rejecting due to EnforceTSIG")
				m.SetRcode(r, dns.RcodeRefused)
				_ = w.WriteMsg(m)
				return

			case tsig == nil && !enforceTSIG:
				// TSIG not present and not required
				log.Println("AXFR/IXFR without TSIG — accepted due to EnforceTSIG=false")
			}

			// Delegate to ServeDNS
			dnsutils.ServeDNS(w, r)
			return

		case dns.TypeSRV:
			if rec, ok := zone.LookupRecord(dns.TypeSRV, q.Name); ok {
				log.Println("Getting SRV record: ", q.Name)
				m.Answer = append(m.Answer, rec...)
				answered = true
				break
			}
			if cnameRec, ok := zone.LookupRecord(dns.TypeCNAME, q.Name); ok {
				m.Answer = append(m.Answer, cnameRec[0])
				target := cnameRec[0].(*dns.CNAME).Target
				if rec2, ok := zone.LookupRecord(dns.TypeSRV, target); ok {
					m.Answer = append(m.Answer, rec2...)
				}
				answered = true
			}

		default:
			if rec, ok := zone.LookupRecord(q.Qtype, q.Name); ok {
				log.Println("Record found:", rec)
				m.Answer = append(m.Answer, rec...)
				answered = true
			}
		}

		if !answered {
			if rec, ok := lookupWildcard(q.Qtype, q.Name, wantsDNSSEC); ok {
				m.Answer = append(m.Answer, rec...)
				answered = true
			}
		}

		if !answered {
			nameFound := nameExists(q.Name)
			nxdomain := !nameFound && !zone.WildcardExists(q.Name)
			if nxdomain {
				m.Rcode = dns.RcodeNameError
			}
			if soaRec, ok := lookupApexSOA(q.Name); ok {
				m.Ns = append(m.Ns, soaRec...)
			}
			if wantsDNSSEC {
				m.Ns = append(m.Ns, denialRecords(q.Name, q.Qtype, nxdomain)...)
			}
		}

		if wantsDNSSEC {
			slog.Crazy("Using DNSSEC")
			m.Answer = appendRRSIGs(m.Answer)
			m.Ns = appendRRSIGs(m.Ns)
		}
	}

	_ = w.WriteMsg(m)
}

func appendRRSIGs(section []dns.RR) []dns.RR {
	seen := make(map[string]bool)
	for _, rr := range section {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			seen[rr.String()] = true
		}
	}

	covered := make(map[string]bool)
	for _, rr := range section {
		rrsig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		key := strings.ToLower(rrsig.Hdr.Name) + "|" + dns.TypeToString[rrsig.TypeCovered]
		covered[key] = true
	}

	rrsets := make(map[string][]dns.RR)
	for _, rr := range section {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			continue
		}
		hdr := rr.Header()
		key := strings.ToLower(hdr.Name) + "|" + dns.TypeToString[hdr.Rrtype]
		if covered[key] {
			continue
		}
		rrsets[key] = append(rrsets[key], rr)
	}

	for _, rrset := range rrsets {
		rrsigRecords, err := zone.EnsureSignedRRSet(rrset)
		if err != nil {
			slog.Warn("DNSSEC query-time signing failed: %v", err)
			continue
		}
		for _, sig := range rrsigRecords {
			rrsig, ok := sig.(*dns.RRSIG)
			if !ok {
				continue
			}
			key := rrsig.String()
			if seen[key] {
				continue
			}
			section = append(section, rrsig)
			seen[key] = true
		}
	}

	return section
}

func shouldReturnReferral(q dns.Question, delegation string) bool {
	if strings.EqualFold(q.Name, delegation) && q.Qtype == dns.TypeDS {
		return false
	}
	return true
}

func glueRecords(nsRecords []dns.RR) []dns.RR {
	var out []dns.RR
	seen := make(map[string]bool)
	for _, rr := range nsRecords {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		if !inBailiwickGlue(ns.Ns, ns.Hdr.Name) {
			continue
		}
		for _, rrtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			records, ok := zone.LookupRecord(rrtype, ns.Ns)
			if !ok {
				continue
			}
			for _, glue := range records {
				key := glue.String()
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, glue)
			}
		}
	}
	return out
}

func inBailiwickGlue(target, delegation string) bool {
	target = strings.ToLower(dns.Fqdn(target))
	delegation = strings.ToLower(dns.Fqdn(delegation))
	return target == delegation || strings.HasSuffix(target, "."+delegation)
}

func lookupWildcard(rrtype uint16, qname string, wantsDNSSEC bool) ([]dns.RR, bool) {
	if nameExists(qname) {
		return nil, false
	}
	wildcard, ok := zone.WildcardName(qname)
	if !ok {
		return nil, false
	}

	if rec, ok := zone.LookupRecord(rrtype, wildcard); ok {
		return synthesizeWildcard(qname, rec, wantsDNSSEC), true
	}
	if rrtype != dns.TypeCNAME {
		if rec, ok := zone.LookupRecord(dns.TypeCNAME, wildcard); ok {
			return synthesizeWildcard(qname, rec, wantsDNSSEC), true
		}
	}
	return nil, false
}

func synthesizeWildcard(qname string, wildcardRRSet []dns.RR, wantsDNSSEC bool) []dns.RR {
	var out []dns.RR
	for _, rr := range wildcardRRSet {
		copied := dns.Copy(rr)
		copied.Header().Name = dns.Fqdn(qname)
		out = append(out, copied)
	}

	if !wantsDNSSEC {
		return out
	}
	rrsigRecords, err := zone.EnsureSignedRRSet(wildcardRRSet)
	if err != nil {
		slog.Warn("DNSSEC wildcard signing failed: %v", err)
		return out
	}
	for _, sig := range rrsigRecords {
		rrsig, ok := dns.Copy(sig).(*dns.RRSIG)
		if !ok {
			continue
		}
		rrsig.Hdr.Name = dns.Fqdn(qname)
		out = append(out, rrsig)
	}
	return out
}

func lookupApexSOA(name string) ([]dns.RR, bool) {
	zoneName, _, ok := internal.SplitName(name)
	if !ok {
		return nil, false
	}
	apex, err := internal.SanitizeFQDN(zoneName)
	if err != nil {
		return nil, false
	}
	return zone.LookupRecord(dns.TypeSOA, apex)
}

func denialRecords(name string, qtype uint16, nxdomain bool) []dns.RR {
	return zone.DenialProofs(name, qtype, nxdomain)
}

func nameExists(name string) bool {
	return zone.NameExists(name)
}

func transferClientAllowed(remoteAddr string, allowTransfer string) bool {
	allowTransfer = strings.TrimSpace(allowTransfer)
	if allowTransfer == "" {
		return true
	}

	remoteIP, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		remoteIP = remoteAddr
	}
	remote := net.ParseIP(remoteIP)
	if remote == nil {
		return false
	}

	for _, entry := range strings.Split(allowTransfer, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if ip := net.ParseIP(entry); ip != nil {
			if ip.Equal(remote) {
				return true
			}
			continue
		}

		if ip, _, err := net.SplitHostPort(entry); err == nil {
			if parsed := net.ParseIP(ip); parsed != nil && parsed.Equal(remote) {
				return true
			}
		}
	}

	return false
}
