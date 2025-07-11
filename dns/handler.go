package dns

import (
	"github.com/miekg/dns"
	"go53/config"
	"go53/dns/dnsutils"
	"go53/security"
	"go53/zone"
	"log"
	"net"
	"strings"
)

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	log.Println("Incomming DNS request")
	live := config.AppConfig.GetLive()
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
			if _, ok := security.TSIGSecrets[tsig.Hdr.Name]; !ok {
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

		switch q.Qtype {
		case dns.TypeA:
			if rec, ok := zone.LookupRecord(q.Qtype, q.Name); ok {
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

		case dns.TypeCNAME, dns.TypeNS:
			if rec, ok := zone.LookupRecord(q.Qtype, q.Name); ok {
				m.Answer = append(m.Answer, rec...)
				answered = true
			}

		case dns.TypeAXFR, dns.TypeIXFR:
			// RFC 2845 §4.5: If TSIG is present, it MUST be validated. If not present, only require it if EnforceTSIG is true.
			tsig := r.IsTsig()
			enforceTSIG := config.AppConfig.GetLive().EnforceTSIG

			switch {
			case tsig != nil:
				// TSIG present: validate it
				if _, ok := security.TSIGSecrets[tsig.Hdr.Name]; !ok {
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
				m.Answer = append(m.Answer, rec...)
				answered = true
			}
		}

		if !answered {
			if soaRec, ok := zone.LookupRecord(dns.TypeSOA, q.Name); ok {
				m.Ns = append(m.Ns, soaRec...)
			}
		}
	}

	_ = w.WriteMsg(m)
}
