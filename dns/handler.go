package dns

import (
	"github.com/miekg/dns"
	"go53/config"
	"go53/dns/dnsutils"
	"go53/zone"
	"log"
	"net"
	"strings"
)

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	if r.Opcode == dns.OpcodeNotify && (config.AppConfig.GetLive().Mode == "secondary" ||
		config.AppConfig.GetLive().Dev.DualMode) {
		dnsutils.HandleNotify(w, r)
		return
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	for _, q := range r.Question {
		var answered bool
		answered = false

		if q.Qclass == dns.ClassCHAOS && q.Qtype == dns.TypeTXT && strings.ToLower(q.Name) == "version.bind." {
			version := config.AppConfig.GetLive().Version
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
			// Only over TCP and only on secondaries
			if _, tcp := w.RemoteAddr().(*net.TCPAddr); !tcp {
				m.SetRcode(r, dns.RcodeRefused)
				_ = w.WriteMsg(m)
				return
			}
			if config.AppConfig.GetLive().Mode != "secondary" && !config.AppConfig.GetLive().Dev.DualMode {
				m.SetRcode(r, dns.RcodeNotImplemented)
				_ = w.WriteMsg(m)
				return
			}
			//serveAXFR(w, r, q.Name)
			log.Println("Serve AXFR here")
			return

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
