package dns

import (
	"github.com/miekg/dns"
	"go53/zone"
	"log"
)

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	for _, q := range r.Question {
		var answered bool
		answered = false

		switch q.Qtype {
		case dns.TypeA: //, dns.TypeAAAA:
			// 1) Försök direkt A/AAAA
			if rec, ok := zone.LookupRecord(q.Qtype, q.Name); ok {
				m.Answer = append(m.Answer, rec...)
				answered = true
				break
			}
			//2) Fallback: kolla CNAME
			if cnameRec, ok := zone.LookupRecord(dns.TypeCNAME, q.Name); ok {
				m.Answer = append(m.Answer, cnameRec[0])
				// 2a) och följ CNAME till slutmål
				target := cnameRec[0].(*dns.CNAME).Target
				if rec2, ok := zone.LookupRecord(q.Qtype, target); ok {
					m.Answer = append(m.Answer, rec2...)
				}
				answered = true
			}

		case dns.TypeCNAME, dns.TypeNS:
			if rec, ok := zone.LookupRecord(q.Qtype, q.Name); ok {
				log.Printf("Value in dns handler is: %v\n", rec)
				m.Answer = append(m.Answer, rec...)
				answered = true
			}

		default:
			// Andra typer (MX, TXT, osv) – generisk hantering
			if rec, ok := zone.LookupRecord(q.Qtype, q.Name); ok {
				m.Answer = append(m.Answer, rec...)
				answered = true
			}
		}

		if !answered {
			// Inget svar → Authority med SOA
			if soaRec, ok := zone.LookupRecord(dns.TypeSOA, q.Name); ok {
				m.Ns = append(m.Ns, soaRec...)
			}
		}
	}

	_ = w.WriteMsg(m)
}
