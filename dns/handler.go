package dns

import (
	"github.com/miekg/dns"
	"go53/zone"
)

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	for _, q := range r.Question {
		switch q.Qtype {
		case dns.TypeA:
			if rec := zone.LookupA(q.Name); rec != nil {
				m.Answer = append(m.Answer, rec)
			}
		case dns.TypeAAAA:
			if rec := zone.LookupAAAA(q.Name); rec != nil {
				m.Answer = append(m.Answer, rec)
			}
		case dns.TypeMX:
			if recs := zone.LookupMX(q.Name); recs != nil {
				for _, r := range recs {
					m.Answer = append(m.Answer, r)
				}
			}
		case dns.TypeTXT:
			if recs := zone.LookupTXT(q.Name); recs != nil {
				for _, r := range recs {
					m.Answer = append(m.Answer, r)
				}
			}
		case dns.TypeCNAME:
			if rec := zone.LookupCNAME(q.Name); rec != nil {
				m.Answer = append(m.Answer, rec)
			}
		case dns.TypeDNAME:
			if rec := zone.LookupDNAME(q.Name); rec != nil {
				m.Answer = append(m.Answer, rec)
			}
		case dns.TypePTR:
			if rec := zone.LookupPTR(q.Name); rec != nil {
				m.Answer = append(m.Answer, rec)
			}
		case dns.TypeNS:
			if recs := zone.LookupNS(q.Name); recs != nil {
				for _, r := range recs {
					m.Answer = append(m.Answer, r)
				}
			}
		case dns.TypeSOA:
			if rec := zone.LookupSOA(q.Name); rec != nil {
				m.Answer = append(m.Answer, rec)
			}
		}
	}

	_ = w.WriteMsg(m)
}
