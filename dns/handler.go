package dns

import (
	"github.com/miekg/dns"
	"go53/zone"
	"log"
)

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	log.Printf("TEST")
	m := new(dns.Msg)
	m.SetReply(r)
	log.Printf("Query %s\n", r.Question[0].Name)

	for _, q := range r.Question {
		if rec, ok := zone.LookupRecord(q.Qtype, q.Name); ok && rec != nil {
			m.Answer = append(m.Answer, rec)
		} else {
			soaRec, ok := zone.LookupRecord(dns.TypeSOA, q.Name)
			log.Printf("soaRec: %v\n", soaRec)
			if ok && soaRec != nil {
				m.Ns = append(m.Ns, soaRec)
			}
		}
	}

	_ = w.WriteMsg(m)
}
