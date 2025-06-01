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
            if record := zone.LookupA(q.Name); record != nil {
                m.Answer = append(m.Answer, record)
            }
        }
    }
    w.WriteMsg(m)
}
