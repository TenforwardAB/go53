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
			log.Println("Type is:", q.Qtype)

			// Only allow AXFR/IXFR over TCP
			if _, tcp := w.RemoteAddr().(*net.TCPAddr); !tcp {
				log.Println("Request is NOT over TCP")
				m.SetRcode(r, dns.RcodeRefused)
				_ = w.WriteMsg(m)
				return
			}

			// Allow AXFR only from primary or replication mode (or dual-mode if configured)
			if !(live.Mode == "primary" || live.Mode == "replication" || live.Dev.DualMode) {
				log.Println("AXFR refused: not in primary/replication/dual mode (current mode:", live.Mode, ")")
				m.SetRcode(r, dns.RcodeRefused)
				_ = w.WriteMsg(m)
				return
			}

			log.Println("Sending AXFR to client")
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
