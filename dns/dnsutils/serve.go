package dnsutils

import (
	"github.com/miekg/dns"
	"go53/zone"
	"log"
)

func ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if req == nil || len(req.Question) != 1 {
		log.Println("req.Question error:", req)
		respondWithFailure(w, req)
		return
	}

	q := req.Question[0]
	if q.Qtype != dns.TypeAXFR {
		log.Println("Q.type is not dns.TypeAXFR: ", q.Qtype)
		respondWithFailure(w, req)
		return
	}

	log.Println("Fetching Zone from memory")
	rrs, ok := zone.LookupRecord(dns.TypeAXFR, q.Name)
	log.Println("Raw zone data is::: ", rrs)
	if !ok || len(rrs) < 2 {
		log.Println("zone not found or too few records")
		respondWithFailure(w, req)
		return
	}

	const maxSize = 61 * 1024 // 61 KiB for safety

	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Answer = make([]dns.RR, 0, 10)

	for _, rr := range rrs {
		msg.Answer = append(msg.Answer, rr)

		// Try to pack and check size
		packed, err := msg.Pack()
		if err != nil {
			log.Printf("Pack error: %v", err)
			respondWithFailure(w, req)
			return
		}

		if len(packed) > maxSize {
			// remove last rr, send, then start new msg
			msg.Answer = msg.Answer[:len(msg.Answer)-1]
			if err := w.WriteMsg(msg); err != nil {
				log.Printf("Failed to send AXFR packet: %v", err)
				return
			}

			// Start new msg with current rr
			msg = new(dns.Msg)
			msg.SetReply(req)
			msg.Answer = []dns.RR{rr}
		}
	}

	// Send final message
	if len(msg.Answer) > 0 {
		if err := w.WriteMsg(msg); err != nil {
			log.Printf("Failed to send final AXFR packet: %v", err)
		}
	}
}

func respondWithFailure(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	if req != nil {
		m.SetRcode(req, dns.RcodeServerFailure)
	} else {
		m.MsgHdr.Rcode = dns.RcodeServerFailure
	}
	_ = w.WriteMsg(m)
}
