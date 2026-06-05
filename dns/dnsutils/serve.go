// This file is part of the go53 project.
//
// This file is licensed under the European Union Public License (EUPL) v1.2.
// You may only use this work in compliance with the License.
// You may obtain a copy of the License at:
//
//	https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed "as is",
// without any warranty or conditions of any kind.
//
// Copyleft (c) 2025 - Tenforward AB. All rights reserved.
//
// Created on 6/22/25 by andrek <andre(-at-)sess.se>
//
// This file: serve.go is part of the go53 authoritative DNS server.
package dnsutils

import (
	"github.com/miekg/dns"
	"go53/config"
	"go53/zone"
	"log"
	"time"
)

// ServeDNS handles incoming DNS requests and responds with AXFR (full zone transfer) data
// if the request is valid. It ensures the query is for a zone transfer (AXFR or IXFR),
// retrieves the corresponding zone data from memory, and streams the response in chunks
// that do not exceed the DNS message size limit.
//
// The function performs the following steps:
//   - Validates that the DNS request is non-nil and contains exactly one question.
//   - Verifies that the question type is either AXFR or IXFR.
//   - Retrieves the corresponding zone records from in-memory storage using `zone.LookupRecord`.
//   - Packs and sends records in DNS messages that do not exceed 61 KiB in size.
//   - Sends the final message if any records remain after the last chunk.
//   - Responds with SERVFAIL if the request is invalid or an error occurs.
//
// Parameters:
//   - w: The dns.ResponseWriter used to send the response.
//   - req: The incoming *dns.Msg representing the client's request.
//
// This function is intended for use in a DNS server supporting zone transfers.
func ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if req == nil || len(req.Question) != 1 {
		log.Println("req.Question error:", req)
		respondWithFailure(w, req)
		return
	}

	q := req.Question[0]
	//TODO: Do we need this extra check?
	if !(q.Qtype == dns.TypeAXFR || q.Qtype == dns.TypeIXFR) {
		log.Println("Q.type is not AXFR or IXFR:", q.Qtype)
		respondWithFailure(w, req)
		return
	}

	log.Println("Fetching zone from memory:", q.Name)
	rrs, ok := zone.LookupRecord(dns.TypeAXFR, q.Name)
	if !ok || len(rrs) < 2 {
		log.Println("zone not found or too few records")
		respondWithFailure(w, req)
		return
	}
	currentSOA, ok := firstSOA(rrs)
	if !ok {
		log.Println("zone transfer data missing SOA")
		respondWithFailure(w, req)
		return
	}

	const maxSize = 61 * 1024

	tsigKey := ""
	if req.IsTsig() != nil {
		if w.TsigStatus() == nil {
			tsigKey = req.Extra[len(req.Extra)-1].Header().Name
			log.Printf("TSIG validated, using key: %s", tsigKey)
		} else {
			log.Printf("TSIG present. Name: %s, Algorithm: %s", req.IsTsig().Hdr.Name, req.IsTsig().Algorithm)

			if config.AppConfig.GetLive().EnforceTSIG {
				log.Printf("TSIG validation failed and EnforceTSIG is enabled: %v", w.TsigStatus())
				respondWithFailure(w, req)
				return
			} else {
				log.Printf("TSIG validation failed but EnforceTSIG is disabled: ignoring error")
			}
		}
	} else if config.AppConfig.GetLive().EnforceTSIG {
		log.Println("TSIG required but not present")
		respondWithFailure(w, req)
		return
	}

	if q.Qtype == dns.TypeIXFR {
		clientSerial, ok := ixfrClientSerial(req)
		if !ok {
			log.Println("IXFR request missing client SOA in authority section")
			respondWithRcode(w, req, dns.RcodeFormatError)
			return
		}
		if !serialNewer(currentSOA.Serial, clientSerial) {
			log.Printf("IXFR client is up-to-date for %s: client=%d current=%d", q.Name, clientSerial, currentSOA.Serial)
			writeTransferMessage(w, req, []dns.RR{currentSOA}, tsigKey)
			return
		}
		log.Printf("IXFR journal unavailable for %s: client=%d current=%d; falling back to full zone transfer", q.Name, clientSerial, currentSOA.Serial)
	}

	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Answer = make([]dns.RR, 0, 10)

	for _, rr := range rrs {
		msg.Answer = append(msg.Answer, rr)

		packed, err := msg.Pack()
		if err != nil {
			log.Printf("Pack error: %v", err)
			respondWithFailure(w, req)
			return
		}

		if len(packed) > maxSize {
			msg.Answer = msg.Answer[:len(msg.Answer)-1]

			if config.AppConfig.GetLive().EnforceTSIG && tsigKey != "" {
				msg.SetTsig(tsigKey, dns.HmacSHA256, 300, time.Now().Unix())
			}

			if err := w.WriteMsg(msg); err != nil {
				log.Printf("Failed to send AXFR chunk: %v", err)
				return
			}

			msg = new(dns.Msg)
			msg.SetReply(req)
			msg.Answer = []dns.RR{rr}
		}
	}

	if len(msg.Answer) > 0 {
		if config.AppConfig.GetLive().EnforceTSIG && tsigKey != "" {
			msg.SetTsig(tsigKey, dns.HmacSHA256, 300, time.Now().Unix())
		}

		if err := w.WriteMsg(msg); err != nil {
			log.Printf("Failed to send final AXFR packet: %v", err)
		}
	}
}

func firstSOA(rrs []dns.RR) (*dns.SOA, bool) {
	for _, rr := range rrs {
		soa, ok := rr.(*dns.SOA)
		if ok {
			return soa, true
		}
	}
	return nil, false
}

func ixfrClientSerial(req *dns.Msg) (uint32, bool) {
	for _, rr := range req.Ns {
		soa, ok := rr.(*dns.SOA)
		if ok {
			return soa.Serial, true
		}
	}
	return 0, false
}

func serialNewer(current, client uint32) bool {
	return current != client && uint32(current-client) < 1<<31
}

func writeTransferMessage(w dns.ResponseWriter, req *dns.Msg, answer []dns.RR, tsigKey string) {
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Answer = answer
	if config.AppConfig.GetLive().EnforceTSIG && tsigKey != "" {
		msg.SetTsig(tsigKey, dns.HmacSHA256, 300, time.Now().Unix())
	}
	if err := w.WriteMsg(msg); err != nil {
		log.Printf("Failed to send transfer response: %v", err)
	}
}

// respondWithFailure sends a DNS response with RcodeServerFailure (SERVFAIL) to the client.
// It sets the Rcode in the response message appropriately, based on the incoming request.
//
// Parameters:
//   - w: The dns.ResponseWriter used to send the response.
//   - req: The original *dns.Msg request, may be nil.
func respondWithFailure(w dns.ResponseWriter, req *dns.Msg) {
	respondWithRcode(w, req, dns.RcodeServerFailure)
}

func respondWithRcode(w dns.ResponseWriter, req *dns.Msg, rcode int) {
	m := new(dns.Msg)
	if req != nil {
		m.SetRcode(req, rcode)
	} else {
		m.MsgHdr.Rcode = rcode
	}
	_ = w.WriteMsg(m)
}
