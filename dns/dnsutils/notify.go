package dnsutils

import (
	"log"
	"strings"
	"time"

	"github.com/miekg/dns"

	"go53/zone"
)

var lookupZoneRecord = zone.LookupRecord

func SendNotify(zone string, targets []string) {
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		go func(addr string) {
			if !strings.Contains(addr, ":") {
				addr += ":53"
			}

			m := new(dns.Msg)
			m.SetNotify(zone)
			m.RecursionDesired = false

			udpClient := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
			_, _, err := udpClient.Exchange(m, addr)
			if err == nil {
				log.Printf("SendNotify: successfully notified %s for zone %s over UDP", addr, zone)
				return
			}

			log.Printf("SendNotify: UDP notify to %s failed: %v — retrying over TCP", addr, err)

			tcpClient := &dns.Client{Net: "tcp", Timeout: 5 * time.Second}
			_, _, err = tcpClient.Exchange(m, addr)
			if err != nil {
				log.Printf("SendNotify: TCP notify to %s for zone %s also failed: %v", addr, zone, err)
			} else {
				log.Printf("SendNotify: successfully notified %s for zone %s over TCP", addr, zone)
			}
		}(target)
	}
}

func HandleNotify(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	if len(r.Question) == 0 {
		m.SetRcode(r, dns.RcodeFormatError)
		_ = w.WriteMsg(m)
		return
	}

	zoneName := r.Question[0].Name

	// RFC 1034 - A zone contains exactly one SOA record.
	// (Section 4.3.4 — Start Of Authority)
	//  RFC 1035 - Every zone has a single origin node, and the database at the origin node must include an SOA record.
	// (Section 5.2 — Zone Maintenance)
	_, exists := lookupZoneRecord(dns.TypeSOA, zoneName)
	if !exists {
		m.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(m)
		return
	}

	log.Printf("Received NOTIFY for zone %s from %s", zoneName, w.RemoteAddr().String())

	//TODO: RELOAD ZONE FROM PRIMARY IF SECONDARY

	m.SetRcode(r, dns.RcodeSuccess)
	_ = w.WriteMsg(m)
}
