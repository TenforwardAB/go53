package dnsutils

import (
	"fmt"
	"go53/config"
	"go53/internal"
	"go53/zone"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var lookupZoneRecord = zone.LookupRecord

type notifyState struct {
	lastNotify    time.Time
	debounceTimer *time.Timer
	pending       bool
}

type zoneState struct {
	pending   bool
	lastFetch time.Time
}

var notifyStates = make(map[string]*notifyState)

var zoneStates = make(map[string]*zoneState)
var fetchQueue = make(chan string, 100)

func ScheduleNotify(zone string) {
	state, ok := notifyStates[zone]
	if !ok {
		state = &notifyState{}
		notifyStates[zone] = state
	}

	if state.pending {
		return
	}

	state.pending = true

	state.debounceTimer = time.AfterFunc(time.Duration(
		config.AppConfig.GetLive().Primary.NotifyDebounceMs)*time.Millisecond, func() {
		SendNotify(zone)
		state.lastNotify = time.Now()
		state.pending = false
	})
}

func SendNotify(inzone string) {
	szone, err := internal.SanitizeFQDN(inzone)
	if err != nil {
		log.Printf("warning: failed to sanitize FQDN: %v", err)
	}
	targets := strings.Split(config.AppConfig.GetLive().AllowTransfer, ",")
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
			m.SetNotify(szone)
			m.RecursionDesired = false

			udpClient := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
			_, _, err := udpClient.Exchange(m, addr)
			log.Println("Zone is: ", szone)
			if err == nil {
				log.Printf("SendNotify: successfully notified %s for zone %s over UDP", addr, szone)
				return
			}

			log.Printf("SendNotify: UDP notify to %s failed: %v — retrying over TCP", addr, err)

			tcpClient := &dns.Client{Net: "tcp", Timeout: 5 * time.Second}
			_, _, err = tcpClient.Exchange(m, addr)
			if err != nil {
				log.Printf("SendNotify: TCP notify to %s for zone %s also failed: %v", addr, szone, err)
			} else {
				log.Printf("SendNotify: successfully notified %s for zone %s over TCP", addr, szone)
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

	handleNotify(zoneName)

	m.SetRcode(r, dns.RcodeSuccess)
	_ = w.WriteMsg(m)
}

func localZoneSerial(lzone string) (uint32, error) {
	zoneName, err := internal.SanitizeFQDN(lzone)
	if err != nil {
		return 0, fmt.Errorf("zone %q validation failed: %w", lzone, err)
	}

	rrs, ok := zone.LookupRecord(dns.TypeSOA, zoneName)
	if !ok || len(rrs) == 0 {
		return 0, fmt.Errorf("zone %q not loaded locally", lzone)
	}

	// The first RR is SOA since only ONE SOA can exsist for each zone
	if soa, ok := rrs[0].(*dns.SOA); ok {
		return soa.Serial, nil
	}

	return 0, fmt.Errorf("unexpected record type for %q: %T", zoneName, rrs[0])
}

func checkSOA(zone string) bool {

	primaryIP := config.AppConfig.GetLive().Primary.Ip
	addr := net.JoinHostPort(primaryIP, strconv.Itoa(config.AppConfig.GetLive().Primary.Port))

	// 2) build the query
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeSOA)
	m.RecursionDesired = false

	c := &dns.Client{
		Timeout: 3 * time.Second,
	}

	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		log.Printf("[checkSOA] lookup %s SOA on %s: %v", zone, addr, err)
		return false
	}

	var primarySerial uint32
	for _, ans := range resp.Answer {
		if soa, ok := ans.(*dns.SOA); ok {
			primarySerial = soa.Serial
			break
		}
	}
	if primarySerial == 0 {
		log.Printf("[checkSOA] no SOA in answer for %s from %s", zone, addr)
		return false
	}

	localSerial, err := localZoneSerial(zone)
	if err != nil {
		log.Printf("[checkSOA] cannot read local serial for %s: %v", zone, err)
		return false
	}

	log.Printf("[checkSOA] %s primary=%d local=%d", zone, primarySerial, localSerial)
	return primarySerial > localSerial
}

func handleNotify(zone string) {
	state, ok := zoneStates[zone]
	if !ok {
		state = &zoneState{}
		zoneStates[zone] = state
	}
	if state.pending || time.Since(state.lastFetch) < 10*time.Second {
		return
	}
	state.pending = true
	fetchQueue <- zone
}

func fetchZone(zoneName string) {
	live := config.AppConfig.GetLive()
	primaryIP := live.Primary.Ip
	port := live.Primary.Port
	if port == 0 {
		port = 53
	}
	addr := net.JoinHostPort(primaryIP, strconv.Itoa(port))

	// Prepare the AXFR request
	req := new(dns.Msg)
	req.SetAxfr(dns.Fqdn(zoneName))

	// Set up a Transfer; it will dial over TCP automatically for AXFR.
	tran := &dns.Transfer{
		DialTimeout:  5 * time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	log.Printf("[fetchZone] starting AXFR of %s from %s", zoneName, addr)
	envCh, err := tran.In(req, addr)
	if err != nil {
		log.Printf("[fetchZone] error initiating AXFR: %v", err)
		return
	}

	var records []dns.RR
	for env := range envCh {
		if env.Error != nil {
			log.Printf("[fetchZone] AXFR error for %s: %v", zoneName, env.Error)
			return
		}
		records = append(records, env.RR...)
	}

	log.Printf("[fetchZone] AXFR returned %d records", len(records))
	log.Printf("[fetchZone] AXFR returned the records", records)

	log.Printf("[fetchZone] got %d records for %s", len(records), zoneName)

	// Now update your in-memory zone store
	//if err := zone.LoadZoneFromRecords(zoneName, records); err != nil {
	//	log.Printf("[fetchZone] failed to load zone %s: %v", zoneName, err)
	//} else {
	//	log.Printf("[fetchZone] zone %s updated successfully", zoneName)
	//}
}

func ProcessFetchQueue() {
	for zone := range fetchQueue {
		go func(zone string) {
			defer func() {
				zoneStates[zone].pending = false
			}()
			if checkSOA(zone) {
				fetchZone(zone) // do AXFR via config.Primary.Ip
				zoneStates[zone].lastFetch = time.Now()
			}
		}(zone)
	}
}
