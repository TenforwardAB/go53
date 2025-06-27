package dnsutils

import (
	"fmt"
	"go53/config"
	"go53/internal"
	"go53/security"
	"go53/zone"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

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

var (
	checkSOAFunc  = checkSOA
	fetchZoneFunc = fetchZone
)

// ScheduleNotify schedules a DNS NOTIFY message for the specified zone.
// It uses a debounce timer to prevent repeated notifications within a short
// time window, based on the NotifyDebounceMs configuration.
//
// If a notification is already pending for the zone, the function does nothing.
//
// Parameters:
//   - zone: The zone name for which a NOTIFY message should be sent.
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

// SendNotify sends a DNS NOTIFY message for the given zone to all
// configured transfer targets. It tries UDP first and falls back to TCP
// if the UDP attempt fails. Each target is notified asynchronously.
//
// Parameters:
//   - inzone: The raw zone name (which will be sanitized before use).
func SendNotify(inzone string) {
	szone, err := internal.SanitizeFQDN(inzone)
	if err != nil {
		log.Printf("warning: failed to sanitize FQDN: %v", err)
	}
	targets := strings.Split(config.AppConfig.GetLive().AllowTransfer, ",")
	enforceTSIG := config.AppConfig.GetLive().EnforceTSIG

	const tsigKeyName = "xxfr-key" //TODO: We have this set in too many locations need a central place for all constants
	fqdnKeyName := dns.Fqdn(tsigKeyName)
	tsigKey, tsigExists := security.TSIGSecrets[fqdnKeyName]

	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		addr := target
		if !strings.Contains(addr, ":") {
			addr += ":53"
		}

		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			log.Printf("SendNotify: invalid address format '%s': %v", addr, err)
			continue
		}
		if ip := net.ParseIP(host); ip == nil {
			log.Printf("SendNotify: invalid IP address '%s'", host)
			continue
		}

		go func(addr string) {
			m := new(dns.Msg)
			m.SetNotify(szone)
			m.RecursionDesired = false

			// Optional: sign with TSIG
			var tsigSecrets map[string]string
			if enforceTSIG && tsigExists {
				m.SetTsig(fqdnKeyName, dns.HmacSHA256, 300, time.Now().Unix())
				tsigSecrets = map[string]string{fqdnKeyName: tsigKey.Secret}
			}

			udpClient := &dns.Client{
				Net:        "udp",
				Timeout:    3 * time.Second,
				TsigSecret: tsigSecrets,
			}

			_, _, err := udpClient.Exchange(m, addr)
			log.Println("Zone is: ", szone)
			if err == nil {
				log.Printf("SendNotify: successfully notified %s for zone %s over UDP", addr, szone)
				return
			}

			log.Printf("SendNotify: UDP notify to %s failed: %v — retrying over TCP", addr, err)

			tcpClient := &dns.Client{
				Net:        "tcp",
				Timeout:    5 * time.Second,
				TsigSecret: tsigSecrets,
			}

			_, _, err = tcpClient.Exchange(m, addr)
			if err != nil {
				log.Printf("SendNotify: TCP notify to %s for zone %s also failed: %v", addr, szone, err)
			} else {
				log.Printf("SendNotify: successfully notified %s for zone %s over TCP", addr, szone)
			}
		}(addr)
	}
}

// HandleNotify processes an incoming DNS NOTIFY message.
// If the message contains a valid question, it extracts the zone name
// and triggers a background fetch for that zone via `handleNotify`.
//
// Parameters:
//   - w: dns.ResponseWriter used to send the response.
//   - r: The received *dns.Msg containing the NOTIFY message.
func HandleNotify(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	log.Println("Notify recieved")

	if len(r.Question) == 0 {
		m.SetRcode(r, dns.RcodeFormatError)
		_ = w.WriteMsg(m)
		return
	}

	zoneName := r.Question[0].Name

	log.Printf("Received NOTIFY for zone %s from %s", zoneName, w.RemoteAddr().String())

	handleNotify(zoneName)

	m.SetRcode(r, dns.RcodeSuccess)
	_ = w.WriteMsg(m)
}

// localZoneSerial retrieves the local SOA serial number for a given zone.
// It sanitizes the input FQDN, performs a lookup, and extracts the serial
// from the first SOA record if found.
//
// Returns:
//   - uint32: The local SOA serial number (0 if not found).
//   - error:  An error if the lookup or type assertion fails.
//
// Parameters:
//   - lzone: The raw zone name to check.
func localZoneSerial(lzone string) (uint32, error) {
	zoneName, err := internal.SanitizeFQDN(lzone)
	if err != nil {
		return 0, fmt.Errorf("zone %q validation failed: %w", lzone, err)
	}

	rrs, ok := zone.LookupRecord(dns.TypeSOA, zoneName)
	if !ok || len(rrs) == 0 {
		return 0, nil
	}

	// RFC 1034 - A zone contains exactly one SOA record.
	// (Section 4.3.4 — Start Of Authority)
	//  RFC 1035 - Every zone has a single origin node, and the database at the origin node must include an SOA record.
	// (Section 5.2 — Zone Maintenance)
	if soa, ok := rrs[0].(*dns.SOA); ok {
		return soa.Serial, nil
	}

	return 0, fmt.Errorf("unexpected record type for %q: %T", zoneName, rrs[0])
}

// checkSOA compares the SOA serial number of a zone from the primary DNS server
// with the local zone's SOA serial. It determines if the primary has a newer version.
//
// Returns true if the primary serial is higher (indicating an update is available),
// or false if the serials are equal, missing, or if an error occurs.
//
// Parameters:
//   - zone: The zone name to check.
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

// handleNotify updates the state for a zone upon receiving a NOTIFY.
// It ensures at least 10 seconds have passed since the last fetch and that no
// fetch is currently pending. If eligible, the zone is queued for background fetching.
//
// Parameters:
//   - zone: The zone name received in the NOTIFY message.
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

// fetchZone performs a full AXFR (zone transfer) for the specified zone
// from the configured primary DNS server. If the transfer is successful,
// the resulting records are imported into the system.
//
// This function logs the outcome and any errors encountered during transfer
// or record import.
//
// Parameters:
//   - zoneName: The name of the zone to fetch.
func fetchZone(zoneName string) {
	live := config.AppConfig.GetLive()
	primaryIP := live.Primary.Ip
	port := live.Primary.Port
	if port == 0 {
		port = 53
	}
	addr := net.JoinHostPort(primaryIP, strconv.Itoa(port))

	req := new(dns.Msg)
	req.SetAxfr(dns.Fqdn(zoneName))

	tsigKeyName := dns.Fqdn("xxfr-key")

	tran := &dns.Transfer{
		DialTimeout:  5 * time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	if config.AppConfig.GetLive().EnforceTSIG {
		tsigSecret := security.TSIGSecrets[tsigKeyName].Secret

		req.SetTsig(tsigKeyName, dns.HmacSHA256, 300, time.Now().Unix())
		tran.TsigSecret = map[string]string{
			tsigKeyName: tsigSecret,
		}
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
	log.Printf("[fetchZone] AXFR returned the records: %+v", records)

	err = ImportRecords("", zoneName, records)
	if err != nil {
		log.Println("[fetchZone] error importing AXFR records: ", err)
		return
	}

	log.Printf("[fetchZone] got %d records for %s", len(records), zoneName)
}

// ProcessFetchQueue starts an infinite loop to process zone fetches
// from the `fetchQueue` channel. For each zone, it launches a goroutine
// that checks if an update is required using `checkSOA`, and if so,
// performs an AXFR via `fetchZone`. It respects `Dev.DualMode` as an override.
//
// This function is intended to run as a background worker.

func ProcessFetchQueue() {
	for izone := range fetchQueue {
		go func(zone string) {
			defer func() {
				if state, ok := zoneStates[zone]; ok {
					state.pending = false
				}
			}()
			if checkSOAFunc(zone) || config.AppConfig.GetLive().Dev.DualMode {
				fetchZoneFunc(zone)
				if state, ok := zoneStates[zone]; ok {
					state.lastFetch = time.Now()
				}
			}
		}(izone)
	}
}
