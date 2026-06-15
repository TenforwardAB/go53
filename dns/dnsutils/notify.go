package dnsutils

import (
	"context"
	"fmt"
	"go53/config"
	"go53/internal"
	"go53/security"
	"go53/zone"
	"go53/zone/rtypes"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
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

// stateMu guards both notifyStates and zoneStates. Multiple producers feed the
// fetch pipeline concurrently (incoming NOTIFY handlers, the startup sweep, and the
// periodic refresh ticker), so all access to these maps must be serialized.
var stateMu sync.Mutex

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
	stateMu.Lock()
	state, ok := notifyStates[zone]
	if !ok {
		state = &notifyState{}
		notifyStates[zone] = state
	}

	if state.pending {
		stateMu.Unlock()
		return
	}

	state.pending = true
	stateMu.Unlock()

	debounce := time.Duration(config.AppConfig.GetLive().Primary.NotifyDebounceMs) * time.Millisecond
	state.debounceTimer = time.AfterFunc(debounce, func() {
		SendNotify(zone)
		stateMu.Lock()
		state.lastNotify = time.Now()
		state.pending = false
		stateMu.Unlock()
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
	fqdnKeyName, _ := internal.SanitizeFQDN(tsigKeyName)
	tsigKey, tsigExists := security.GetTSIGKey(fqdnKeyName)

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
	for _, primary := range transferPrimariesForZone(zone) {
		if checkSOAFromPrimary(zone, primary) {
			return true
		}
	}
	return false
}

func checkSOAFromPrimary(zone string, primary catalogPrimary) bool {
	addr := primary.addr()

	// 2) build the query
	m := new(dns.Msg)
	fqdn, _ := internal.SanitizeFQDN(zone)
	m.SetQuestion(fqdn, dns.TypeSOA)
	m.RecursionDesired = false

	c := &dns.Client{
		Timeout: 3 * time.Second,
	}
	if !applyTransferTSIG(m, c, primary, "[checkSOA]") {
		return false
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

// enqueueFetch applies the per-zone pending guard and secondary.min_fetch_interval_sec
// rate-limit under stateMu, then submits the zone to fetchQueue for a background AXFR.
// It is the single producer path shared by NOTIFY, the startup sweep, and the periodic
// refresh ticker, so they all share identical rate-limiting and the pending guard.
//
// The zone name is normalized to a sanitized FQDN so producers using different name
// forms (NOTIFY question names vs. ZoneNamesSnapshot keys) map to the same zoneStates
// entry. The channel send happens OUTSIDE the lock and never blocks; a full queue
// rolls back pending so later NOTIFY/sweeps can retry the zone.
//
// Returns true if the zone was enqueued.
func enqueueFetch(zone string) bool {
	z, err := internal.SanitizeFQDN(zone)
	if err != nil || z == "" {
		return false
	}
	stateMu.Lock()
	state, ok := zoneStates[z]
	if !ok {
		state = &zoneState{}
		zoneStates[z] = state
	}
	minInterval := time.Duration(config.AppConfig.GetLive().Secondary.MinFetchIntervalSec) * time.Second
	if state.pending || (minInterval > 0 && time.Since(state.lastFetch) < minInterval) {
		stateMu.Unlock()
		return false
	}
	state.pending = true
	stateMu.Unlock()

	select {
	case fetchQueue <- z:
		return true
	default:
		stateMu.Lock()
		if state, ok := zoneStates[z]; ok {
			state.pending = false
		}
		stateMu.Unlock()
		return false
	}
}

func EnqueueZoneFetch(zone string) bool {
	return enqueueFetch(zone)
}

// handleNotify is the NOTIFY fast-path entry point. It delegates to enqueueFetch so
// the rate-limit and pending guard are identical across all producers.
//
// Parameters:
//   - zone: The zone name received in the NOTIFY message.
func handleNotify(zone string) {
	enqueueFetch(zone)
}

// fetchZone performs a full AXFR (zone transfer) for the specified zone
// from the configured primary DNS server. If the transfer is successful,
// the resulting records are imported into the system.
//
// This function logs the outcome and any errors encountered during transfer
// or record import. It returns true only after a successful import.
//
// Parameters:
//   - zoneName: The name of the zone to fetch.
func fetchZone(zoneName string) bool {
	for _, primary := range transferPrimariesForZone(zoneName) {
		if fetchZoneFromPrimary(zoneName, primary) {
			return true
		}
	}
	return false
}

func fetchZoneFromPrimary(zoneName string, primary catalogPrimary) bool {
	addr := primary.addr()
	req := new(dns.Msg)
	fqdn, _ := internal.SanitizeFQDN(zoneName)
	req.SetAxfr(fqdn)

	tran := &dns.Transfer{
		DialTimeout:  5 * time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	if !applyTransferTSIG(req, tran, primary, "[fetchZone]") {
		return false
	}

	log.Printf("[fetchZone] starting AXFR of %s from %s", zoneName, addr)
	envCh, err := tran.In(req, addr)
	if err != nil {
		log.Printf("[fetchZone] error initiating AXFR: %v", err)
		return false
	}

	var records []dns.RR
	for env := range envCh {
		if env.Error != nil {
			log.Printf("[fetchZone] AXFR error for %s: %v", zoneName, env.Error)
			return false
		}
		records = append(records, env.RR...)
	}

	log.Printf("[fetchZone] AXFR returned %d records", len(records))
	log.Printf("[fetchZone] AXFR returned the records: %+v", records)

	var oldCatalogMembers, newCatalogMembers []string
	if catalog, ok := catalogZoneName(); ok && fqdn == catalog {
		oldCatalogMembers = catalogMembers()
		newCatalogMembers = catalogMembersFromRecords(records, catalog)
	}

	err = ImportRecords("", zoneName, records)
	if err != nil {
		log.Println("[fetchZone] error importing AXFR records: ", err)
		return false
	}
	if oldCatalogMembers != nil {
		pruneRemovedCatalogMembers(oldCatalogMembers, newCatalogMembers)
	}

	log.Printf("[fetchZone] got %d records for %s", len(records), zoneName)
	return true
}

func applyTransferTSIG(msg *dns.Msg, target any, primary catalogPrimary, logPrefix string) bool {
	tsigKeyName := primary.TSIGKeyName
	if tsigKeyName == "" && config.AppConfig.GetLive().EnforceTSIG {
		tsigKeyName, _ = internal.SanitizeFQDN("xxfr-key")
	}
	if tsigKeyName == "" {
		return true
	}
	tsigKey, ok := security.GetTSIGKey(tsigKeyName)
	if !ok {
		log.Printf("%s TSIG key %s is not loaded", logPrefix, tsigKeyName)
		return false
	}
	algorithm := dns.CanonicalName(tsigKey.Algorithm)
	if algorithm == "." {
		algorithm = dns.HmacSHA256
	}
	msg.SetTsig(tsigKeyName, algorithm, 300, time.Now().Unix())
	switch t := target.(type) {
	case *dns.Client:
		t.TsigSecret = map[string]string{tsigKeyName: tsigKey.Secret}
	case *dns.Transfer:
		t.TsigSecret = map[string]string{tsigKeyName: tsigKey.Secret}
	default:
		log.Printf("%s unsupported TSIG target %T", logPrefix, target)
		return false
	}
	return true
}

func transferPrimariesForZone(zoneName string) []catalogPrimary {
	if primaries, found := catalogPrimariesForZoneWithPresence(zoneName); found {
		return primaries
	}
	live := config.AppConfig.GetLive()
	if strings.TrimSpace(live.Primary.Ip) == "" {
		return nil
	}
	port := live.Primary.Port
	if port == 0 {
		port = 53
	}
	return []catalogPrimary{{IP: live.Primary.Ip, Port: port}}
}

func hasTransferPrimaryForZone(zoneName string, live config.LiveConfig) bool {
	if primaries, found := catalogPrimariesForZoneWithPresence(zoneName); found {
		return len(primaries) > 0
	}
	return strings.TrimSpace(live.Primary.Ip) != ""
}

// ProcessFetchQueue starts an infinite loop to process zone fetches
// from the `fetchQueue` channel. For each zone, it launches a goroutine
// that checks if an update is required using `checkSOA`, and if so,
// performs an AXFR via `fetchZone`.
//
// This function is intended to run as a background worker.

func ProcessFetchQueue() {
	maxParallel := config.AppConfig.GetLive().Secondary.MaxParallelFetches
	if maxParallel <= 0 {
		maxParallel = 5 // sane default when 0/unset
	}
	// Bounded semaphore enforcing Secondary.MaxParallelFetches. The slot is acquired in
	// the dispatch loop (not inside the goroutine) so a full pool also throttles draining
	// of fetchQueue — real backpressure. Sized once: a channel cannot be resized live, so
	// changing the limit requires a restart.
	sem := make(chan struct{}, maxParallel)

	for izone := range fetchQueue {
		sem <- struct{}{}
		go func(zone string) {
			defer func() { <-sem }()
			defer func() {
				stateMu.Lock()
				if state, ok := zoneStates[zone]; ok {
					state.pending = false
				}
				stateMu.Unlock()
			}()
			if checkSOAFunc(zone) && fetchZoneFunc(zone) {
				// lastFetch is set only on the success branch, so a failed AXFR is not
				// rate-limited and is retried on the next sweep/NOTIFY.
				stateMu.Lock()
				if state, ok := zoneStates[zone]; ok {
					state.lastFetch = time.Now()
				}
				stateMu.Unlock()
				if catalog, ok := catalogZoneName(); ok && zone == catalog {
					enqueueCatalogMembers()
				}
			}
		}(izone)
	}
}

// secondaryEnabled reports whether secondary refresh logic should run for the given
// live config. It mirrors the NOTIFY gating used in dns/handler.go.
func secondaryEnabled(live config.LiveConfig) bool {
	return live.Mode == "secondary"
}

// refreshZoneUnion returns the deduped union of the configured bootstrap zones
// (Secondary.Zones) and the locally stored zones (ZoneNamesSnapshot), as sanitized
// FQDNs. The configured list bootstraps a fresh/empty secondary; the local snapshot
// self-heals already-imported zones after downtime.
func refreshZoneUnion() []string {
	set := make(map[string]struct{})
	for _, z := range config.AppConfig.GetLive().Secondary.Zones {
		if f, err := internal.SanitizeFQDN(z); err == nil && f != "" {
			set[f] = struct{}{}
		}
	}
	if catalog, ok := catalogZoneName(); ok {
		set[catalog] = struct{}{}
	}
	for _, z := range catalogMembers() {
		set[z] = struct{}{}
	}
	if store := rtypes.GetMemStore(); store != nil {
		for _, z := range store.ZoneNamesSnapshot() {
			if f, err := internal.SanitizeFQDN(z); err == nil && f != "" {
				set[f] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for z := range set {
		out = append(out, z)
	}
	return out
}

// StartSecondaryRefresh runs a one-shot startup sweep and then the periodic refresh
// ticker. It is a no-op unless secondary mode is active and at least one transfer
// primary is configured or discoverable from the catalog.
// The startup sweep enqueues the zone union once
// through the guarded enqueueFetch path, so ProcessFetchQueue's SOA-gate decides whether
// an AXFR is actually needed. NOTIFY remains the fast-path signal on top of this.
//
// The provided context cancels the periodic ticker for graceful shutdown.
func StartSecondaryRefresh(ctx context.Context) {
	live := config.AppConfig.GetLive()
	if !secondaryEnabled(live) {
		return
	}
	if !hasAnyTransferPrimary(live) {
		log.Printf("[secondary-refresh] disabled: no primary is configured")
		return
	}

	go func() {
		zones := refreshZoneUnion()
		log.Printf("[secondary-refresh] startup sweep: %d zones", len(zones))
		for _, z := range zones {
			if hasTransferPrimaryForZone(z, config.AppConfig.GetLive()) {
				enqueueFetch(z)
			}
		}
		runRefreshTicker(ctx)
	}()
}

// runRefreshTicker periodically re-enqueues the zone union on the configured
// Secondary.RefreshIntervalSec cadence. A value <= 0 disables periodic refresh (the
// startup sweep still ran, and NOTIFY remains active). It mirrors the distributed
// resync ticker idiom: read the interval once, run on the ticker, exit on ctx.Done().
func runRefreshTicker(ctx context.Context) {
	interval := time.Duration(config.AppConfig.GetLive().Secondary.RefreshIntervalSec) * time.Second
	if interval <= 0 {
		log.Printf("[secondary-refresh] periodic refresh disabled (refresh_interval_sec<=0)")
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			live := config.AppConfig.GetLive()
			if !secondaryEnabled(live) || !hasAnyTransferPrimary(live) {
				continue
			}
			sweepOnce(ctx, live)
		}
	}
}

// sweepOnce recomputes the zone union and enqueues each zone, spreading the enqueues
// across [0, RefreshJitterSec] so a many-zone secondary does not hammer the primary at
// a single instant. The union is recomputed each call so newly imported local zones and
// edits to Secondary.Zones are picked up automatically.
func sweepOnce(ctx context.Context, live config.LiveConfig) {
	zones := refreshZoneUnion()
	jitterMax := time.Duration(live.Secondary.RefreshJitterSec) * time.Second
	log.Printf("[secondary-refresh] periodic sweep: %d zones", len(zones))
	for _, z := range zones {
		if jitterMax > 0 {
			zz := z
			time.AfterFunc(time.Duration(rand.Int63n(int64(jitterMax)+1)), func() {
				live := config.AppConfig.GetLive()
				if ctx.Err() != nil || !secondaryEnabled(live) || !hasTransferPrimaryForZone(zz, live) {
					return
				}
				enqueueFetch(zz)
			})
		} else if hasTransferPrimaryForZone(z, live) {
			enqueueFetch(z)
		}
	}
}

func hasAnyTransferPrimary(live config.LiveConfig) bool {
	if strings.TrimSpace(live.Primary.Ip) != "" {
		return true
	}
	for _, z := range refreshZoneUnion() {
		if len(catalogPrimariesForZone(z)) > 0 {
			return true
		}
	}
	return false
}
