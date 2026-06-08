package dnsutils

import (
	"context"
	"go53/config"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

var mockSOAExists = true

func mockZoneLookupRecord(qtype uint16, name string) (any, bool) {
	if qtype == dns.TypeSOA && mockSOAExists {
		return "fakeSOA", true
	}
	return nil, false
}

func testNotifyHandler(w dns.ResponseWriter, r *dns.Msg) {
	original := zoneLookupRecordFunc
	defer func() { zoneLookupRecordFunc = original }()

	zoneLookupRecordFunc = mockZoneLookupRecord

	HandleNotify(w, r)
}

func clearFetchQueue() {
	for {
		select {
		case <-fetchQueue:
			// drain
		default:
			return
		}
	}
}

var zoneLookupRecordFunc = func(qtype uint16, name string) (any, bool) {
	return nil, false
}

func TestHandleNotify_Success(t *testing.T) {

	mockSOAExists = true

	msg := new(dns.Msg)
	msg.SetNotify("example.com.")
	msg.Question = []dns.Question{
		{Name: "example.com.", Qtype: dns.TypeSOA, Qclass: dns.ClassINET},
	}

	srv := &dns.Server{Addr: "127.0.0.1:18053", Net: "udp", Handler: dns.HandlerFunc(testNotifyHandler)}
	go func() {
		err := srv.ListenAndServe()
		if err != nil {

		}
	}()
	defer func(srv *dns.Server) {
		err := srv.Shutdown()
		if err != nil {

		}
	}(srv)

	time.Sleep(100 * time.Millisecond)

	c := &dns.Client{}
	resp, _, err := c.Exchange(msg, "127.0.0.1:18053")
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("expected RcodeSuccess, got %d", resp.Rcode)
	}
}

func TestHandleNotify_FormatError(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetNotify("invalid.")
	msg.Question = nil // Ingen fråga alls

	srv := &dns.Server{
		Addr:    "127.0.0.1:18054",
		Net:     "udp",
		Handler: dns.HandlerFunc(HandleNotify),
	}
	go srv.ListenAndServe()
	defer srv.Shutdown()
	time.Sleep(100 * time.Millisecond)

	c := &dns.Client{}
	resp, _, err := c.Exchange(msg, "127.0.0.1:18054")
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}

	if resp.Rcode != dns.RcodeFormatError {
		t.Errorf("expected FormatError, got %d", resp.Rcode)
	}
}

func TestSendNotify_UDPAndTCP(t *testing.T) {
	tmpConfig := config.ConfigManager{
		Base: config.DefaultBaseConfig,
		Live: config.LiveConfig{
			AllowTransfer: "127.0.0.1:8055",
		},
	}
	config.AppConfig = &tmpConfig

	var mu sync.Mutex
	received := false

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if r.Opcode == dns.OpcodeNotify {
			mu.Lock()
			received = true
			mu.Unlock()
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.SetRcode(r, dns.RcodeSuccess)
		_ = w.WriteMsg(m)
	})

	udpServer := &dns.Server{Addr: "127.0.0.1:8055", Net: "udp", Handler: handler}
	tcpServer := &dns.Server{Addr: "127.0.0.1:8055", Net: "tcp", Handler: handler}

	go udpServer.ListenAndServe()
	go tcpServer.ListenAndServe()
	defer udpServer.Shutdown()
	defer tcpServer.Shutdown()

	time.Sleep(100 * time.Millisecond)

	SendNotify("example.com.")

	time.Sleep(300 * time.Millisecond)

	mu.Lock()
	got := received
	mu.Unlock()

	if !got {
		t.Errorf("expected server to receive NOTIFY")
	}
}

func TestScheduleNotify_Debounce(t *testing.T) {
	zone := "example.com."

	// Clean state
	delete(notifyStates, zone)

	config.AppConfig = &config.ConfigManager{
		Live: config.LiveConfig{
			Primary: config.PrimaryConfig{
				NotifyDebounceMs: 100,
			},
		},
	}

	ScheduleNotify(zone)

	state, ok := notifyStates[zone]
	if !ok || !state.pending || state.debounceTimer == nil {
		t.Errorf("expected notifyState to be initialized and pending")
	}

	// Call again, should not schedule twice
	ScheduleNotify(zone)
	if state.debounceTimer == nil {
		t.Errorf("expected debounceTimer to remain after duplicate ScheduleNotify")
	}
}

func TestHandleNotify_NoQuestion(t *testing.T) {
	msg := new(dns.Msg)
	msg.Opcode = dns.OpcodeNotify

	handler := dns.HandlerFunc(HandleNotify)
	srv := &dns.Server{Addr: "127.0.0.1:8056", Net: "udp", Handler: handler}
	go srv.ListenAndServe()
	defer srv.Shutdown()
	time.Sleep(50 * time.Millisecond)

	c := &dns.Client{}
	resp, _, err := c.Exchange(msg, "127.0.0.1:8056")
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}

	if resp.Rcode != dns.RcodeFormatError {
		t.Errorf("expected FormatError, got %d", resp.Rcode)
	}
}

func TestHandleNotify_TriggersHandleNotify(t *testing.T) {
	testZone := "test.com."

	clearFetchQueue()

	// Reset zoneStates
	zoneStates = make(map[string]*zoneState)

	handler := dns.HandlerFunc(HandleNotify)
	srv := &dns.Server{Addr: "127.0.0.1:8057", Net: "udp", Handler: handler}
	go srv.ListenAndServe()
	defer srv.Shutdown()
	time.Sleep(50 * time.Millisecond)

	msg := new(dns.Msg)
	msg.SetNotify(testZone)

	msg.Question = []dns.Question{
		{Name: testZone, Qtype: dns.TypeSOA, Qclass: dns.ClassINET},
	}

	c := &dns.Client{}
	_, _, err := c.Exchange(msg, "127.0.0.1:8057")
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}

	select {
	case z := <-fetchQueue:
		if z != testZone {
			t.Errorf("expected %s in fetchQueue, got %s", testZone, z)
		}
	case <-time.After(500 * time.Millisecond):
		t.Errorf("zone was not queued for fetch")
	}
}

func TestHandleNotifyUsesConfiguredMinFetchInterval(t *testing.T) {
	testZone := "interval.test."
	clearFetchQueue()
	zoneStates = make(map[string]*zoneState)
	config.AppConfig = &config.ConfigManager{}
	config.AppConfig.Live = config.DefaultLiveConfig
	config.AppConfig.Live.Secondary.MinFetchIntervalSec = 0

	handleNotify(testZone)
	readQueuedZone(t, testZone)
	zoneStates[testZone].pending = false
	zoneStates[testZone].lastFetch = time.Now()
	handleNotify(testZone)
	readQueuedZone(t, testZone)

	clearFetchQueue()
	zoneStates = make(map[string]*zoneState)
	config.AppConfig.Live.Secondary.MinFetchIntervalSec = 30
	handleNotify(testZone)
	readQueuedZone(t, testZone)
	zoneStates[testZone].pending = false
	zoneStates[testZone].lastFetch = time.Now()
	handleNotify(testZone)
	select {
	case zone := <-fetchQueue:
		t.Fatalf("unexpected queued zone during min interval: %s", zone)
	default:
	}
}

func TestEnqueueFetchFullQueueClearsPending(t *testing.T) {
	testZone := "full-queue.test."
	clearFetchQueue()
	stateMu.Lock()
	zoneStates = make(map[string]*zoneState)
	stateMu.Unlock()
	config.AppConfig = &config.ConfigManager{}
	config.AppConfig.Live = config.DefaultLiveConfig
	config.AppConfig.Live.Secondary.MinFetchIntervalSec = 0

	for i := 0; i < cap(fetchQueue); i++ {
		fetchQueue <- "queued.test."
	}
	if enqueueFetch(testZone) {
		t.Fatalf("enqueueFetch succeeded with a full queue")
	}

	stateMu.Lock()
	state := zoneStates[testZone]
	pending := state != nil && state.pending
	stateMu.Unlock()
	if pending {
		t.Fatalf("zone remained pending after full queue rejection")
	}
	clearFetchQueue()
}

func readQueuedZone(t *testing.T, want string) {
	t.Helper()
	select {
	case got := <-fetchQueue:
		if got != want {
			t.Fatalf("queued zone = %q, want %q", got, want)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("zone %q was not queued for fetch", want)
	}
}

func TestCheckSOA_MissingPrimary(t *testing.T) {
	config.AppConfig = &config.ConfigManager{
		Live: config.LiveConfig{
			Primary: config.PrimaryConfig{
				Ip:   "127.0.0.2", // nothing is running
				Port: 5353,
			},
		},
	}

	ok := checkSOA("nonexistent.com.")
	if ok {
		t.Errorf("checkSOA should return false on connection failure")
	}
}

func TestFetchZone_InvalidAXFR(t *testing.T) {
	addr := "127.0.0.1:15353"
	zoneName := "refused.com."

	config.AppConfig = &config.ConfigManager{
		Live: config.LiveConfig{
			Primary: config.PrimaryConfig{
				Ip:   "127.0.0.1",
				Port: 15353,
			},
		},
	}

	dns.HandleFunc(zoneName, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(m)
	})

	srv := &dns.Server{Addr: addr, Net: "tcp"}
	go srv.ListenAndServe()
	defer srv.Shutdown()

	time.Sleep(100 * time.Millisecond)

	if fetchZone(zoneName) {
		t.Fatalf("fetchZone succeeded for refused AXFR")
	}

}

func TestSendNotify_InvalidTarget(t *testing.T) {
	config.AppConfig = &config.ConfigManager{
		Live: config.LiveConfig{
			AllowTransfer: "256.256.256.256",
		},
	}

	SendNotify("invalid.com.")

	time.Sleep(200 * time.Millisecond)
}

// collectQueued drains up to want zone names from fetchQueue within the timeout and
// returns them as a set. It does not require ProcessFetchQueue to be running.
func collectQueued(want int, timeout time.Duration) map[string]bool {
	got := make(map[string]bool)
	deadline := time.After(timeout)
	for len(got) < want {
		select {
		case z := <-fetchQueue:
			got[z] = true
		case <-deadline:
			return got
		}
	}
	return got
}

func TestStartSecondaryRefresh_StartupSweepEnqueuesConfiguredZones(t *testing.T) {
	clearFetchQueue()
	stateMu.Lock()
	zoneStates = make(map[string]*zoneState)
	stateMu.Unlock()

	config.AppConfig = &config.ConfigManager{}
	config.AppConfig.Live = config.DefaultLiveConfig
	config.AppConfig.Live.Mode = "secondary"
	config.AppConfig.Live.Primary.Ip = "127.0.0.1"
	config.AppConfig.Live.Secondary.MinFetchIntervalSec = 0
	config.AppConfig.Live.Secondary.RefreshIntervalSec = 0 // disable ticker; test the one-shot sweep
	config.AppConfig.Live.Secondary.Zones = []string{"a.test.", "b.test."}

	StartSecondaryRefresh(context.Background())

	got := collectQueued(2, time.Second)
	if !got["a.test."] || !got["b.test."] {
		t.Fatalf("startup sweep enqueued %v, want a.test. and b.test.", got)
	}
}

func TestStartSecondaryRefresh_DisabledInPrimaryMode(t *testing.T) {
	clearFetchQueue()
	stateMu.Lock()
	zoneStates = make(map[string]*zoneState)
	stateMu.Unlock()

	config.AppConfig = &config.ConfigManager{}
	config.AppConfig.Live = config.DefaultLiveConfig
	config.AppConfig.Live.Mode = "primary" // gating must suppress the sweep
	config.AppConfig.Live.Primary.Ip = "127.0.0.1"
	config.AppConfig.Live.Secondary.Zones = []string{"a.test."}

	StartSecondaryRefresh(context.Background())

	select {
	case z := <-fetchQueue:
		t.Fatalf("primary mode must not enqueue, got %q", z)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestStartSecondaryRefresh_DisabledWhenPrimaryIpEmpty(t *testing.T) {
	clearFetchQueue()
	stateMu.Lock()
	zoneStates = make(map[string]*zoneState)
	stateMu.Unlock()

	config.AppConfig = &config.ConfigManager{}
	config.AppConfig.Live = config.DefaultLiveConfig
	config.AppConfig.Live.Mode = "secondary"
	config.AppConfig.Live.Primary.Ip = "" // no upstream configured
	config.AppConfig.Live.Secondary.Zones = []string{"a.test."}

	StartSecondaryRefresh(context.Background())

	select {
	case z := <-fetchQueue:
		t.Fatalf("empty Primary.Ip must not enqueue, got %q", z)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestRunRefreshTicker_PeriodicEnqueue(t *testing.T) {
	clearFetchQueue()
	stateMu.Lock()
	zoneStates = make(map[string]*zoneState)
	stateMu.Unlock()

	config.AppConfig = &config.ConfigManager{}
	config.AppConfig.Live = config.DefaultLiveConfig
	config.AppConfig.Live.Mode = "secondary"
	config.AppConfig.Live.Primary.Ip = "127.0.0.1"
	config.AppConfig.Live.Secondary.MinFetchIntervalSec = 0
	config.AppConfig.Live.Secondary.RefreshIntervalSec = 1
	config.AppConfig.Live.Secondary.RefreshJitterSec = 0
	config.AppConfig.Live.Secondary.Zones = []string{"t.test."}

	// Drain enqueued zones and clear the pending flag so each tick can re-enqueue
	// (ProcessFetchQueue is not running in this test).
	var mu sync.Mutex
	count := 0
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case z := <-fetchQueue:
				mu.Lock()
				count++
				mu.Unlock()
				stateMu.Lock()
				if s, ok := zoneStates[z]; ok {
					s.pending = false
				}
				stateMu.Unlock()
			case <-stop:
				return
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	go runRefreshTicker(ctx)
	time.Sleep(2500 * time.Millisecond) // ~2 ticks at 1s
	cancel()
	close(stop)

	mu.Lock()
	got := count
	mu.Unlock()
	if got < 2 {
		t.Fatalf("periodic ticker enqueued %d times in ~2.5s at 1s interval, want >= 2", got)
	}
}

func TestSweepOnceJitterHonorsCanceledContext(t *testing.T) {
	clearFetchQueue()
	stateMu.Lock()
	zoneStates = make(map[string]*zoneState)
	stateMu.Unlock()

	config.AppConfig = &config.ConfigManager{}
	config.AppConfig.Live = config.DefaultLiveConfig
	config.AppConfig.Live.Mode = "secondary"
	config.AppConfig.Live.Primary.Ip = "127.0.0.1"
	config.AppConfig.Live.Secondary.MinFetchIntervalSec = 0
	config.AppConfig.Live.Secondary.RefreshJitterSec = 1
	config.AppConfig.Live.Secondary.Zones = []string{"jitter.test."}

	ctx, cancel := context.WithCancel(context.Background())
	sweepOnce(ctx, config.AppConfig.GetLive())
	cancel()

	select {
	case z := <-fetchQueue:
		t.Fatalf("canceled jitter callback enqueued %q", z)
	case <-time.After(1200 * time.Millisecond):
	}
}

func TestProcessFetchQueue_Trigger(t *testing.T) {
	called := make(chan string, 1)

	// Override fetchZone temporarily
	originalFetchZone := fetchZoneFunc
	fetchZoneFunc = func(zoneName string) bool {
		called <- zoneName
		return true
	}
	defer func() { fetchZoneFunc = originalFetchZone }()

	originalCheckSOA := checkSOAFunc
	checkSOAFunc = func(zone string) bool { return true }
	defer func() { checkSOAFunc = originalCheckSOA }()

	// Reset state
	clearFetchQueue()
	zoneStates = make(map[string]*zoneState)

	go ProcessFetchQueue()

	fetchQueue <- "testfetch.com."

	select {
	case zone := <-called:
		if zone != "testfetch.com." {
			t.Errorf("expected testfetch.com., got %s", zone)
		}
	case <-time.After(1 * time.Second):
		t.Error("expected fetchZone to be called")
	}
}
