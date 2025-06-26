package dnsutils

import (
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

	fetchZone(zoneName)

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

func TestProcessFetchQueue_Trigger(t *testing.T) {
	called := make(chan string, 1)

	// Override fetchZone temporarily
	originalFetchZone := fetchZoneFunc
	fetchZoneFunc = func(zoneName string) {
		called <- zoneName
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
