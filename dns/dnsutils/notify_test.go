package dnsutils

import (
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

	// mocka
	zoneLookupRecordFunc = mockZoneLookupRecord

	HandleNotify(w, r)
}

var zoneLookupRecordFunc = func(qtype uint16, name string) (any, bool) {
	return nil, false
}

func TestHandleNotify_Success(t *testing.T) {
	lookupZoneRecord = func(rrtype uint16, name string) ([]dns.RR, bool) {
		return []dns.RR{
			&dns.SOA{
				Hdr:     dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
				Ns:      "ns1.example.com.",
				Mbox:    "hostmaster.example.com.",
				Serial:  2025061701,
				Refresh: 3600,
				Retry:   600,
				Expire:  604800,
				Minttl:  86400,
			},
		}, true
	}
	mockSOAExists = true

	msg := new(dns.Msg)
	msg.SetNotify("example.com.")
	msg.Question = []dns.Question{
		{Name: "example.com.", Qtype: dns.TypeSOA, Qclass: dns.ClassINET},
	}

	srv := &dns.Server{Addr: "127.0.0.1:8053", Net: "udp", Handler: dns.HandlerFunc(testNotifyHandler)}
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
	resp, _, err := c.Exchange(msg, "127.0.0.1:8053")
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("expected RcodeSuccess, got %d", resp.Rcode)
	}
}

func TestHandleNotify_Refused(t *testing.T) {
	lookupZoneRecord = func(rrtype uint16, name string) ([]dns.RR, bool) {
		return nil, false
	}
	mockSOAExists = false

	msg := new(dns.Msg)
	msg.SetNotify("unknown.com.")
	msg.Question = []dns.Question{
		{Name: "unknown.com.", Qtype: dns.TypeSOA, Qclass: dns.ClassINET},
	}

	srv := &dns.Server{Addr: "127.0.0.1:8054", Net: "udp", Handler: dns.HandlerFunc(testNotifyHandler)}
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
	resp, _, err := c.Exchange(msg, "127.0.0.1:8054")
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}

	if resp.Rcode != dns.RcodeRefused {
		t.Errorf("expected RcodeRefused, got %d", resp.Rcode)
	}
}

func TestSendNotify_UDPAndTCP(t *testing.T) {
	received := false

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if r.Opcode == dns.OpcodeNotify {
			received = true
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.SetRcode(r, dns.RcodeSuccess)
		_ = w.WriteMsg(m)
	})

	udpServer := &dns.Server{Addr: "127.0.0.1:8055", Net: "udp", Handler: handler}
	tcpServer := &dns.Server{Addr: "127.0.0.1:8055", Net: "tcp", Handler: handler}

	go func() {
		err := udpServer.ListenAndServe()
		if err != nil {

		}
	}()
	go func() {
		err := tcpServer.ListenAndServe()
		if err != nil {

		}
	}()
	defer func(udpServer *dns.Server) {
		err := udpServer.Shutdown()
		if err != nil {

		}
	}(udpServer)
	defer func(tcpServer *dns.Server) {
		err := tcpServer.Shutdown()
		if err != nil {

		}
	}(tcpServer)

	time.Sleep(100 * time.Millisecond)

	SendNotify("example.com.", []string{"127.0.0.1:8055"})

	time.Sleep(300 * time.Millisecond)

	if !received {
		t.Errorf("expected server to receive NOTIFY")
	}
}
