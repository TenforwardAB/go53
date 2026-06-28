package dnsutils

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"go53/config"
	"go53/memory"
	"go53/storage"
	"go53/zone/rtypes"
)

type transferResponseWriter struct {
	messages []*dns.Msg
}

func (w *transferResponseWriter) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 15353}
}

func (w *transferResponseWriter) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5353}
}

func (w *transferResponseWriter) WriteMsg(m *dns.Msg) error {
	w.messages = append(w.messages, m)
	return nil
}

func (w *transferResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (w *transferResponseWriter) Close() error              { return nil }
func (w *transferResponseWriter) TsigStatus() error         { return nil }
func (w *transferResponseWriter) TsigTimersOnly(bool)       {}
func (w *transferResponseWriter) Hijack()                   {}

func TestServeDNSIXFRUpToDateReturnsCurrentSOAOnly(t *testing.T) {
	zoneName := "ixfr-current.test"
	current := setupIXFRTestZone(t, zoneName)
	req := ixfrRequest(zoneName, current.Serial)

	w := &transferResponseWriter{}
	ServeDNS(w, req)

	if len(w.messages) != 1 {
		t.Fatalf("messages = %d, want 1", len(w.messages))
	}
	if w.messages[0].Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[w.messages[0].Rcode])
	}
	if len(w.messages[0].Answer) != 1 {
		t.Fatalf("answer count = %d, want 1 SOA", len(w.messages[0].Answer))
	}
	soa, ok := w.messages[0].Answer[0].(*dns.SOA)
	if !ok || soa.Serial != current.Serial {
		t.Fatalf("answer = %#v, want current SOA serial %d", w.messages[0].Answer[0], current.Serial)
	}
}

func TestServeDNSIXFROlderClientFallsBackToFullTransfer(t *testing.T) {
	zoneName := "ixfr-old.test"
	setupIXFRTestZone(t, zoneName)
	req := ixfrRequest(zoneName, 0)

	w := &transferResponseWriter{}
	ServeDNS(w, req)

	if len(w.messages) == 0 {
		t.Fatalf("expected transfer response")
	}
	var answers []dns.RR
	for _, msg := range w.messages {
		if msg.Rcode != dns.RcodeSuccess {
			t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[msg.Rcode])
		}
		answers = append(answers, msg.Answer...)
	}
	if countTransferType(answers, dns.TypeSOA) != 2 {
		t.Fatalf("SOA count = %d, want AXFR-style opening and closing SOA", countTransferType(answers, dns.TypeSOA))
	}
	if countTransferType(answers, dns.TypeA) == 0 {
		t.Fatalf("full transfer fallback missing A record")
	}
}

func TestServeDNSIXFRMissingClientSOAIsFormErr(t *testing.T) {
	zoneName := "ixfr-formerr.test"
	setupIXFRTestZone(t, zoneName)
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(zoneName), dns.TypeIXFR)

	w := &transferResponseWriter{}
	ServeDNS(w, req)

	if len(w.messages) != 1 {
		t.Fatalf("messages = %d, want 1", len(w.messages))
	}
	if w.messages[0].Rcode != dns.RcodeFormatError {
		t.Fatalf("rcode = %s, want FORMERR", dns.RcodeToString[w.messages[0].Rcode])
	}
}

func setupIXFRTestZone(t *testing.T, zoneName string) *dns.SOA {
	t.Helper()
	config.AppConfig = &config.ConfigManager{}
	config.AppConfig.SetLive(config.DefaultLiveConfig)
	config.AppConfig.LiveForTest().DNSSECEnabled = false
	config.AppConfig.LiveForTest().Mode = "primary"
	storage.Backend = &storage.MockStorage{Zones: map[string][]byte{}, Tables: map[string]map[string][]byte{}}
	store, err := memory.NewZoneStore(storage.Backend)
	if err != nil {
		t.Fatalf("NewZoneStore: %v", err)
	}
	rtypes.InitMemoryStore(store)
	t.Cleanup(func() {
		rtypes.InitMemoryStore(nil)
	})

	ttl := uint32(3600)
	if err := mustTransferRR(t, dns.TypeSOA).Add(zoneName, zoneName, map[string]interface{}{
		"ns":      "ns1." + zoneName,
		"mbox":    "hostmaster." + zoneName,
		"refresh": float64(3600),
		"retry":   float64(900),
		"expire":  float64(1209600),
		"minimum": float64(300),
	}, &ttl); err != nil {
		t.Fatalf("add SOA: %v", err)
	}
	if err := mustTransferRR(t, dns.TypeA).Add(zoneName, "www", map[string]interface{}{"ip": "192.0.2.44"}, &ttl); err != nil {
		t.Fatalf("add A: %v", err)
	}
	rrs, ok := mustTransferRR(t, dns.TypeSOA).Lookup(dns.Fqdn(zoneName))
	if !ok || len(rrs) != 1 {
		t.Fatalf("lookup SOA failed")
	}
	soa, ok := rrs[0].(*dns.SOA)
	if !ok {
		t.Fatalf("lookup returned %T, want SOA", rrs[0])
	}
	return soa
}

func ixfrRequest(zoneName string, serial uint32) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(zoneName), dns.TypeIXFR)
	req.Ns = []dns.RR{&dns.SOA{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(zoneName),
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Ns:      "ns1." + dns.Fqdn(zoneName),
		Mbox:    "hostmaster." + dns.Fqdn(zoneName),
		Serial:  serial,
		Refresh: 3600,
		Retry:   900,
		Expire:  1209600,
		Minttl:  300,
	}}
	return req
}

func mustTransferRR(t *testing.T, rrtype uint16) rtypes.RRType {
	t.Helper()
	rr, ok := rtypes.Get(rrtype)
	if !ok {
		t.Fatalf("rrtype %s not registered", dns.TypeToString[rrtype])
	}
	return rr
}

func countTransferType(rrs []dns.RR, rrtype uint16) int {
	count := 0
	for _, rr := range rrs {
		if rr.Header().Rrtype == rrtype {
			count++
		}
	}
	return count
}
