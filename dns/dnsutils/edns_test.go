package dnsutils

import (
	"encoding/hex"
	"testing"

	"github.com/miekg/dns"
	"go53/config"
)

// setLiveNSID configures the live NSID/EDNS settings for a test and restores
// the previous live config afterwards.
func setLiveNSID(t *testing.T, enableEDNS bool, nsid string) {
	t.Helper()
	prev := config.AppConfig.GetLive()
	t.Cleanup(func() {
		config.AppConfig.Live = prev
	})
	live := prev
	live.EnableEDNS = enableEDNS
	live.NSID = nsid
	config.AppConfig.Live = live
}

// requestWithNSID builds a query that opts in to NSID via an empty NSID option.
func requestWithNSID() *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	opt := &dns.OPT{
		Hdr:    dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT},
		Option: []dns.EDNS0{&dns.EDNS0_NSID{Code: dns.EDNS0NSID}},
	}
	opt.SetUDPSize(1232)
	req.Extra = append(req.Extra, opt)
	return req
}

func responseNSID(resp *dns.Msg) (string, bool) {
	opt := resp.IsEdns0()
	if opt == nil {
		return "", false
	}
	for _, o := range opt.Option {
		if nsid, ok := o.(*dns.EDNS0_NSID); ok {
			return nsid.Nsid, true
		}
	}
	return "", false
}

func TestApplyNSID_AddsHexEncodedNSID(t *testing.T) {
	setLiveNSID(t, true, "node-a")

	req := requestWithNSID()
	resp := new(dns.Msg)
	resp.SetReply(req)

	ApplyNSID(resp, req)

	got, ok := responseNSID(resp)
	if !ok {
		t.Fatal("expected NSID option in response, found none")
	}
	want := hex.EncodeToString([]byte("node-a"))
	if got != want {
		t.Errorf("expected NSID %q, got %q", want, got)
	}
}

func TestApplyNSID_PreservesRequestUDPSizeAndDO(t *testing.T) {
	setLiveNSID(t, true, "node-a")

	req := requestWithNSID()
	req.IsEdns0().SetDo()

	resp := new(dns.Msg)
	resp.SetReply(req)

	ApplyNSID(resp, req)

	opt := resp.IsEdns0()
	if opt == nil {
		t.Fatal("expected OPT record in response")
	}
	if opt.UDPSize() != 1232 {
		t.Errorf("expected UDP size 1232, got %d", opt.UDPSize())
	}
	if !opt.Do() {
		t.Error("expected DO bit to be preserved")
	}
}

func TestApplyNSID_SilentWhenClientDidNotAsk(t *testing.T) {
	setLiveNSID(t, true, "node-a")

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.SetEdns0(1232, false) // OPT present but no NSID option

	resp := new(dns.Msg)
	resp.SetReply(req)

	ApplyNSID(resp, req)

	if _, ok := responseNSID(resp); ok {
		t.Error("expected no NSID option when client did not request it")
	}
}

func TestApplyNSID_SilentWithoutOPT(t *testing.T) {
	setLiveNSID(t, true, "node-a")

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	resp := new(dns.Msg)
	resp.SetReply(req)

	ApplyNSID(resp, req)

	if _, ok := responseNSID(resp); ok {
		t.Error("expected no NSID option when request had no OPT")
	}
}

func TestApplyNSID_SilentWhenNSIDUnconfigured(t *testing.T) {
	setLiveNSID(t, true, "")

	req := requestWithNSID()
	resp := new(dns.Msg)
	resp.SetReply(req)

	ApplyNSID(resp, req)

	if _, ok := responseNSID(resp); ok {
		t.Error("expected no NSID option when NSID is unconfigured")
	}
}

func TestApplyNSID_SilentWhenEDNSDisabled(t *testing.T) {
	setLiveNSID(t, false, "node-a")

	req := requestWithNSID()
	resp := new(dns.Msg)
	resp.SetReply(req)

	ApplyNSID(resp, req)

	if _, ok := responseNSID(resp); ok {
		t.Error("expected no NSID option when EDNS is disabled")
	}
}

func TestApplyNSID_ReusesExistingResponseOPT(t *testing.T) {
	setLiveNSID(t, true, "node-a")

	req := requestWithNSID()
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.SetEdns0(4096, true)

	ApplyNSID(resp, req)

	opts := 0
	for _, rr := range resp.Extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			opts++
		}
	}
	if opts != 1 {
		t.Errorf("expected exactly one OPT record, got %d", opts)
	}
	if _, ok := responseNSID(resp); !ok {
		t.Error("expected NSID to be added to the existing OPT record")
	}
}
