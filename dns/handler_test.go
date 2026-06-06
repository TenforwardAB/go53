package dns

import (
	"net"
	"testing"

	mdns "github.com/miekg/dns"
	"go53/config"
	"go53/memory"
	"go53/storage"
	"go53/types"
	"go53/zone"
	"go53/zone/rtypes"
)

type captureResponseWriter struct {
	msg *mdns.Msg
}

func (w *captureResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 15353}
}

func (w *captureResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5353}
}

func (w *captureResponseWriter) WriteMsg(m *mdns.Msg) error {
	w.msg = m
	return nil
}

func (w *captureResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (w *captureResponseWriter) Close() error              { return nil }
func (w *captureResponseWriter) TsigStatus() error         { return nil }
func (w *captureResponseWriter) TsigTimersOnly(bool)       {}
func (w *captureResponseWriter) Hijack()                   {}

func TestHandleRequestRejectsMultiQuestion(t *testing.T) {
	resetDNSHandlerTestConfig()

	req := new(mdns.Msg)
	req.SetQuestion("example.test.", mdns.TypeA)
	req.Question = append(req.Question, mdns.Question{
		Name:   "example.test.",
		Qtype:  mdns.TypeAAAA,
		Qclass: mdns.ClassINET,
	})
	req.SetEdns0(1232, true)

	w := &captureResponseWriter{}
	handleRequest(w, req)

	if w.msg == nil {
		t.Fatalf("expected response")
	}
	if w.msg.Rcode != mdns.RcodeFormatError {
		t.Fatalf("rcode = %s, want FORMERR", mdns.RcodeToString[w.msg.Rcode])
	}
	if w.msg.Authoritative {
		t.Fatalf("multi-question FORMERR must not be authoritative")
	}
	if len(w.msg.Answer) != 0 || len(w.msg.Ns) != 0 || len(w.msg.Extra) != 0 {
		t.Fatalf("multi-question FORMERR should not include DNSSEC records: answer=%d ns=%d extra=%d", len(w.msg.Answer), len(w.msg.Ns), len(w.msg.Extra))
	}
}

func TestBuildDNSServersConfiguresUDPAndTCP(t *testing.T) {
	cfg := config.BaseConfig{BindHost: "127.0.0.1", DNSPort: ":15353"}

	addr, udpServer, tcpServer := buildDNSServers(cfg)

	if addr != "127.0.0.1:15353" {
		t.Fatalf("addr = %q, want 127.0.0.1:15353", addr)
	}
	if udpServer.Addr != addr || udpServer.Net != "udp" {
		t.Fatalf("udp server = addr %q net %q, want %q udp", udpServer.Addr, udpServer.Net, addr)
	}
	if tcpServer.Addr != addr || tcpServer.Net != "tcp" {
		t.Fatalf("tcp server = addr %q net %q, want %q tcp", tcpServer.Addr, tcpServer.Net, addr)
	}
	if tcpServer.ReadTimeout == 0 || tcpServer.WriteTimeout == 0 {
		t.Fatalf("tcp timeouts must be configured")
	}
	if tcpServer.MaxTCPQueries != 128 {
		t.Fatalf("MaxTCPQueries = %d, want 128", tcpServer.MaxTCPQueries)
	}
	if udpServer.Handler == nil || tcpServer.Handler == nil {
		t.Fatalf("DNS servers must have handlers")
	}
	if udpServer.TsigProvider == nil || tcpServer.TsigProvider == nil {
		t.Fatalf("DNS servers must use dynamic TSIG provider")
	}
}

func TestHandleRequestVersionBindChaosTXT(t *testing.T) {
	resetDNSHandlerTestConfig()
	config.AppConfig.Live.Version = "go53-test"

	req := new(mdns.Msg)
	req.SetQuestion("version.bind.", mdns.TypeTXT)
	req.Question[0].Qclass = mdns.ClassCHAOS

	w := &captureResponseWriter{}
	handleRequest(w, req)

	if w.msg == nil {
		t.Fatalf("expected response")
	}
	if w.msg.Rcode != mdns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", mdns.RcodeToString[w.msg.Rcode])
	}
	if len(w.msg.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(w.msg.Answer))
	}
	txt, ok := w.msg.Answer[0].(*mdns.TXT)
	if !ok {
		t.Fatalf("answer type = %T, want TXT", w.msg.Answer[0])
	}
	if len(txt.Txt) != 1 || txt.Txt[0] != "go53-test" {
		t.Fatalf("TXT = %v, want go53-test", txt.Txt)
	}
	if !w.msg.Authoritative {
		t.Fatalf("version.bind response should be authoritative")
	}
}

func TestHandleRequestAXFRRefusedWhenDisabled(t *testing.T) {
	resetDNSHandlerTestConfig()
	config.AppConfig.Live.AllowAXFR = false

	req := new(mdns.Msg)
	req.SetQuestion("example.test.", mdns.TypeAXFR)
	w := &captureResponseWriter{}
	handleRequest(w, req)
	if w.msg == nil {
		t.Fatalf("no response written")
	}
	if w.msg.Rcode != mdns.RcodeRefused {
		t.Fatalf("rcode = %s, want REFUSED", mdns.RcodeToString[w.msg.Rcode])
	}
}

func TestHandleRequestPositiveAAndNXDOMAIN(t *testing.T) {
	setupDNSHandlerTestStore(t)
	ttl := uint32(300)
	if err := zone.AddRecord(mdns.TypeSOA, "lookup.test.", "lookup.test.", map[string]interface{}{"ns": "ns1.lookup.test.", "mbox": "hostmaster.lookup.test.", "serial": float64(1), "refresh": float64(3600), "retry": float64(600), "expire": float64(86400), "minimum": float64(300)}, &ttl); err != nil {
		t.Fatalf("add SOA: %v", err)
	}
	if err := zone.AddRecord(mdns.TypeA, "lookup.test.", "www", map[string]interface{}{"ip": "192.0.2.80"}, &ttl); err != nil {
		t.Fatalf("add A: %v", err)
	}

	req := new(mdns.Msg)
	req.SetQuestion("www.lookup.test.", mdns.TypeA)
	w := &captureResponseWriter{}
	handleRequest(w, req)
	if w.msg == nil || w.msg.Rcode != mdns.RcodeSuccess || len(w.msg.Answer) != 1 {
		t.Fatalf("positive A response = %#v", w.msg)
	}
	if a, ok := w.msg.Answer[0].(*mdns.A); !ok || a.A.String() != "192.0.2.80" {
		t.Fatalf("A answer = %#v ok=%v", w.msg.Answer[0], ok)
	}

	nxReq := new(mdns.Msg)
	nxReq.SetQuestion("missing.lookup.test.", mdns.TypeA)
	nxW := &captureResponseWriter{}
	handleRequest(nxW, nxReq)
	if nxW.msg == nil || nxW.msg.Rcode != mdns.RcodeNameError {
		t.Fatalf("NXDOMAIN response = %#v", nxW.msg)
	}
	if len(nxW.msg.Ns) == 0 || nxW.msg.Ns[0].Header().Rrtype != mdns.TypeSOA {
		t.Fatalf("NXDOMAIN authority = %#v", nxW.msg.Ns)
	}
}

func TestHandleRequestDNSKEYAndReferralWithGlue(t *testing.T) {
	setupDNSHandlerTestStore(t)
	ttl := uint32(300)
	if err := zone.AddRecord(mdns.TypeDNSKEY, "dnskey.test.", "dnskey.test.", map[string]interface{}{"flags": float64(257), "protocol": float64(3), "algorithm": float64(15), "public_key": "abc"}, &ttl); err != nil {
		t.Fatalf("add DNSKEY: %v", err)
	}
	dnskeyReq := new(mdns.Msg)
	dnskeyReq.SetQuestion("dnskey.test.", mdns.TypeDNSKEY)
	dnskeyW := &captureResponseWriter{}
	handleRequest(dnskeyW, dnskeyReq)
	if dnskeyW.msg == nil || len(dnskeyW.msg.Answer) != 1 || dnskeyW.msg.Answer[0].Header().Rrtype != mdns.TypeDNSKEY {
		t.Fatalf("DNSKEY response = %#v", dnskeyW.msg)
	}

	if err := zone.AddRecord(mdns.TypeNS, "parent.test.", "child", map[string]interface{}{"ns": "ns1.child.parent.test."}, &ttl); err != nil {
		t.Fatalf("add child NS: %v", err)
	}
	if err := zone.AddRecord(mdns.TypeA, "parent.test.", "ns1.child", map[string]interface{}{"ip": "192.0.2.81"}, &ttl); err != nil {
		t.Fatalf("add child glue A: %v", err)
	}
	refReq := new(mdns.Msg)
	refReq.SetQuestion("www.child.parent.test.", mdns.TypeA)
	refW := &captureResponseWriter{}
	handleRequest(refW, refReq)
	if refW.msg == nil || refW.msg.Authoritative || len(refW.msg.Ns) != 1 || len(refW.msg.Extra) != 1 {
		t.Fatalf("referral response = %#v", refW.msg)
	}
	if refW.msg.Ns[0].Header().Rrtype != mdns.TypeNS || refW.msg.Extra[0].Header().Rrtype != mdns.TypeA {
		t.Fatalf("referral sections ns=%#v extra=%#v", refW.msg.Ns, refW.msg.Extra)
	}
}

func TestTransferClientAllowed(t *testing.T) {
	tests := []struct {
		name          string
		remoteAddress string
		allowTransfer string
		want          bool
	}{
		{name: "empty acl allows all", remoteAddress: "192.0.2.10:5353", allowTransfer: "", want: true},
		{name: "exact ip match", remoteAddress: "192.0.2.10:5353", allowTransfer: "192.0.2.10", want: true},
		{name: "hostport acl match", remoteAddress: "192.0.2.10:5353", allowTransfer: "127.0.0.1,192.0.2.10:53", want: true},
		{name: "ip mismatch", remoteAddress: "192.0.2.10:5353", allowTransfer: "192.0.2.11", want: false},
		{name: "invalid remote", remoteAddress: "not-an-ip", allowTransfer: "192.0.2.10", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := transferClientAllowed(tt.remoteAddress, tt.allowTransfer)
			if got != tt.want {
				t.Fatalf("transferClientAllowed(%q, %q) = %v, want %v", tt.remoteAddress, tt.allowTransfer, got, tt.want)
			}
		})
	}
}

func TestDNAMERewriteTarget(t *testing.T) {
	target, ok := dnameRewriteTarget("www.old.example.", "old.example.", "new.example.")
	if !ok {
		t.Fatalf("expected DNAME rewrite")
	}
	if target != "www.new.example." {
		t.Fatalf("target = %q, want www.new.example.", target)
	}

	if _, ok := dnameRewriteTarget("old.example.", "old.example.", "new.example."); ok {
		t.Fatalf("owner name must not synthesize a CNAME")
	}
	if _, ok := dnameRewriteTarget("www.other.example.", "old.example.", "new.example."); ok {
		t.Fatalf("non-child name must not synthesize a CNAME")
	}
}

func TestGlueRecordsReturnsOnlyInBailiwickAddressRecords(t *testing.T) {
	setupDNSHandlerTestStore(t)

	ttl := uint32(60)
	if err := zone.AddRecord(mdns.TypeA, "example.test.", "ns1", map[string]interface{}{"ip": "192.0.2.53"}, &ttl); err != nil {
		t.Fatalf("add in-bailiwick A: %v", err)
	}
	if err := zone.AddRecord(mdns.TypeA, "other.test.", "ns", map[string]interface{}{"ip": "198.51.100.53"}, &ttl); err != nil {
		t.Fatalf("add out-of-bailiwick A: %v", err)
	}

	nsRecords := []mdns.RR{
		&mdns.NS{Hdr: mdns.RR_Header{Name: "example.test.", Rrtype: mdns.TypeNS, Class: mdns.ClassINET, Ttl: ttl}, Ns: "ns1.example.test."},
		&mdns.NS{Hdr: mdns.RR_Header{Name: "example.test.", Rrtype: mdns.TypeNS, Class: mdns.ClassINET, Ttl: ttl}, Ns: "ns.other.test."},
	}

	glue := glueRecords(nsRecords)
	if len(glue) != 1 {
		t.Fatalf("glue records = %d, want 1: %v", len(glue), glue)
	}
	a, ok := glue[0].(*mdns.A)
	if !ok {
		t.Fatalf("glue type = %T, want A", glue[0])
	}
	if a.A.String() != "192.0.2.53" {
		t.Fatalf("glue A = %s, want 192.0.2.53", a.A.String())
	}
}

func TestAliasAndReferralHelpers(t *testing.T) {
	cnameRR := &mdns.CNAME{Hdr: mdns.RR_Header{Name: "alias.example.test.", Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: 300}, Target: "target.example.test."}
	if got, ok := firstCNAME([]mdns.RR{cnameRR}); !ok || got.Target != "target.example.test." {
		t.Fatalf("firstCNAME = %#v ok=%v", got, ok)
	}
	if _, ok := firstCNAME([]mdns.RR{&mdns.A{Hdr: mdns.RR_Header{Name: "alias.example.test.", Rrtype: mdns.TypeA}}}); ok {
		t.Fatalf("firstCNAME accepted non-CNAME")
	}

	dnameRR := &mdns.DNAME{Hdr: mdns.RR_Header{Name: "old.example.test.", Rrtype: mdns.TypeDNAME, Class: mdns.ClassINET, Ttl: 300}, Target: "new.example.test."}
	if got, ok := firstDNAME([]mdns.RR{dnameRR}); !ok || got.Target != "new.example.test." {
		t.Fatalf("firstDNAME = %#v ok=%v", got, ok)
	}
	target, ok := dnameRewriteTarget("www.old.example.test.", "old.example.test.", "new.example.test.")
	if !ok || target != "www.new.example.test." {
		t.Fatalf("dnameRewriteTarget = %q ok=%v", target, ok)
	}
	if _, ok := dnameRewriteTarget("old.example.test.", "old.example.test.", "new.example.test."); ok {
		t.Fatalf("dnameRewriteTarget rewrote owner itself")
	}

	section := []mdns.RR{
		dnameRR,
		&mdns.CNAME{Hdr: mdns.RR_Header{Name: "www.old.example.test.", Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: 300}, Target: "www.new.example.test."},
	}
	if synthesized := synthesizedDNAMECNAMEs(section); !synthesized["www.old.example.test."] {
		t.Fatalf("synthesizedDNAMECNAMEs = %#v", synthesized)
	}

	dsQuestion := mdns.Question{Name: "child.example.test.", Qtype: mdns.TypeDS, Qclass: mdns.ClassINET}
	if shouldReturnReferral(dsQuestion, "child.example.test.") {
		t.Fatalf("shouldReturnReferral returned true for DS at delegation")
	}
	aQuestion := mdns.Question{Name: "www.child.example.test.", Qtype: mdns.TypeA, Qclass: mdns.ClassINET}
	if !shouldReturnReferral(aQuestion, "child.example.test.") {
		t.Fatalf("shouldReturnReferral returned false for child A")
	}
}

func TestAppendRRSIGsSkipsAlreadyCoveredAndSynthesizedCNAME(t *testing.T) {
	setupDNSHandlerTestStore(t)
	a := &mdns.A{Hdr: mdns.RR_Header{Name: "www.sig.test.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.90").To4()}
	existing := &mdns.RRSIG{
		Hdr:         mdns.RR_Header{Name: "www.sig.test.", Rrtype: mdns.TypeRRSIG, Class: mdns.ClassINET, Ttl: 300},
		TypeCovered: mdns.TypeA,
		Algorithm:   15,
		Labels:      3,
		OrigTtl:     300,
		Expiration:  2000,
		Inception:   1000,
		KeyTag:      12345,
		SignerName:  "sig.test.",
		Signature:   "abc",
	}
	dname := &mdns.DNAME{Hdr: mdns.RR_Header{Name: "old.sig.test.", Rrtype: mdns.TypeDNAME, Class: mdns.ClassINET, Ttl: 300}, Target: "new.sig.test."}
	synth := &mdns.CNAME{Hdr: mdns.RR_Header{Name: "www.old.sig.test.", Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: 300}, Target: "www.new.sig.test."}

	out := appendRRSIGs([]mdns.RR{a, existing, dname, synth})
	if len(out) != 4 {
		t.Fatalf("appendRRSIGs added unexpected records: %#v", out)
	}
	if out[1] != existing {
		t.Fatalf("existing RRSIG not preserved in place")
	}
}

func TestWildcardSynthesisAndApexSOAHelpers(t *testing.T) {
	setupDNSHandlerTestStore(t)
	ttl := uint32(300)
	if err := rtypes.GetMemStore().AddRecord("example.test.", "A", "*.wild", []map[string]interface{}{{"ip": "192.0.2.55", "ttl": float64(ttl)}}); err != nil {
		t.Fatalf("Add wildcard A: %v", err)
	}
	if err := rtypes.GetMemStore().AddRecord("example.test.", "A", "wild", []map[string]interface{}{{"ip": "192.0.2.56", "ttl": float64(ttl)}}); err != nil {
		t.Fatalf("Add closest encloser A: %v", err)
	}
	if err := rtypes.GetMemStore().AddRecord("example.test.", "SOA", "@", types.SOARecord{Ns: "ns1.example.test.", Mbox: "hostmaster.example.test.", Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300, TTL: ttl}); err != nil {
		t.Fatalf("Add SOA: %v", err)
	}

	wildcardRRSet, ok := lookupWildcard(mdns.TypeA, "missing.wild.example.test.", false)
	if !ok || len(wildcardRRSet) != 1 || wildcardRRSet[0].Header().Name != "missing.wild.example.test." {
		wildcardName, wildcardOK := zone.WildcardName("missing.wild.example.test.")
		lookup, lookupOK := zone.LookupRecord(mdns.TypeA, wildcardName)
		t.Fatalf("lookupWildcard = %#v ok=%v wildcard=%q wildcardOK=%v lookup=%#v lookupOK=%v", wildcardRRSet, ok, wildcardName, wildcardOK, lookup, lookupOK)
	}
	synthesized := synthesizeWildcard("other.wild.example.test.", wildcardRRSet, false)
	if len(synthesized) != 1 || synthesized[0].Header().Name != "other.wild.example.test." {
		t.Fatalf("synthesizeWildcard = %#v", synthesized)
	}
	if soa, ok := lookupApexSOA("www.example.test."); !ok || len(soa) != 1 || soa[0].Header().Rrtype != mdns.TypeSOA {
		t.Fatalf("lookupApexSOA = %#v ok=%v", soa, ok)
	}
	if !authoritativeForName("www.example.test.") {
		t.Fatalf("authoritativeForName returned false")
	}
}

func TestResolveAnswerChainCNAMEAndDNAME(t *testing.T) {
	setupDNSHandlerTestStore(t)
	ttl := uint32(300)
	if err := zone.AddRecord(mdns.TypeA, "chain.test.", "target", map[string]interface{}{"ip": "192.0.2.70"}, &ttl); err != nil {
		t.Fatalf("Add target A: %v", err)
	}
	if err := zone.AddRecord(mdns.TypeCNAME, "chain.test.", "alias", map[string]interface{}{"target": "target.chain.test."}, &ttl); err != nil {
		t.Fatalf("Add CNAME: %v", err)
	}
	result := resolveAnswerChain("alias.chain.test.", mdns.TypeA, false)
	if result.Rcode != mdns.RcodeSuccess || len(result.Answer) != 2 {
		t.Fatalf("CNAME resolve result = %#v", result)
	}
	if _, ok := result.Answer[0].(*mdns.CNAME); !ok {
		t.Fatalf("first answer = %T, want CNAME", result.Answer[0])
	}
	if _, ok := result.Answer[1].(*mdns.A); !ok {
		t.Fatalf("second answer = %T, want A", result.Answer[1])
	}

	if err := zone.AddRecord(mdns.TypeA, "other.test.", "www.new", map[string]interface{}{"ip": "192.0.2.71"}, &ttl); err != nil {
		t.Fatalf("Add DNAME target A: %v", err)
	}
	if err := zone.AddRecord(mdns.TypeDNAME, "other.test.", "old", map[string]interface{}{"target": "new.other.test."}, &ttl); err != nil {
		t.Fatalf("Add DNAME: %v", err)
	}
	dnameResult := resolveAnswerChain("www.old.other.test.", mdns.TypeA, false)
	if len(dnameResult.Answer) != 3 {
		t.Fatalf("DNAME resolve result = %#v", dnameResult)
	}
	if _, ok := dnameResult.Answer[0].(*mdns.DNAME); !ok {
		t.Fatalf("first DNAME answer = %T", dnameResult.Answer[0])
	}
	if cname, ok := dnameResult.Answer[1].(*mdns.CNAME); !ok || cname.Target != "www.new.other.test." {
		t.Fatalf("synthesized CNAME = %#v ok=%v", dnameResult.Answer[1], ok)
	}
	if _, ok := dnameResult.Answer[2].(*mdns.A); !ok {
		t.Fatalf("third DNAME answer = %T", dnameResult.Answer[2])
	}
}

func resetDNSHandlerTestConfig() {
	config.AppConfig = &config.ConfigManager{}
	config.AppConfig.Live = config.DefaultLiveConfig
	config.AppConfig.Live.DNSSECEnabled = false
}

func setupDNSHandlerTestStore(t *testing.T) {
	t.Helper()
	resetDNSHandlerTestConfig()
	backend := &storage.MockStorage{}
	if err := backend.Init(); err != nil {
		t.Fatalf("init mock storage: %v", err)
	}
	storage.Backend = backend
	store, err := memory.NewZoneStore(backend)
	if err != nil {
		t.Fatalf("new zone store: %v", err)
	}
	rtypes.InitMemoryStore(store)
}
