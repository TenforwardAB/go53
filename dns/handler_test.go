package dns

import (
	"net"
	"testing"

	mdns "github.com/miekg/dns"
	"go53/config"
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
	config.AppConfig = &config.ConfigManager{}
	config.AppConfig.Live = config.DefaultLiveConfig

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
