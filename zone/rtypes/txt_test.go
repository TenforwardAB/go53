package rtypes

import (
	"testing"

	"github.com/miekg/dns"
)

func TestTXTRecordLifecycle(t *testing.T) {
	zone := "go53.test"
	name := "text"
	text := "v=spf1 include:_spf.google.com ~all"
	fqdn := name + "." + zone + "."

	value := map[string]interface{}{
		"text": text,
	}

	rr, ok := Get(dns.TypeTXT)
	if !ok {
		t.Fatalf("TXT record type not found")
	}

	err := rr.Add(zone, name, value, nil)
	if err != nil {
		t.Fatalf("failed to add TXT record: %v", err)
	}

	err = rr.Add(zone, name, value, nil)
	if err != nil {
		t.Errorf("expected no error when adding duplicate TXT record, got: %v", err)
	}

	results, ok := rr.Lookup(fqdn)
	if !ok || len(results) == 0 {
		t.Fatalf("expected TXT record for %s, got none", fqdn)
	}

	txt, ok := results[0].(*dns.TXT)
	if !ok {
		t.Fatalf("expected TXT record type in response")
	}

	if len(txt.Txt) == 0 || txt.Txt[0] != text {
		t.Errorf("expected text %q, got %+v", text, txt.Txt)
	}

	err = rr.Delete(fqdn, 1234)
	if err == nil {
		t.Errorf("expected error for invalid delete input type, got nil")
	}

	err = rr.Delete(fqdn, nil)
	if err != nil {
		t.Fatalf("failed to delete TXT record: %v", err)
	}

	results, _ = rr.Lookup(fqdn)
	if len(results) != 0 {
		t.Errorf("expected no TXT record after delete")
	}
}

// TestTXTRecordApexFQDN verifies that Add with an FQDN zone-apex name ("go53.test.")
// stores the record under the same key that Lookup derives for the apex, fixing the
// bug where FQDN-posted TXT records were silently unreachable via DNS.
func TestTXTRecordApexFQDN(t *testing.T) {
	zone := "go53.test"
	text := "v=spf1 mx -all"

	rr, _ := Get(dns.TypeTXT)

	// Add using the FQDN form callers naturally supply (e.g. from a JSON body
	// that mirrors the zone name).
	if err := rr.Add(zone, zone+".", map[string]interface{}{"text": text}, nil); err != nil {
		t.Fatalf("Add FQDN apex TXT: %v", err)
	}

	// Lookup must resolve the same apex — this was the failing case.
	results, ok := rr.Lookup(zone + ".")
	if !ok || len(results) == 0 {
		t.Fatal("TXT apex via FQDN Add: Lookup returned nothing (normalization bug)")
	}
	txt := results[0].(*dns.TXT)
	if len(txt.Txt) == 0 || txt.Txt[0] != text {
		t.Errorf("expected %q, got %v", text, txt.Txt)
	}
}

func TestTXTRecordAdd_InvalidInputs(t *testing.T) {
	rr := TXTRecord{}

	err := rr.Add("go53.test", "bad", "not-a-map", nil)
	if err == nil {
		t.Error("expected error for non-map value")
	}

	err = rr.Add("go53.test", "bad", map[string]interface{}{}, nil)
	if err == nil || err.Error() != "TXTRecord expects field 'text'" {
		t.Errorf("expected 'missing text' error, got: %v", err)
	}

	err = rr.Add("go53.test", "bad", map[string]interface{}{"text": 123}, nil)
	if err == nil || err.Error() != "TXTRecord: field 'text' must be a string, got int" {
		t.Errorf("expected 'wrong type' error, got: %v", err)
	}
}

func TestTXTRecordLookup_NotFound(t *testing.T) {
	rr := TXTRecord{}
	_, ok := rr.Lookup("nonexistent.go53.test.")
	if ok {
		t.Error("expected lookup to fail for nonexistent record")
	}
}

func TestTXTRecordDelete_NonExisting(t *testing.T) {
	rr := TXTRecord{}
	err := rr.Delete("nonexistent.go53.test.", "some text")
	if err != nil {
		t.Errorf("expected no error for delete on missing record, got: %v", err)
	}
}
