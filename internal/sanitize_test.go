package internal

import "testing"

// SanitizeFQDN character validation used to be a regexp compiled on every
// call; the byte loop must accept and reject exactly the same inputs.
func TestSanitizeFQDNCharacters(t *testing.T) {
	accept := map[string]string{
		"example.com":          "example.com.",
		"Example.COM.":         "example.com.",
		"_sip._tcp.example.":   "_sip._tcp.example.",
		"my-host.example":      "my-host.example.",
		"  padded.example  ":   "padded.example.",
		"*.example.":           "*.example.",
		"@":                    "@",
		"@.":                   "@",
		"1.2.3.4.in-addr.arpa": "1.2.3.4.in-addr.arpa.",
	}
	for in, want := range accept {
		got, err := SanitizeFQDN(in)
		if err != nil || got != want {
			t.Errorf("SanitizeFQDN(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	reject := []string{"", "   ", "bad host", "bad/host", "bad\thost", "exämple.com", "host\x00", "a b.c", "*.@", "*."}
	for _, in := range reject {
		if got, err := SanitizeFQDN(in); err == nil {
			t.Errorf("SanitizeFQDN(%q) = %q, want error", in, got)
		}
	}
}

func TestSanitizeFQDNCanonicalInputAllocFree(t *testing.T) {
	allocs := testing.AllocsPerRun(1000, func() {
		if _, err := SanitizeFQDN("www.example.com."); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Fatalf("SanitizeFQDN allocates %.1f/op on canonical input", allocs)
	}
}
