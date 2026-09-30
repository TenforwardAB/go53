package internal

import "testing"

// Baseline for #60: SanitizeFQDN runs on every Lookup and currently compiles
// its regexp per call.
func BenchmarkSanitizeFQDN(b *testing.B) {
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		if _, err := SanitizeFQDN("www.example.com."); err != nil {
			b.Fatal(err)
		}
	}
}
