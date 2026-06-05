package internal

import "testing"

func TestCanonicalDNSSECNameCompareCommonEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want int
	}{
		{
			name: "case insensitive",
			a:    "WWW.Example.COM.",
			b:    "www.example.com.",
			want: 0,
		},
		{
			name: "root sorts before non-root",
			a:    ".",
			b:    "com.",
			want: -1,
		},
		{
			name: "parent sorts before child",
			a:    "example.com.",
			b:    "a.example.com.",
			want: -1,
		},
		{
			name: "escaped decimal lowercases in canonical wire form",
			a:    `\065.example.com.`,
			b:    "a.example.com.",
			want: 0,
		},
		{
			name: "escaped dot is one label",
			a:    `a\.b.example.com.`,
			b:    "a.b.example.com.",
			want: -1,
		},
		{
			name: "idna unicode equals punycode",
			a:    "räksmörgås.example.com.",
			b:    "xn--rksmrgs-5wao1o.example.com.",
			want: 0,
		},
		{
			name: "wildcard label uses ordinary octet ordering",
			a:    "*.example.com.",
			b:    "a.example.com.",
			want: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sign(CanonicalDNSSECNameCompare(tt.a, tt.b))
			if got != tt.want {
				t.Fatalf("CanonicalDNSSECNameCompare(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
			reversed := sign(CanonicalDNSSECNameCompare(tt.b, tt.a))
			if reversed != -tt.want {
				t.Fatalf("reversed compare = %d, want %d", reversed, -tt.want)
			}
		})
	}
}

func sign(v int) int {
	switch {
	case v < 0:
		return -1
	case v > 0:
		return 1
	default:
		return 0
	}
}
