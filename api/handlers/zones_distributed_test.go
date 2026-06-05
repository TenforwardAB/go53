package handlers

import "testing"

func TestCanonicalRecordNameForDistributedEvents(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{name: "www", want: "www"},
		{name: "www.dist.test.", want: "www"},
		{name: "dist.test.", want: "@"},
	}

	for _, tt := range tests {
		if got := canonicalRecordName("dist.test.", "A", tt.name); got != tt.want {
			t.Fatalf("canonicalRecordName(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
	if got := canonicalRecordName("dist.test.", "SOA", "dist.test."); got != "@" {
		t.Fatalf("SOA canonicalRecordName = %q, want @", got)
	}
}
