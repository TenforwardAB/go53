package memory

import (
	"testing"

	"go53/types"
)

func TestIsUnsignedDelegationOwner(t *testing.T) {
	tests := []struct {
		name  string
		owner string
		types map[string]bool
		want  bool
	}{
		{
			name:  "unsigned delegation",
			owner: "child",
			types: map[string]bool{string(types.TypeNS): true},
			want:  true,
		},
		{
			name:  "signed delegation",
			owner: "child",
			types: map[string]bool{string(types.TypeNS): true, string(types.TypeDS): true},
			want:  false,
		},
		{
			name:  "apex is not opt-out delegation",
			owner: "@",
			types: map[string]bool{string(types.TypeNS): true},
			want:  false,
		},
		{
			name:  "ordinary owner",
			owner: "www",
			types: map[string]bool{string(types.TypeA): true},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isUnsignedDelegationOwner(tt.owner, tt.types)
			if got != tt.want {
				t.Fatalf("isUnsignedDelegationOwner(%q, %v) = %v, want %v", tt.owner, tt.types, got, tt.want)
			}
		})
	}
}

func TestNSEC3IntervalHasOmittedOptOut(t *testing.T) {
	tests := []struct {
		name    string
		owner   string
		next    string
		omitted []string
		want    bool
	}{
		{
			name:    "linear interval covers omitted delegation",
			owner:   "A",
			next:    "D",
			omitted: []string{"C"},
			want:    true,
		},
		{
			name:    "linear interval excludes omitted delegation",
			owner:   "A",
			next:    "D",
			omitted: []string{"E"},
			want:    false,
		},
		{
			name:    "wrap interval covers omitted delegation",
			owner:   "X",
			next:    "B",
			omitted: []string{"Z"},
			want:    true,
		},
		{
			name:    "owner hash itself is not covered",
			owner:   "A",
			next:    "D",
			omitted: []string{"A"},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nsec3IntervalHasOmittedOptOut(tt.owner, tt.next, tt.omitted)
			if got != tt.want {
				t.Fatalf("nsec3IntervalHasOmittedOptOut(%q, %q, %v) = %v, want %v", tt.owner, tt.next, tt.omitted, got, tt.want)
			}
		})
	}
}
