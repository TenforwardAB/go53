package memory

import (
	"strings"

	"github.com/TenforwardAB/slog"
	"github.com/miekg/dns"
	"go53/types"
)

// canonZone returns the canonical store key for a zone: lowercase FQDN.
// Already-canonical input is returned unchanged without allocating.
func canonZone(zone string) string {
	return strings.ToLower(dns.Fqdn(zone))
}

// canonName returns the canonical store key for an owner-name key.
func canonName(name string) string {
	return strings.ToLower(name)
}

// caseSensitiveNameKeys reports whether the name keys for rtype embed
// case-sensitive material and must never be case-folded: NSEC3 maps are keyed
// by uppercase base32 owner hashes and RRSIG maps by covered-type mnemonics
// with owner names nested one level down.
func caseSensitiveNameKeys(rtype string) bool {
	return rtype == string(types.TypeNSEC3) || rtype == string(types.TypeRRSIG)
}

// canonicalizeZoneData rewrites legacy mixed-case keys in a decoded zone map
// to canonical form and reports whether anything changed.
func canonicalizeZoneData(zoneMap map[string]map[string]any) bool {
	changed := false
	for rtype, names := range zoneMap {
		if rtype == string(types.TypeNSEC3) {
			continue
		}
		if rtype == string(types.TypeRRSIG) {
			for typeName, raw := range names {
				if inner, ok := raw.(map[string]any); ok {
					if canonicalizeNameKeys(inner) {
						changed = true
					}
					names[typeName] = inner
				}
			}
			continue
		}
		if canonicalizeNameKeys(names) {
			changed = true
		}
	}
	return changed
}

// canonicalizeNameKeys lowercases the keys of names in place. On a collision
// the canonical entry wins and the duplicate is dropped with a warning.
func canonicalizeNameKeys(names map[string]any) bool {
	changed := false
	for name, value := range names {
		lower := canonName(name)
		if lower == name {
			continue
		}
		if _, exists := names[lower]; exists {
			slog.Warn("[memory] dropping duplicate record key %q: canonical key %q already exists", name, lower)
		} else {
			names[lower] = value
		}
		delete(names, name)
		changed = true
	}
	return changed
}
