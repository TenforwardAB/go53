package dnsutils

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"go53/config"
	"go53/internal"
	"go53/zone"
	"go53/zone/rtypes"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

const catalogVersion = "2"

type catalogPrimary struct {
	IP   string
	Port int
}

func catalogZoneName() (string, bool) {
	live := config.AppConfig.GetLive()
	if !live.Secondary.CatalogEnabled {
		return "", false
	}
	name := live.Secondary.CatalogZone
	if strings.TrimSpace(name) == "" {
		name = config.DefaultLiveConfig.Secondary.CatalogZone
	}
	fqdn, err := internal.SanitizeFQDN(name)
	return fqdn, err == nil && fqdn != ""
}

func catalogMemberOwner(member, catalog string) string {
	sum := sha1.Sum([]byte(strings.ToLower(dns.Fqdn(member))))
	return hex.EncodeToString(sum[:]) + ".zones." + catalog
}

// EnsureCatalogMember adds zoneName to the configured RFC 9432 catalog zone.
// It is intentionally idempotent and uses a deterministic member node so the
// common primary mutation path does not scan large catalogs.
func EnsureCatalogMember(zoneName string) error {
	catalog, ok := catalogZoneName()
	if !ok || config.AppConfig.GetLive().Mode == "secondary" {
		return nil
	}
	member, err := internal.SanitizeFQDN(zoneName)
	if err != nil {
		return err
	}
	if member == catalog {
		return nil
	}
	if _, ok := zone.LookupRecord(dns.TypeSOA, member); !ok {
		return nil
	}
	owner := catalogMemberOwner(member, catalog)
	if ptrs, ok := zone.LookupRecord(dns.TypePTR, owner); ok {
		for _, rr := range ptrs {
			if ptr, ok := rr.(*dns.PTR); ok && strings.EqualFold(ptr.Ptr, member) {
				return nil
			}
		}
	}

	ttl := uint32(3600)
	if err := ensureCatalogBase(catalog, ttl); err != nil {
		return err
	}
	if err := zone.AddRecord(dns.TypePTR, catalog, owner, map[string]interface{}{"ptr": member}, &ttl); err != nil {
		return err
	}
	if err := UpdateSOASerial(catalog); err != nil {
		return fmt.Errorf("catalog member stored but serial update failed: %w", err)
	}
	go ScheduleNotify(catalog)
	return nil
}

func ensureCatalogBase(catalog string, ttl uint32) error {
	if _, ok := zone.LookupRecord(dns.TypeSOA, catalog); !ok {
		if err := zone.AddRecord(dns.TypeSOA, catalog, catalog, map[string]interface{}{
			"ns":      "invalid.",
			"mbox":    "hostmaster." + strings.TrimPrefix(catalog, "_"),
			"refresh": float64(3600),
			"retry":   float64(600),
			"expire":  float64(86400),
			"minimum": float64(300),
			"ttl":     float64(ttl),
		}, &ttl); err != nil {
			return err
		}
	}
	if _, ok := zone.LookupRecord(dns.TypeNS, catalog); !ok {
		if err := zone.AddRecord(dns.TypeNS, catalog, "@", map[string]interface{}{"ns": "invalid."}, &ttl); err != nil {
			return err
		}
	}
	versionOwner := "version." + catalog
	if _, ok := zone.LookupRecord(dns.TypeTXT, versionOwner); !ok {
		if err := zone.AddRecord(dns.TypeTXT, catalog, versionOwner, map[string]interface{}{"text": catalogVersion}, &ttl); err != nil {
			return err
		}
	}
	return nil
}

func catalogMembers() []string {
	catalog, ok := catalogZoneName()
	if !ok {
		return nil
	}
	owner := "version." + catalog
	txts, ok := zone.LookupRecord(dns.TypeTXT, owner)
	if !ok || len(txts) == 0 {
		return nil
	}
	validVersion := false
	for _, rr := range txts {
		if txt, ok := rr.(*dns.TXT); ok {
			for _, s := range txt.Txt {
				if s == catalogVersion {
					validVersion = true
					break
				}
			}
		}
	}
	if !validVersion {
		log.Printf("[catalog] ignoring %s: unsupported or missing version", catalog)
		return nil
	}

	store := zoneStore()
	if store == nil {
		return nil
	}
	snapshot := store.ZoneRecordsSnapshot(catalog)
	ptrByName := snapshot["PTR"]
	out := make([]string, 0, len(ptrByName))
	for name := range ptrByName {
		owner := name
		if owner == "@" {
			owner = catalog
		} else if !strings.HasSuffix(owner, ".") {
			owner = owner + "." + catalog
		}
		if !strings.HasSuffix(strings.ToLower(owner), ".zones."+strings.ToLower(catalog)) {
			continue
		}
		for _, rr := range ptrRecords(owner) {
			if ptr, ok := rr.(*dns.PTR); ok {
				if member, err := internal.SanitizeFQDN(ptr.Ptr); err == nil && member != "" && member != catalog {
					out = append(out, member)
				}
			}
		}
	}
	return out
}

func CatalogStatus() map[string]any {
	catalog, ok := catalogZoneName()
	members := []string{}
	primaries := []string{}
	if ok {
		members = catalogMembers()
		for _, primary := range globalCatalogPrimaries(catalog) {
			primaries = append(primaries, primary.addr())
		}
	}
	return map[string]any{
		"enabled":          config.AppConfig.GetLive().Secondary.CatalogEnabled,
		"zone":             catalog,
		"valid":            ok,
		"members":          members,
		"count":            len(members),
		"version":          catalogVersion,
		"global_primaries": primaries,
	}
}

func CatalogMembers() []string {
	members := catalogMembers()
	if members == nil {
		return []string{}
	}
	return members
}

func catalogMembersFromRecords(records []dns.RR, catalog string) []string {
	hasVersion := false
	out := make([]string, 0)
	suffix := ".zones." + strings.ToLower(catalog)
	for _, rr := range records {
		switch r := rr.(type) {
		case *dns.TXT:
			if strings.EqualFold(r.Hdr.Name, "version."+catalog) {
				for _, s := range r.Txt {
					if s == catalogVersion {
						hasVersion = true
						break
					}
				}
			}
		case *dns.PTR:
			if !strings.HasSuffix(strings.ToLower(r.Hdr.Name), suffix) {
				continue
			}
			if member, err := internal.SanitizeFQDN(r.Ptr); err == nil && member != "" && member != catalog {
				out = append(out, member)
			}
		}
	}
	if !hasVersion {
		return nil
	}
	return out
}

func catalogPrimariesForZone(zoneName string) []catalogPrimary {
	catalog, ok := catalogZoneName()
	if !ok {
		return nil
	}
	member, err := internal.SanitizeFQDN(zoneName)
	if err != nil || member == "" || member == catalog {
		return nil
	}
	members := catalogMemberLabels(catalog)
	memberLabels := members[member]
	specific := memberCatalogPrimaries(catalog, memberLabels)
	if len(specific) > 0 {
		return specific
	}
	return globalCatalogPrimaries(catalog)
}

func catalogNotifyAllowed(zoneName, remoteIP string) bool {
	if net.ParseIP(remoteIP) == nil {
		return false
	}
	for _, primary := range catalogPrimariesForZone(zoneName) {
		if primary.IP == remoteIP {
			return true
		}
	}
	return false
}

// NotifyAllowedFromCatalogPrimary reports whether remoteIP is one of the catalog
// primaries currently configured for zoneName. It lets the DNS handler keep its
// secondary NOTIFY gate in sync with the dynamic catalog transfer source.
func NotifyAllowedFromCatalogPrimary(zoneName, remoteIP string) bool {
	return catalogNotifyAllowed(zoneName, remoteIP)
}

func globalCatalogPrimaries(catalog string) []catalogPrimary {
	suffixes := []string{
		".primaries.ext." + catalog,
		".masters.ext." + catalog,
	}
	return primariesWithSuffix(catalog, suffixes)
}

func memberCatalogPrimaries(catalog string, labels []string) []catalogPrimary {
	if len(labels) == 0 {
		return nil
	}
	suffixes := make([]string, 0, len(labels)*2)
	for _, label := range labels {
		suffixes = append(suffixes,
			".primaries.ext."+label+".zones."+catalog,
			".masters.ext."+label+".zones."+catalog,
		)
	}
	return primariesWithSuffix(catalog, suffixes)
}

func primariesWithSuffix(catalog string, suffixes []string) []catalogPrimary {
	store := zoneStore()
	if store == nil {
		return nil
	}
	snapshot := store.ZoneRecordsSnapshot(catalog)
	seen := map[string]struct{}{}
	var out []catalogPrimary
	for _, rrtype := range []string{"A", "AAAA"} {
		for name := range snapshot[rrtype] {
			owner := catalogOwnerName(name, catalog)
			if !hasAnySuffix(owner, suffixes) {
				continue
			}
			for _, primary := range primaryRecords(owner, rrtype) {
				key := primary.addr()
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				out = append(out, primary)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].addr() < out[j].addr()
	})
	return out
}

func catalogMemberLabels(catalog string) map[string][]string {
	store := zoneStore()
	if store == nil {
		return nil
	}
	snapshot := store.ZoneRecordsSnapshot(catalog)
	ptrByName := snapshot["PTR"]
	out := make(map[string][]string, len(ptrByName))
	for name := range ptrByName {
		owner := catalogOwnerName(name, catalog)
		label, ok := catalogMemberLabel(owner, catalog)
		if !ok {
			continue
		}
		for _, rr := range ptrRecords(owner) {
			ptr, ok := rr.(*dns.PTR)
			if !ok {
				continue
			}
			member, err := internal.SanitizeFQDN(ptr.Ptr)
			if err != nil || member == "" || member == catalog {
				continue
			}
			out[member] = append(out[member], label)
		}
	}
	return out
}

func catalogMemberLabel(owner, catalog string) (string, bool) {
	owner = strings.ToLower(dns.Fqdn(owner))
	suffix := ".zones." + strings.ToLower(catalog)
	if !strings.HasSuffix(owner, suffix) {
		return "", false
	}
	label := strings.TrimSuffix(owner, suffix)
	label = strings.TrimSuffix(label, ".")
	if label == "" || strings.Contains(label, ".") {
		return "", false
	}
	return label, true
}

func catalogOwnerName(name, catalog string) string {
	if name == "@" {
		return catalog
	}
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "." + catalog
}

func hasAnySuffix(owner string, suffixes []string) bool {
	owner = strings.ToLower(dns.Fqdn(owner))
	for _, suffix := range suffixes {
		if strings.HasSuffix(owner, strings.ToLower(suffix)) {
			prefix := strings.TrimSuffix(owner, suffix)
			prefix = strings.TrimSuffix(prefix, ".")
			if prefix != "" && !strings.Contains(prefix, ".") {
				return true
			}
		}
	}
	return false
}

func primaryRecords(owner, rrtype string) []catalogPrimary {
	rrTypeCode, ok := dns.StringToType[rrtype]
	if !ok {
		return nil
	}
	rrs, ok := zone.LookupRecord(rrTypeCode, owner)
	if !ok {
		return nil
	}
	out := make([]catalogPrimary, 0, len(rrs))
	for _, rr := range rrs {
		switch r := rr.(type) {
		case *dns.A:
			out = append(out, catalogPrimary{IP: r.A.String(), Port: 53})
		case *dns.AAAA:
			out = append(out, catalogPrimary{IP: r.AAAA.String(), Port: 53})
		}
	}
	return out
}

func (p catalogPrimary) addr() string {
	port := p.Port
	if port == 0 {
		port = 53
	}
	return net.JoinHostPort(p.IP, strconv.Itoa(port))
}

func pruneRemovedCatalogMembers(oldMembers, newMembers []string) {
	keep := make(map[string]struct{}, len(newMembers)+len(config.AppConfig.GetLive().Secondary.Zones)+1)
	for _, z := range newMembers {
		if f, err := internal.SanitizeFQDN(z); err == nil && f != "" {
			keep[f] = struct{}{}
		}
	}
	for _, z := range config.AppConfig.GetLive().Secondary.Zones {
		if f, err := internal.SanitizeFQDN(z); err == nil && f != "" {
			keep[f] = struct{}{}
		}
	}
	if catalog, ok := catalogZoneName(); ok {
		keep[catalog] = struct{}{}
	}
	for _, z := range oldMembers {
		member, err := internal.SanitizeFQDN(z)
		if err != nil || member == "" {
			continue
		}
		if _, ok := keep[member]; ok {
			continue
		}
		if err := zone.DeleteZone(member); err != nil {
			log.Printf("[catalog] failed to delete removed member %s: %v", member, err)
			continue
		}
		log.Printf("[catalog] deleted removed member %s", member)
	}
}

func ptrRecords(owner string) []dns.RR {
	rrs, _ := zone.LookupRecord(dns.TypePTR, owner)
	return rrs
}

func enqueueCatalogMembers() {
	for _, member := range catalogMembers() {
		enqueueFetch(member)
	}
}

func zoneStore() interface {
	ZoneRecordsSnapshot(string) map[string]map[string]any
} {
	return rtypes.GetMemStore()
}
