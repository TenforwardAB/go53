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
	"strings"

	"github.com/miekg/dns"
)

const catalogVersion = "2"

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
