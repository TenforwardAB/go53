package memory

import (
	"crypto"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/TenforwardAB/slog"
	"github.com/miekg/dns"
	"go53/config"
	"go53/internal"
	"go53/security"
	"go53/storage"
	"go53/types"
	"log"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
)

type InMemoryZoneStore struct {
	cache   map[string]map[string]map[string]map[string]any // "zones" -> zone -> type -> name -> record
	storage storage.Storage
	mu      sync.RWMutex
}

func NewZoneStore(s storage.Storage) (*InMemoryZoneStore, error) {
	zs := &InMemoryZoneStore{
		cache: map[string]map[string]map[string]map[string]any{
			"zones": {},
		},
		storage: s,
	}
	if err := zs.loadFromStorage(); err != nil {
		return nil, err
	}
	fmt.Printf("Estimated deep size: %d bytes\n", DeepSize(zs.cache))
	return zs, nil
}

func (z *InMemoryZoneStore) loadFromStorage() error {
	names, err := z.storage.ListZones()
	if err != nil {
		return err
	}
	dnssecPrimary := config.AppConfig.GetLive().DNSSECEnabled && config.AppConfig.GetLive().Mode != "secondary"
	z.mu.Lock()
	defer z.mu.Unlock()
	for _, zone := range names {
		raw, err := z.storage.LoadZone(zone)
		if err != nil {
			log.Printf("failed to load zone %s: %v", zone, err)
			continue
		}
		decoded, err := decodeZoneData(raw)
		if err != nil {
			log.Printf("failed to decode zone %s: %v", zone, err)
			continue
		}
		z.cache["zones"][zone] = decoded
		if dnssecPrimary {
			z.rebuildNSECChainLocked(zone)
			z.rebuildNSEC3ChainLocked(zone)
			if err := z.persist(zone); err != nil {
				log.Printf("failed to persist regenerated denial chains for %s: %v", zone, err)
			}
		}
	}

	return nil
}

func (z *InMemoryZoneStore) persist(zone string) error {
	data, err := encodeZoneData(z.cache["zones"][zone])
	if err != nil {
		return err
	}
	return z.storage.SaveZone(zone, data)
}

func (z *InMemoryZoneStore) AddRecord(zone, rtype, name string, record any) error {
	dnssecPrimary := config.AppConfig.GetLive().DNSSECEnabled && config.AppConfig.GetLive().Mode != "secondary"

	z.mu.Lock()
	zones := z.cache["zones"]
	if _, ok := zones[zone]; !ok {
		zones[zone] = make(map[string]map[string]any)
	}
	if _, ok := zones[zone][rtype]; !ok {
		zones[zone][rtype] = make(map[string]any)
	}
	zones[zone][rtype][name] = record
	if dnssecPrimary {
		z.invalidateRRSIGLocked(zone, rtype, name)
		if shouldMaintainNSEC(rtype) {
			z.rebuildNSECChainLocked(zone)
			z.rebuildNSEC3ChainLocked(zone)
		}
	}
	z.mu.Unlock()

	if !dnssecPrimary || rtype == string(types.TypeRRSIG) {
		return z.persist(zone)
	}

	go z.maybeSignRRSet(zone, rtype, name)
	if shouldMaintainNSEC(rtype) {
		go z.signNSECChain(zone)
		go z.signNSEC3Chain(zone)
	}

	return nil
}

func (z *InMemoryZoneStore) GetRecord(zone, rtype, name string) (string, string, any, bool) {
	z.mu.RLock()
	defer z.mu.RUnlock()
	zones := z.cache["zones"]
	recType, ok := zones[zone][rtype]
	if !ok {
		return "", "", nil, false
	}
	rec, exists := recType[name]
	return zone, rtype, rec, exists
}

func (z *InMemoryZoneStore) GetZone(zone string) ([]dns.RR, error) {
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return nil, err
	}

	z.mu.RLock()
	defer z.mu.RUnlock()

	zonesMap, ok := z.cache["zones"]
	log.Println("zonesMap: %v with length: %d", zonesMap, len(zonesMap))
	if !ok {
		return nil, errors.New("zones cache missing")
	}

	zoneMap, ok := zonesMap[sanitizedZone]
	log.Println("zoneMap", zoneMap)
	if !ok {
		return nil, errors.New("zone not found")
	}

	var allRRs []dns.RR

	for rtype, namesMap := range zoneMap {
		builder, ok := internal.RRBuilders[rtype]
		if !ok {
			slog.Warn("[GetZone] no builder for rtype", "rtype", rtype)
			continue
		}

		if rtype == "RRSIG" {
			// Special nested handling for RRSIG
			for _, innerData := range namesMap {
				innerMap, ok := innerData.(map[string]any)
				if !ok {
					slog.Warn("[GetZone] RRSIG innerData unexpected type", "type", reflect.TypeOf(innerData))
					continue
				}
				for innerName, rawData := range innerMap {
					//fqdn, _ := internal.SanitizeFQDN(innerName)
					slog.Emerg("[GetZone] RRSIG innerData fqdn: %s and data : %+v", innerName, rawData)
					rrs := builder(innerName, rawData)
					slog.Error("[GetZone] RRSIG rrs: %+v", rrs)
					allRRs = append(allRRs, rrs...)
				}
			}
			continue
		}

		// Handle other record types normally
		for name, rawData := range namesMap {
			var fqdn string
			switch {
			case name == "@":
				fqdn = sanitizedZone
			case dns.IsFqdn(name) && strings.HasSuffix(name, sanitizedZone):
				fqdn = name
			default:
				fqdn = name + "." + sanitizedZone
			}
			if sanitizedName, err := internal.SanitizeFQDN(fqdn); err == nil {
				fqdn = sanitizedName
			} else {
				fqdn = dns.Fqdn(fqdn)
			}
			rrs := builder(fqdn, rawData)
			if len(rrs) > 0 {
				allRRs = append(allRRs, rrs...)
			}
		}
	}

	return allRRs, nil
}

func (z *InMemoryZoneStore) DeleteRecord(zone, rtype, name string) error {
	z.mu.Lock()
	zones := z.cache["zones"]
	if recType, ok := zones[zone][rtype]; ok {
		delete(recType, name)
		dnssecPrimary := config.AppConfig.GetLive().DNSSECEnabled && config.AppConfig.GetLive().Mode != "secondary"
		if dnssecPrimary {
			z.invalidateRRSIGLocked(zone, rtype, name)
			if shouldMaintainNSEC(rtype) {
				z.rebuildNSECChainLocked(zone)
				z.rebuildNSEC3ChainLocked(zone)
			}
		}
		z.mu.Unlock()
		if err := z.persist(zone); err != nil {
			return err
		}
		if dnssecPrimary && shouldMaintainNSEC(rtype) {
			go z.signNSECChain(zone)
			go z.signNSEC3Chain(zone)
		}
		return nil
	}
	z.mu.Unlock()
	return errors.New("record type not found")

}

func (z *InMemoryZoneStore) DeleteZone(zone string) error {
	z.mu.Lock()
	defer z.mu.Unlock()

	zones := z.cache["zones"]
	if _, exists := zones[zone]; exists {
		delete(zones, zone)
		return z.storage.DeleteZone(zone)
	}

	return z.storage.DeleteZone(zone)
}

func (z *InMemoryZoneStore) EnsureSignedRRSet(rrs []dns.RR) ([]dns.RR, error) {
	if len(rrs) == 0 {
		return nil, errors.New("cannot sign empty RRSet")
	}
	if !config.AppConfig.GetLive().DNSSECEnabled || config.AppConfig.GetLive().Mode == "secondary" {
		return nil, nil
	}

	hdr := rrs[0].Header()
	if hdr.Rrtype == dns.TypeRRSIG {
		return nil, nil
	}
	for _, rr := range rrs[1:] {
		rrHdr := rr.Header()
		if !strings.EqualFold(rrHdr.Name, hdr.Name) || rrHdr.Rrtype != hdr.Rrtype || rrHdr.Class != hdr.Class {
			return nil, fmt.Errorf("RRSet contains mixed records: %s/%d and %s/%d", hdr.Name, hdr.Rrtype, rrHdr.Name, rrHdr.Rrtype)
		}
	}

	zoneName, shortName, ok := internal.SplitName(hdr.Name)
	if !ok {
		return nil, fmt.Errorf("cannot derive zone from %q", hdr.Name)
	}
	zoneName, err := internal.SanitizeFQDN(zoneName)
	if err != nil {
		return nil, err
	}
	typeName := dns.TypeToString[hdr.Rrtype]
	if typeName == "" {
		return nil, fmt.Errorf("unknown RR type %d", hdr.Rrtype)
	}

	if cached := z.cachedRRSIGs(zoneName, typeName, shortName, hdr.Rrtype, hdr.Name); len(cached) > 0 {
		return cached, nil
	}

	isDNSKEY := hdr.Rrtype == dns.TypeDNSKEY
	keyNames, err := security.GetDNSSECKeyNamesForRRSet(zoneName, isDNSKEY)
	if err != nil {
		return nil, err
	}

	var signed []dns.RR
	for _, keyName := range keyNames {
		privKey, storedKey, err := security.LoadPrivateKeyFromStorage(keyName)
		if err != nil {
			slog.Alert("Failed to load private key %q: %v", keyName, err)
			continue
		}

		signer, ok := privKey.(crypto.Signer)
		if !ok {
			slog.Alert("Key %q does not implement crypto.Signer", keyName)
			continue
		}

		signerName, _ := internal.SanitizeFQDN(storedKey.Zone)
		rrsig, err := security.SignRRSet(append([]dns.RR(nil), rrs...), signer, storedKey.KeyTag, signerName, security.AlgorithmNumberFromName(storedKey.Algorithm))
		if err != nil {
			slog.Error("Failed to query-time sign RRSet %q/%s with key %q: %v", hdr.Name, typeName, keyName, err)
			continue
		}

		z.storeRRSIG(zoneName, typeName, shortName, security.RRSIGFromDNS(rrsig))
		signed = append(signed, rrsig)
	}

	if len(signed) == 0 {
		return nil, fmt.Errorf("no usable DNSSEC key for %s %s", hdr.Name, typeName)
	}
	if err := z.persist(zoneName); err != nil {
		slog.Warn("Failed to persist query-time RRSIG cache for zone %q: %v", zoneName, err)
	}
	return signed, nil
}

func (z *InMemoryZoneStore) FindNSECProof(name string) ([]dns.RR, bool) {
	zoneName, _, ok := internal.SplitName(name)
	if !ok {
		return nil, false
	}
	zoneName, err := internal.SanitizeFQDN(zoneName)
	if err != nil {
		return nil, false
	}
	qname := strings.ToLower(dns.Fqdn(name))

	z.mu.RLock()
	defer z.mu.RUnlock()

	nsecMap, ok := z.cache["zones"][zoneName][string(types.TypeNSEC)]
	if !ok {
		return nil, false
	}

	for ownerName, raw := range nsecMap {
		owner := strings.ToLower(ownerFQDN(zoneName, ownerName))
		rec, ok := nsecRecordFromRaw(raw)
		if !ok {
			continue
		}
		next := strings.ToLower(dns.Fqdn(rec.NextDomain))
		if owner == qname || nsecCovers(owner, next, qname) {
			return []dns.RR{nsecRecordToDNS(ownerFQDN(zoneName, ownerName), rec)}, true
		}
	}

	return nil, false
}

func (z *InMemoryZoneStore) FindNSEC3Proof(name string) ([]dns.RR, bool) {
	zoneName, _, ok := internal.SplitName(name)
	if !ok {
		return nil, false
	}
	zoneName, err := internal.SanitizeFQDN(zoneName)
	if err != nil {
		return nil, false
	}

	z.mu.RLock()
	defer z.mu.RUnlock()

	params, ok := z.nsec3ParamsLocked(zoneName)
	if !ok {
		return nil, false
	}
	nsec3Map, ok := z.cache["zones"][zoneName][string(types.TypeNSEC3)]
	if !ok {
		return nil, false
	}

	hash := dns.HashName(dns.Fqdn(name), params.HashAlgorithm, params.Iterations, params.Salt)
	if hash == "" {
		return nil, false
	}

	if raw, ok := nsec3Map[hash]; ok {
		if rec, ok := nsec3RecordFromRaw(raw); ok {
			return []dns.RR{nsec3RecordToDNS(hash, zoneName, rec)}, true
		}
	}

	for ownerHash, raw := range nsec3Map {
		rec, ok := nsec3RecordFromRaw(raw)
		if !ok {
			continue
		}
		if nsec3Covers(strings.ToUpper(ownerHash), strings.ToUpper(rec.NextHashed), strings.ToUpper(hash)) {
			return []dns.RR{nsec3RecordToDNS(ownerHash, zoneName, rec)}, true
		}
	}

	return nil, false
}

func (z *InMemoryZoneStore) DenialProofs(name string, qtype uint16, nxdomain bool) []dns.RR {
	zoneName, _, ok := internal.SplitName(name)
	if !ok {
		return nil
	}
	zoneName, err := internal.SanitizeFQDN(zoneName)
	if err != nil {
		return nil
	}

	z.mu.RLock()
	defer z.mu.RUnlock()

	if proofs := z.nsec3DenialProofsLocked(zoneName, name, qtype, nxdomain); len(proofs) > 0 {
		return proofs
	}
	return z.nsecDenialProofsLocked(zoneName, name, qtype, nxdomain)
}

func (z *InMemoryZoneStore) NameExists(name string) bool {
	zoneName, _, ok := internal.SplitName(name)
	if !ok {
		return false
	}
	zoneName, err := internal.SanitizeFQDN(zoneName)
	if err != nil {
		return false
	}

	z.mu.RLock()
	defer z.mu.RUnlock()
	return z.ownerExistsLocked(zoneName, dns.Fqdn(name))
}

func (z *InMemoryZoneStore) WildcardExists(name string) bool {
	wildcard, ok := z.WildcardName(name)
	return ok && z.NameExists(wildcard)
}

func (z *InMemoryZoneStore) WildcardName(name string) (string, bool) {
	zoneName, _, ok := internal.SplitName(name)
	if !ok {
		return "", false
	}
	zoneName, err := internal.SanitizeFQDN(zoneName)
	if err != nil {
		return "", false
	}

	z.mu.RLock()
	defer z.mu.RUnlock()
	_, _, wildcard, ok := z.closestEncloserLocked(zoneName, name)
	return wildcard, ok
}

func (z *InMemoryZoneStore) DelegationFor(name string) (string, []dns.RR, bool) {
	zoneName, _, ok := internal.SplitName(name)
	if !ok {
		return "", nil, false
	}
	zoneName, err := internal.SanitizeFQDN(zoneName)
	if err != nil {
		return "", nil, false
	}

	z.mu.RLock()
	defer z.mu.RUnlock()

	delegation, ok := z.closestDelegationLocked(zoneName, name)
	if !ok {
		return "", nil, false
	}
	ns, ok := z.nsRecordsLocked(zoneName, delegation)
	return delegation, ns, ok
}

func (z *InMemoryZoneStore) maybeSignRRSet(zone, rtype, name string) {
	slog.Crazy("[maybeSignRRSet]", zone, rtype, name)

	//always persist first to make sure the current data is avablee on disc.
	_ = z.persist(zone)
	slog.Crazy("[maybeSignRRSet] DNSSEC is: %v", config.AppConfig.GetLive().DNSSECEnabled)
	if !config.AppConfig.GetLive().DNSSECEnabled {
		slog.Debug("[maybeSignRRSet] DNSSEC disabled, skipping signing")
		return
	} else if config.AppConfig.GetLive().Mode == "secondary" {
		slog.Warn("[maybeSignRRSet] Is secondary, skipping signing, done in primary only")
		return
	}

	_, _, record, ok := z.GetRecord(zone, rtype, name)
	if !ok {
		slog.Debug("Record for zone: %s of type %s and name %s NOT FOUND", zone, rtype, name)
	}

	slog.Crazy("[maybeSignRRSet] Record is: %s ", record)

	rrsetName := name
	switch {
	case rrsetName == "@":
		rrsetName = zone
	case !dns.IsFqdn(rrsetName):
		rrsetName = rrsetName + "." + zone
	}

	rrs, err := security.ToRRSet(rrsetName, rtype, record)
	slog.Crazy("rrs is: %v", rrs)
	if err != nil || len(rrs) == 0 {
		slog.Error("ERROR ToRRSet:", err)
		return
	}

	isDNSKEY := rtype == string(types.TypeDNSKEY)
	keyNames, err := security.GetDNSSECKeyNamesForRRSet(zone, isDNSKEY)
	slog.Crazy("[maybeSignRRSet] keyNames", keyNames)
	if err != nil {
		return
	}

	for _, keyName := range keyNames {
		privKey, storedKey, err := security.LoadPrivateKeyFromStorage(keyName)
		if err != nil {
			slog.Alert("Failed to load private key %q: %v", keyName, err)
			continue
		}

		signer, ok := privKey.(crypto.Signer)
		if !ok {
			slog.Alert("Key %q does not implement crypto.Signer", keyName)
			continue
		}
		fqdn, _ := internal.SanitizeFQDN(storedKey.Zone)

		rrsig, err := security.SignRRSet(rrs, signer, storedKey.KeyTag, fqdn, security.AlgorithmNumberFromName(storedKey.Algorithm))
		slog.Crazy("!!!!!!!!!!!!!!!!!!!![maybeSignRRSet] rrsig is: %v !!!!!!!!!!!!!!!!!", rrsig)
		if err != nil {
			slog.Error("Failed to sign RRSet with key %q: %v", keyName, err)
			continue
		}

		typeName := dns.TypeToString[rrsig.TypeCovered]
		z.storeRRSIG(zone, typeName, name, security.RRSIGFromDNS(rrsig))

		slog.Debug("Successfully signed RRSet for %q with key %q (keyTag=%d)", name, keyName, storedKey.KeyTag)
	}

	_ = z.persist(zone)
}

func (z *InMemoryZoneStore) cachedRRSIGs(zone, typeName, name string, covered uint16, owner string) []dns.RR {
	z.mu.RLock()
	defer z.mu.RUnlock()

	raw, ok := z.cache["zones"][zone]["RRSIG"][typeName]
	if !ok {
		return nil
	}

	typeMap, ok := raw.(map[string]any)
	if !ok {
		return nil
	}

	rawList, ok := typeMap[name]
	if !ok {
		return nil
	}

	var out []dns.RR
	now := time.Now()
	for _, sig := range rrsigRecordsFromRaw(rawList) {
		if sig.TypeCovered != dns.TypeToString[covered] {
			continue
		}
		if !security.RRSIGFresh(owner, sig, covered, now) {
			continue
		}
		rrsig, err := rrsigRecordToDNS(owner, sig)
		if err != nil {
			continue
		}
		if rrsig.TypeCovered != covered {
			continue
		}
		out = append(out, rrsig)
	}
	return out
}

func (z *InMemoryZoneStore) storeRRSIG(zone, typeName, name string, rec *types.RRSIGRecord) {
	if rec == nil {
		return
	}

	z.mu.Lock()
	defer z.mu.Unlock()

	if _, ok := z.cache["zones"][zone]; !ok {
		z.cache["zones"][zone] = make(map[string]map[string]any)
	}
	if _, ok := z.cache["zones"][zone]["RRSIG"]; !ok {
		z.cache["zones"][zone]["RRSIG"] = make(map[string]any)
	}

	rMap := z.cache["zones"][zone]["RRSIG"]
	typedMap, ok := rMap[typeName].(map[string]any)
	if !ok {
		typedMap = make(map[string]any)
		rMap[typeName] = typedMap
	}

	var updated []interface{}
	for _, existing := range rrsigRecordsFromRaw(typedMap[name]) {
		if existing.KeyTag == rec.KeyTag && existing.Algorithm == rec.Algorithm && existing.TypeCovered == rec.TypeCovered {
			continue
		}
		updated = append(updated, existing)
	}
	updated = append(updated, rec)
	typedMap[name] = updated
}

func shouldMaintainNSEC(rtype string) bool {
	switch rtype {
	case string(types.TypeRRSIG), string(types.TypeNSEC), string(types.TypeNSEC3):
		return false
	default:
		return true
	}
}

const nsec3OptOutFlag uint8 = 0x01

func nsec3OptOutEnabled(params types.NSEC3ParamRecord) bool {
	return params.Flags&nsec3OptOutFlag != 0
}

func isUnsignedDelegationOwner(name string, typesForOwner map[string]bool) bool {
	if name == "@" {
		return false
	}
	if !typesForOwner[string(types.TypeNS)] {
		return false
	}
	if typesForOwner[string(types.TypeDS)] || typesForOwner[string(types.TypeSOA)] {
		return false
	}
	return true
}

func nsec3IntervalHasOmittedOptOut(ownerHash, nextHash string, omittedHashes []string) bool {
	for _, omittedHash := range omittedHashes {
		if nsec3Covers(strings.ToUpper(ownerHash), strings.ToUpper(nextHash), strings.ToUpper(omittedHash)) {
			return true
		}
	}
	return false
}

func (z *InMemoryZoneStore) rebuildNSECChainLocked(zone string) {
	zoneMap, ok := z.cache["zones"][zone]
	if !ok {
		return
	}

	owners := make(map[string]map[string]bool)
	for rtype, namesMap := range zoneMap {
		if rtype == string(types.TypeRRSIG) || rtype == string(types.TypeNSEC) || rtype == string(types.TypeNSEC3) {
			continue
		}
		for name, raw := range namesMap {
			if raw == nil {
				continue
			}
			if _, ok := owners[name]; !ok {
				owners[name] = make(map[string]bool)
			}
			owners[name][rtype] = true
		}
	}

	if len(owners) == 0 {
		delete(zoneMap, string(types.TypeNSEC))
		z.invalidateAllRRSIGLocked(zone, string(types.TypeNSEC))
		return
	}

	names := make([]string, 0, len(owners))
	for name := range owners {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		return nsecCompare(ownerFQDN(zone, names[i]), ownerFQDN(zone, names[j])) < 0
	})

	ttl := uint32(config.AppConfig.GetLive().DefaultTTL)
	if ttl == 0 {
		ttl = 3600
	}

	nsecMap := make(map[string]any, len(names))
	for i, name := range names {
		next := names[(i+1)%len(names)]
		typesForOwner := owners[name]
		typesForOwner[string(types.TypeNSEC)] = true
		typesForOwner[string(types.TypeRRSIG)] = true

		typeList := make([]string, 0, len(typesForOwner))
		for rtype := range typesForOwner {
			typeList = append(typeList, rtype)
		}
		sort.Slice(typeList, func(i, j int) bool {
			return dns.StringToType[typeList[i]] < dns.StringToType[typeList[j]]
		})

		nsecMap[name] = types.NSECRecord{
			NextDomain: ownerFQDN(zone, next),
			Types:      typeList,
			TTL:        ttl,
		}
	}

	zoneMap[string(types.TypeNSEC)] = nsecMap
	z.invalidateAllRRSIGLocked(zone, string(types.TypeNSEC))
}

func (z *InMemoryZoneStore) rebuildNSEC3ChainLocked(zone string) {
	zoneMap, ok := z.cache["zones"][zone]
	if !ok {
		return
	}

	params, ok := z.nsec3ParamsLocked(zone)
	if !ok {
		delete(zoneMap, string(types.TypeNSEC3))
		z.invalidateAllRRSIGLocked(zone, string(types.TypeNSEC3))
		return
	}

	owners := make(map[string]map[string]bool)
	omittedOptOut := make(map[string]bool)
	for rtype, namesMap := range zoneMap {
		if rtype == string(types.TypeRRSIG) || rtype == string(types.TypeNSEC) || rtype == string(types.TypeNSEC3) {
			continue
		}
		for name, raw := range namesMap {
			if raw == nil {
				continue
			}
			if _, ok := owners[name]; !ok {
				owners[name] = make(map[string]bool)
			}
			owners[name][rtype] = true
		}
	}

	if nsec3OptOutEnabled(params) {
		for name, typesForOwner := range owners {
			if isUnsignedDelegationOwner(name, typesForOwner) {
				omittedOptOut[name] = true
				delete(owners, name)
			}
		}
	}

	if len(owners) == 0 {
		delete(zoneMap, string(types.TypeNSEC3))
		z.invalidateAllRRSIGLocked(zone, string(types.TypeNSEC3))
		return
	}

	type hashedOwner struct {
		name string
		hash string
	}
	hashed := make([]hashedOwner, 0, len(owners))
	for name := range owners {
		hash := dns.HashName(ownerFQDN(zone, name), params.HashAlgorithm, params.Iterations, params.Salt)
		if hash == "" {
			continue
		}
		hashed = append(hashed, hashedOwner{name: name, hash: strings.ToUpper(hash)})
	}
	omittedHashes := make([]string, 0, len(omittedOptOut))
	for name := range omittedOptOut {
		hash := dns.HashName(ownerFQDN(zone, name), params.HashAlgorithm, params.Iterations, params.Salt)
		if hash == "" {
			continue
		}
		omittedHashes = append(omittedHashes, strings.ToUpper(hash))
	}
	sort.Slice(hashed, func(i, j int) bool {
		return hashed[i].hash < hashed[j].hash
	})

	if len(hashed) == 0 {
		delete(zoneMap, string(types.TypeNSEC3))
		z.invalidateAllRRSIGLocked(zone, string(types.TypeNSEC3))
		return
	}

	ttl := params.TTL
	if ttl == 0 {
		ttl = uint32(config.AppConfig.GetLive().DefaultTTL)
	}
	if ttl == 0 {
		ttl = 3600
	}

	nsec3Map := make(map[string]any, len(hashed))
	for i, owner := range hashed {
		next := hashed[(i+1)%len(hashed)]
		typesForOwner := owners[owner.name]
		typesForOwner[string(types.TypeNSEC3)] = true
		typesForOwner[string(types.TypeRRSIG)] = true

		typeList := make([]string, 0, len(typesForOwner))
		for rtype := range typesForOwner {
			typeList = append(typeList, rtype)
		}
		sort.Slice(typeList, func(i, j int) bool {
			return dns.StringToType[typeList[i]] < dns.StringToType[typeList[j]]
		})

		flags := uint8(0)
		if nsec3IntervalHasOmittedOptOut(owner.hash, next.hash, omittedHashes) {
			flags = nsec3OptOutFlag
		}

		nsec3Map[owner.hash] = types.NSEC3Record{
			HashAlg:    params.HashAlgorithm,
			Flags:      flags,
			Iterations: params.Iterations,
			Salt:       params.Salt,
			NextHashed: next.hash,
			Types:      typeList,
			TTL:        ttl,
		}
	}

	zoneMap[string(types.TypeNSEC3)] = nsec3Map
	z.invalidateAllRRSIGLocked(zone, string(types.TypeNSEC3))
}

func (z *InMemoryZoneStore) signNSECChain(zone string) {
	z.mu.RLock()
	nsecMap, ok := z.cache["zones"][zone][string(types.TypeNSEC)]
	if !ok {
		z.mu.RUnlock()
		return
	}
	names := make([]string, 0, len(nsecMap))
	for name := range nsecMap {
		names = append(names, name)
	}
	z.mu.RUnlock()

	for _, name := range names {
		z.maybeSignRRSet(zone, string(types.TypeNSEC), name)
	}
}

func (z *InMemoryZoneStore) signNSEC3Chain(zone string) {
	z.mu.RLock()
	nsec3Map, ok := z.cache["zones"][zone][string(types.TypeNSEC3)]
	if !ok {
		z.mu.RUnlock()
		return
	}
	names := make([]string, 0, len(nsec3Map))
	for name := range nsec3Map {
		names = append(names, name)
	}
	z.mu.RUnlock()

	for _, name := range names {
		z.maybeSignRRSet(zone, string(types.TypeNSEC3), name)
	}
}

func (z *InMemoryZoneStore) invalidateRRSIGLocked(zone, typeName, name string) {
	zoneMap, ok := z.cache["zones"][zone]
	if !ok {
		return
	}
	rrsigMap, ok := zoneMap[string(types.TypeRRSIG)]
	if !ok {
		return
	}
	raw, ok := rrsigMap[typeName]
	if !ok {
		return
	}
	typedMap, ok := raw.(map[string]any)
	if !ok {
		return
	}
	delete(typedMap, name)
}

func (z *InMemoryZoneStore) invalidateAllRRSIGLocked(zone, typeName string) {
	zoneMap, ok := z.cache["zones"][zone]
	if !ok {
		return
	}
	if rrsigMap, ok := zoneMap[string(types.TypeRRSIG)]; ok {
		delete(rrsigMap, typeName)
	}
}

func ownerFQDN(zone, name string) string {
	switch {
	case name == "@":
		return dns.Fqdn(zone)
	case dns.IsFqdn(name):
		return dns.Fqdn(name)
	default:
		return dns.Fqdn(name + "." + zone)
	}
}

func (z *InMemoryZoneStore) nsecDenialProofsLocked(zone, name string, qtype uint16, nxdomain bool) []dns.RR {
	qname := dns.Fqdn(name)
	exact := z.ownerExistsLocked(zone, qname)
	closest, nextCloser, wildcard, hasClosest := z.closestEncloserLocked(zone, qname)

	var proofs []dns.RR
	add := func(rrs []dns.RR) {
		for _, rr := range rrs {
			if rr != nil {
				proofs = append(proofs, rr)
			}
		}
	}

	switch {
	case nxdomain:
		if hasClosest {
			if rr, ok := z.nsecProofLocked(zone, nextCloser); ok {
				add(rr)
			}
			if rr, ok := z.nsecProofLocked(zone, wildcard); ok {
				add(rr)
			}
		} else if rr, ok := z.nsecProofLocked(zone, qname); ok {
			add(rr)
		}
	case !exact && hasClosest && z.ownerExistsLocked(zone, wildcard):
		if rr, ok := z.nsecExactLocked(zone, closest); ok {
			add(rr)
		}
		if rr, ok := z.nsecExactLocked(zone, wildcard); ok {
			add(rr)
		}
	default:
		if rr, ok := z.nsecExactLocked(zone, qname); ok {
			add(rr)
		} else if rr, ok := z.nsecProofLocked(zone, qname); ok {
			add(rr)
		}
	}

	_ = qtype
	return uniqueRRs(proofs)
}

func (z *InMemoryZoneStore) nsec3DenialProofsLocked(zone, name string, qtype uint16, nxdomain bool) []dns.RR {
	params, ok := z.nsec3ParamsLocked(zone)
	if !ok {
		return nil
	}
	if _, ok := z.cache["zones"][zone][string(types.TypeNSEC3)]; !ok {
		return nil
	}

	qname := dns.Fqdn(name)
	exact := z.ownerExistsLocked(zone, qname)
	closest, nextCloser, wildcard, hasClosest := z.closestEncloserLocked(zone, qname)

	var proofs []dns.RR
	add := func(rr dns.RR, ok bool) {
		if ok && rr != nil {
			proofs = append(proofs, rr)
		}
	}

	switch {
	case nxdomain:
		if hasClosest {
			add(z.nsec3MatchingLocked(zone, closest, params))
			add(z.nsec3CoveringLocked(zone, nextCloser, params, true))
			add(z.nsec3CoveringLocked(zone, wildcard, params, false))
		} else {
			add(z.nsec3CoveringLocked(zone, qname, params, true))
		}
	case !exact && hasClosest && z.ownerExistsLocked(zone, wildcard):
		add(z.nsec3MatchingLocked(zone, closest, params))
		add(z.nsec3MatchingLocked(zone, wildcard, params))
	default:
		add(z.nsec3MatchingLocked(zone, qname, params))
	}

	_ = qtype
	return uniqueRRs(proofs)
}

func (z *InMemoryZoneStore) nsecProofLocked(zone, name string) ([]dns.RR, bool) {
	if rr, ok := z.nsecExactLocked(zone, name); ok {
		return rr, true
	}
	return z.nsecCoveringLocked(zone, name)
}

func (z *InMemoryZoneStore) nsecExactLocked(zone, name string) ([]dns.RR, bool) {
	nsecMap, ok := z.cache["zones"][zone][string(types.TypeNSEC)]
	if !ok {
		return nil, false
	}
	qname := strings.ToLower(dns.Fqdn(name))
	for ownerName, raw := range nsecMap {
		owner := strings.ToLower(ownerFQDN(zone, ownerName))
		if owner != qname {
			continue
		}
		rec, ok := nsecRecordFromRaw(raw)
		if !ok {
			return nil, false
		}
		return []dns.RR{nsecRecordToDNS(ownerFQDN(zone, ownerName), rec)}, true
	}
	return nil, false
}

func (z *InMemoryZoneStore) nsecCoveringLocked(zone, name string) ([]dns.RR, bool) {
	nsecMap, ok := z.cache["zones"][zone][string(types.TypeNSEC)]
	if !ok {
		return nil, false
	}
	qname := strings.ToLower(dns.Fqdn(name))
	for ownerName, raw := range nsecMap {
		owner := strings.ToLower(ownerFQDN(zone, ownerName))
		rec, ok := nsecRecordFromRaw(raw)
		if !ok {
			continue
		}
		next := strings.ToLower(dns.Fqdn(rec.NextDomain))
		if nsecCovers(owner, next, qname) {
			return []dns.RR{nsecRecordToDNS(ownerFQDN(zone, ownerName), rec)}, true
		}
	}
	return nil, false
}

func (z *InMemoryZoneStore) nsec3MatchingLocked(zone, name string, params types.NSEC3ParamRecord) (dns.RR, bool) {
	nsec3Map, ok := z.cache["zones"][zone][string(types.TypeNSEC3)]
	if !ok {
		return nil, false
	}
	hash := strings.ToUpper(dns.HashName(dns.Fqdn(name), params.HashAlgorithm, params.Iterations, params.Salt))
	if hash == "" {
		return nil, false
	}
	raw, ok := nsec3Map[hash]
	if !ok {
		return nil, false
	}
	rec, ok := nsec3RecordFromRaw(raw)
	if !ok {
		return nil, false
	}
	return nsec3RecordToDNS(hash, zone, rec), true
}

func (z *InMemoryZoneStore) nsec3CoveringLocked(zone, name string, params types.NSEC3ParamRecord, allowOptOut bool) (dns.RR, bool) {
	nsec3Map, ok := z.cache["zones"][zone][string(types.TypeNSEC3)]
	if !ok {
		return nil, false
	}
	hash := strings.ToUpper(dns.HashName(dns.Fqdn(name), params.HashAlgorithm, params.Iterations, params.Salt))
	if hash == "" {
		return nil, false
	}
	for ownerHash, raw := range nsec3Map {
		rec, ok := nsec3RecordFromRaw(raw)
		if !ok {
			continue
		}
		if rec.Flags&nsec3OptOutFlag != 0 && !allowOptOut {
			continue
		}
		if nsec3Covers(strings.ToUpper(ownerHash), strings.ToUpper(rec.NextHashed), hash) {
			return nsec3RecordToDNS(ownerHash, zone, rec), true
		}
	}
	return nil, false
}

func (z *InMemoryZoneStore) closestEncloserLocked(zone, name string) (string, string, string, bool) {
	qname := dns.Fqdn(name)
	zoneFQDN := dns.Fqdn(zone)
	if !strings.HasSuffix(strings.ToLower(qname), strings.ToLower(zoneFQDN)) {
		return "", "", "", false
	}

	labels := dns.SplitDomainName(qname)
	for i := 0; i < len(labels); i++ {
		candidate := dns.Fqdn(strings.Join(labels[i:], "."))
		if !z.ownerExistsLocked(zone, candidate) {
			continue
		}
		nextCloser := qname
		if i > 0 {
			nextCloser = dns.Fqdn(strings.Join(labels[i-1:], "."))
		}
		wildcard := dns.Fqdn("*." + candidate)
		return candidate, nextCloser, wildcard, true
	}

	return "", "", "", false
}

func (z *InMemoryZoneStore) closestDelegationLocked(zone, name string) (string, bool) {
	qname := dns.Fqdn(name)
	zoneFQDN := dns.Fqdn(zone)
	if !strings.HasSuffix(strings.ToLower(qname), strings.ToLower(zoneFQDN)) {
		return "", false
	}

	labels := dns.SplitDomainName(qname)
	for i := 0; i < len(labels); i++ {
		candidate := dns.Fqdn(strings.Join(labels[i:], "."))
		if strings.EqualFold(candidate, zoneFQDN) {
			return "", false
		}
		if z.ownerHasTypeLocked(zone, candidate, string(types.TypeNS)) && !z.ownerHasTypeLocked(zone, candidate, string(types.TypeSOA)) {
			return candidate, true
		}
	}
	return "", false
}

func (z *InMemoryZoneStore) nsRecordsLocked(zone, name string) ([]dns.RR, bool) {
	rel, ok := relativeOwner(zone, name)
	if !ok {
		return nil, false
	}
	zoneMap, ok := z.cache["zones"][zone]
	if !ok {
		return nil, false
	}
	raw, ok := zoneMap[string(types.TypeNS)][rel]
	if !ok {
		return nil, false
	}

	var records []types.NSRecord
	switch v := raw.(type) {
	case []types.NSRecord:
		records = append(records, v...)
	case []interface{}:
		for _, item := range v {
			obj, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			ns, _ := obj["ns"].(string)
			if ns == "" {
				continue
			}
			ttl := uint32(3600)
			if t, ok := obj["ttl"].(float64); ok {
				ttl = uint32(t)
			}
			records = append(records, types.NSRecord{NS: dns.Fqdn(ns), TTL: ttl})
		}
	}
	if len(records) == 0 {
		return nil, false
	}

	out := make([]dns.RR, 0, len(records))
	for _, rec := range records {
		out = append(out, &dns.NS{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(name),
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    rec.TTL,
			},
			Ns: dns.Fqdn(rec.NS),
		})
	}
	return out, true
}

func (z *InMemoryZoneStore) ownerExistsLocked(zone, name string) bool {
	rel, ok := relativeOwner(zone, name)
	if !ok {
		return false
	}
	zoneMap, ok := z.cache["zones"][zone]
	if !ok {
		return false
	}
	for rtype, namesMap := range zoneMap {
		if !shouldMaintainNSEC(rtype) {
			continue
		}
		if _, ok := namesMap[rel]; ok {
			return true
		}
	}
	return false
}

func (z *InMemoryZoneStore) ownerHasTypeLocked(zone, name, rtype string) bool {
	rel, ok := relativeOwner(zone, name)
	if !ok {
		return false
	}
	zoneMap, ok := z.cache["zones"][zone]
	if !ok {
		return false
	}
	namesMap, ok := zoneMap[rtype]
	if !ok {
		return false
	}
	_, ok = namesMap[rel]
	return ok
}

func relativeOwner(zone, name string) (string, bool) {
	fqdn := strings.ToLower(dns.Fqdn(name))
	zoneFQDN := strings.ToLower(dns.Fqdn(zone))
	switch {
	case fqdn == zoneFQDN:
		return "@", true
	case strings.HasSuffix(fqdn, "."+zoneFQDN):
		return strings.TrimSuffix(fqdn[:len(fqdn)-len(zoneFQDN)-1], "."), true
	default:
		return "", false
	}
}

func uniqueRRs(rrs []dns.RR) []dns.RR {
	seen := make(map[string]bool, len(rrs))
	unique := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		key := rr.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		unique = append(unique, rr)
	}
	return unique
}

func nsecRecordFromRaw(raw any) (types.NSECRecord, bool) {
	switch v := raw.(type) {
	case types.NSECRecord:
		return v, true
	case map[string]interface{}:
		rec := types.NSECRecord{TTL: 3600}
		rec.NextDomain, _ = v["next_domain"].(string)
		if f, ok := v["ttl"].(float64); ok {
			rec.TTL = uint32(f)
		}
		if arr, ok := v["types"].([]interface{}); ok {
			for _, item := range arr {
				if s, ok := item.(string); ok {
					rec.Types = append(rec.Types, s)
				}
			}
		}
		return rec, rec.NextDomain != ""
	default:
		return types.NSECRecord{}, false
	}
}

func nsecRecordToDNS(owner string, rec types.NSECRecord) *dns.NSEC {
	var bitmap []uint16
	for _, t := range rec.Types {
		if code, ok := dns.StringToType[strings.ToUpper(t)]; ok {
			bitmap = append(bitmap, code)
		}
	}
	sort.Slice(bitmap, func(i, j int) bool {
		return bitmap[i] < bitmap[j]
	})
	return &dns.NSEC{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(owner),
			Rrtype: dns.TypeNSEC,
			Class:  dns.ClassINET,
			Ttl:    rec.TTL,
		},
		NextDomain: dns.Fqdn(rec.NextDomain),
		TypeBitMap: bitmap,
	}
}

func (z *InMemoryZoneStore) nsec3ParamsLocked(zone string) (types.NSEC3ParamRecord, bool) {
	zoneMap, ok := z.cache["zones"][zone]
	if !ok {
		return types.NSEC3ParamRecord{}, false
	}
	paramsMap, ok := zoneMap[string(types.TypeNSECPARAM)]
	if !ok {
		paramsMap, ok = zoneMap["NSEC3PARAM"]
		if !ok {
			return types.NSEC3ParamRecord{}, false
		}
	}
	raw, ok := paramsMap["@"]
	if !ok {
		return types.NSEC3ParamRecord{}, false
	}
	return nsec3ParamFromRaw(raw)
}

func nsec3ParamFromRaw(raw any) (types.NSEC3ParamRecord, bool) {
	switch v := raw.(type) {
	case types.NSEC3ParamRecord:
		return v, true
	case map[string]interface{}:
		rec := types.NSEC3ParamRecord{TTL: 3600}
		if f, ok := v["hash_algorithm"].(float64); ok {
			rec.HashAlgorithm = uint8(f)
		}
		if f, ok := v["flags"].(float64); ok {
			rec.Flags = uint8(f)
		}
		if f, ok := v["iterations"].(float64); ok {
			rec.Iterations = uint16(f)
		}
		if s, ok := v["salt"].(string); ok {
			rec.Salt = strings.TrimSpace(s)
			if rec.Salt == "-" {
				rec.Salt = ""
			}
		}
		if f, ok := v["ttl"].(float64); ok {
			rec.TTL = uint32(f)
		}
		return rec, rec.HashAlgorithm != 0
	default:
		return types.NSEC3ParamRecord{}, false
	}
}

func nsec3RecordFromRaw(raw any) (types.NSEC3Record, bool) {
	switch v := raw.(type) {
	case types.NSEC3Record:
		return v, true
	case map[string]interface{}:
		rec := types.NSEC3Record{TTL: 3600}
		if f, ok := v["hash_algorithm"].(float64); ok {
			rec.HashAlg = uint8(f)
		}
		if f, ok := v["flags"].(float64); ok {
			rec.Flags = uint8(f)
		}
		if f, ok := v["iterations"].(float64); ok {
			rec.Iterations = uint16(f)
		}
		if s, ok := v["salt"].(string); ok {
			rec.Salt = strings.TrimSpace(s)
			if rec.Salt == "-" {
				rec.Salt = ""
			}
		}
		rec.NextHashed, _ = v["next_hashed"].(string)
		if arr, ok := v["types"].([]interface{}); ok {
			for _, item := range arr {
				if s, ok := item.(string); ok {
					rec.Types = append(rec.Types, s)
				}
			}
		}
		if f, ok := v["ttl"].(float64); ok {
			rec.TTL = uint32(f)
		}
		return rec, rec.HashAlg != 0 && rec.NextHashed != ""
	default:
		return types.NSEC3Record{}, false
	}
}

func nsec3RecordToDNS(hash, zone string, rec types.NSEC3Record) *dns.NSEC3 {
	var bitmap []uint16
	for _, t := range rec.Types {
		if code, ok := dns.StringToType[strings.ToUpper(t)]; ok {
			bitmap = append(bitmap, code)
		}
	}
	sort.Slice(bitmap, func(i, j int) bool {
		return bitmap[i] < bitmap[j]
	})
	return &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(hash + "." + zone),
			Rrtype: dns.TypeNSEC3,
			Class:  dns.ClassINET,
			Ttl:    rec.TTL,
		},
		Hash:       rec.HashAlg,
		Flags:      rec.Flags,
		Iterations: rec.Iterations,
		SaltLength: uint8(nsec3SaltLength(rec.Salt)),
		Salt:       rec.Salt,
		HashLength: uint8(nsec3HashLength(rec.NextHashed)),
		NextDomain: rec.NextHashed,
		TypeBitMap: bitmap,
	}
}

func nsec3Covers(ownerHash, nextHash, qHash string) bool {
	switch {
	case ownerHash == nextHash:
		return qHash != ownerHash
	case ownerHash < nextHash:
		return ownerHash < qHash && qHash < nextHash
	default:
		return qHash > ownerHash || qHash < nextHash
	}
}

func nsec3HashLength(value string) int {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" {
		return 0
	}
	decoded, err := base32.HexEncoding.WithPadding(base32.NoPadding).DecodeString(value)
	if err != nil {
		return 0
	}
	return len(decoded)
}

func nsec3SaltLength(value string) int {
	value = strings.TrimSpace(value)
	if value == "" || value == "-" {
		return 0
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return 0
	}
	return len(decoded)
}

func nsecCovers(owner, next, qname string) bool {
	ownerCmpNext := nsecCompare(owner, next)
	ownerCmpQ := nsecCompare(owner, qname)
	qCmpNext := nsecCompare(qname, next)

	switch {
	case ownerCmpNext == 0:
		return ownerCmpQ != 0
	case ownerCmpNext < 0:
		return ownerCmpQ < 0 && qCmpNext < 0
	default:
		return ownerCmpQ < 0 || qCmpNext < 0
	}
}

func nsecCompare(a, b string) int {
	return internal.CanonicalDNSSECNameCompare(a, b)
}

func rrsigRecordsFromRaw(raw any) []*types.RRSIGRecord {
	switch v := raw.(type) {
	case []interface{}:
		var out []*types.RRSIGRecord
		for _, item := range v {
			switch sig := item.(type) {
			case *types.RRSIGRecord:
				out = append(out, sig)
			case types.RRSIGRecord:
				sigCopy := sig
				out = append(out, &sigCopy)
			case map[string]interface{}:
				if parsed := rrsigRecordFromMap(sig); parsed != nil {
					out = append(out, parsed)
				}
			}
		}
		return out
	case []*types.RRSIGRecord:
		return v
	case []types.RRSIGRecord:
		out := make([]*types.RRSIGRecord, 0, len(v))
		for i := range v {
			out = append(out, &v[i])
		}
		return out
	case *types.RRSIGRecord:
		return []*types.RRSIGRecord{v}
	case types.RRSIGRecord:
		return []*types.RRSIGRecord{&v}
	case map[string]interface{}:
		if parsed := rrsigRecordFromMap(v); parsed != nil {
			return []*types.RRSIGRecord{parsed}
		}
	}
	return nil
}

func rrsigRecordFromMap(raw map[string]interface{}) *types.RRSIGRecord {
	rec := &types.RRSIGRecord{}
	if s, ok := raw["type_covered"].(string); ok {
		rec.TypeCovered = s
	}
	if f, ok := raw["algorithm"].(float64); ok {
		rec.Algorithm = uint8(f)
	}
	if f, ok := raw["labels"].(float64); ok {
		rec.Labels = uint8(f)
	}
	if f, ok := raw["original_ttl"].(float64); ok {
		rec.OrigTTL = uint32(f)
	}
	if f, ok := raw["expiration"].(float64); ok {
		rec.Expiration = uint32(f)
	}
	if f, ok := raw["inception"].(float64); ok {
		rec.Inception = uint32(f)
	}
	if f, ok := raw["key_tag"].(float64); ok {
		rec.KeyTag = uint16(f)
	}
	if s, ok := raw["signer_name"].(string); ok {
		rec.SignerName = s
	}
	if s, ok := raw["signature"].(string); ok {
		rec.Signature = s
	}
	if f, ok := raw["ttl"].(float64); ok {
		rec.TTL = uint32(f)
	}
	if rec.TypeCovered == "" || rec.Signature == "" {
		return nil
	}
	return rec
}

func rrsigRecordToDNS(owner string, sig *types.RRSIGRecord) (*dns.RRSIG, error) {
	covered, ok := dns.StringToType[sig.TypeCovered]
	if !ok {
		return nil, fmt.Errorf("invalid type_covered: %s", sig.TypeCovered)
	}
	fqdn, err := internal.SanitizeFQDN(owner)
	if err != nil {
		fqdn = dns.Fqdn(owner)
	}
	return &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   fqdn,
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    sig.TTL,
		},
		TypeCovered: covered,
		Algorithm:   sig.Algorithm,
		Labels:      sig.Labels,
		OrigTtl:     sig.OrigTTL,
		Expiration:  sig.Expiration,
		Inception:   sig.Inception,
		KeyTag:      sig.KeyTag,
		SignerName:  sig.SignerName,
		Signature:   sig.Signature,
	}, nil
}
