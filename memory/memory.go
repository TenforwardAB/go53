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

	keyNames, err := security.GetDNSSECKeyNames(zoneName)
	if err != nil {
		return nil, err
	}

	isDNSKEY := hdr.Rrtype == dns.TypeDNSKEY
	var signed []dns.RR
	for _, keyName := range keyNames {
		if isDNSKEY && !strings.HasPrefix(keyName, "ksk_") {
			continue
		}
		if !isDNSKEY && !strings.HasPrefix(keyName, "zsk_") {
			continue
		}

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

	keyNames, err := security.GetDNSSECKeyNames(zone)
	slog.Crazy("[maybeSignRRSet] keyNames", keyNames)
	if err != nil {
		return
	}

	isDNSKEY := rtype == string(types.TypeDNSKEY)

	for _, keyName := range keyNames {
		if isDNSKEY && !strings.HasPrefix(keyName, "ksk_") {
			slog.Debug("Skipping key %q: not a KSK and DNSKEY is being signed", keyName)
			continue
		}
		if !isDNSKEY && !strings.HasPrefix(keyName, "zsk_") {
			slog.Debug("Skipping key %q: not a ZSK and non-DNSKEY record is being signed", keyName)
			continue
		}

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
	now := uint32(time.Now().Unix())
	for _, sig := range rrsigRecordsFromRaw(rawList) {
		if sig.TypeCovered != dns.TypeToString[covered] {
			continue
		}
		if sig.Inception > now || sig.Expiration <= now {
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

		nsec3Map[owner.hash] = types.NSEC3Record{
			HashAlg:    params.HashAlgorithm,
			Flags:      params.Flags,
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
	aLabels := reverseLabels(a)
	bLabels := reverseLabels(b)
	limit := len(aLabels)
	if len(bLabels) < limit {
		limit = len(bLabels)
	}
	for i := 0; i < limit; i++ {
		switch {
		case aLabels[i] < bLabels[i]:
			return -1
		case aLabels[i] > bLabels[i]:
			return 1
		}
	}
	switch {
	case len(aLabels) < len(bLabels):
		return -1
	case len(aLabels) > len(bLabels):
		return 1
	default:
		return 0
	}
}

func reverseLabels(name string) []string {
	trimmed := strings.TrimSuffix(strings.ToLower(dns.Fqdn(name)), ".")
	if trimmed == "" {
		return nil
	}
	labels := strings.Split(trimmed, ".")
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return labels
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
