package memory

import (
	"crypto"
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
	"maps"
	"reflect"
	"strings"
	"sync"
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
	z.mu.Lock()
	defer z.mu.Unlock()
	for _, zone := range names {
		raw, err := z.storage.LoadZone(zone)
		if err != nil {
			continue
		}
		decoded, err := decodeZoneData(raw)
		if err != nil {
			continue
		}
		z.cache["zones"][zone] = decoded
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
	z.mu.Lock()
	zones := z.cache["zones"]
	if _, ok := zones[zone]; !ok {
		zones[zone] = make(map[string]map[string]any)
	}
	if _, ok := zones[zone][rtype]; !ok {
		zones[zone][rtype] = make(map[string]any)
	}
	zones[zone][rtype][name] = record
	z.mu.Unlock()

	//if config.DNSSECEnabled {
	//	go z.maybeSignRRSet(zone, rtype, name, record)
	//}

	go z.maybeSignRRSet(zone, rtype, name)

	return nil //z.persist(zone)
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
	log.Println("zonesMap", zonesMap)
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
		slog.Crazy("[GetZone] rtype is: ", rtype)
		slog.Crazy("[GetZone] builder is:", builder)
		if !ok {
			slog.Warn("NOT OK IN GetZone")
			continue
		}

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
			fqdn = dns.Fqdn(fqdn)
			slog.Crazy("[GetZone] fqdn is: ", fqdn)
			slog.Crazy("[GetZone] raw is: ", rawData)
			slog.Crazy("[GetZone] reflect.TypeOf(rawData): %v", reflect.TypeOf(rawData))

			rrs := builder(fqdn, rawData)
			slog.Crazy("[GetZone] rrs is: ", rrs)
			if len(rrs) > 0 {
				allRRs = append(allRRs, rrs...)
			}
		}
	}

	return allRRs, nil
}

func (z *InMemoryZoneStore) DeleteRecord(zone, rtype, name string) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	zones := z.cache["zones"]
	if recType, ok := zones[zone][rtype]; ok {
		delete(recType, name)
		return z.persist(zone)
	}
	return errors.New("record type not found")

}

func (z *InMemoryZoneStore) DeleteZone(zone string) error {
	z.mu.Lock()
	defer z.mu.Unlock()

	zones := z.cache["zones"]
	if _, exists := zones[zone]; exists {
		delete(zones, zone)
		return z.persist(zone)
	}

	return nil
}

func (z *InMemoryZoneStore) maybeSignRRSet(zone, rtype, name string) {
	slog.Crazy("[maybeSignRRSet]", zone, rtype, name)

	//always persist first to make sure the current data is avablee on disc.
	_ = z.persist(zone)

	if !config.AppConfig.GetLive().DNSSECEnabled {
		slog.Debug("[maybeSignRRSet] DNSSEC disabled, skipping signing, persisting zone only")
		return
	}

	_, _, record, ok := z.GetRecord(zone, rtype, name)
	if !ok {
		slog.Debug("Record for zone: %s of type %s and name %s NOT FOUND", zone, rtype, name)
	}

	slog.Crazy("*****************[maybeSignRRSet] Record is: %s ", record)

	rrs, err := security.ToRRSet(name, rtype, record)
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

		rrsig, err := security.SignRRSet(rrs, signer, storedKey.KeyTag, dns.Fqdn(storedKey.Zone))
		slog.Crazy("!!!!!!!!!!!!!!!!!!!![maybeSignRRSet] rrsig is: %v !!!!!!!!!!!!!!!!!", rrsig)
		if err != nil {
			slog.Error("Failed to sign RRSet with key %q: %v", keyName, err)
			continue
		}

		rrsigTyped := security.RRSIGFromDNS(rrsig)
		typeName := dns.TypeToString[rrsig.TypeCovered]
		name := dns.Fqdn(rrsig.Hdr.Name)

		slog.Crazy("[maybeSignRRSet] rrsigTyped is: %s,  typeName: %s, name is %s", rrsigTyped, typeName, name)

		z.mu.Lock()
		if _, ok := z.cache["zones"][zone]["RRSIG"]; !ok {
			slog.Crazy("[RRSIG->cache] Initializing RRSIG map for zone=%q", zone)
			z.cache["zones"][zone]["RRSIG"] = make(map[string]any)
		}

		rMap := z.cache["zones"][zone]["RRSIG"]
		slog.Crazy("[RRSIG->cache] rMap type=%T", rMap)

		if _, ok := rMap[typeName]; !ok {
			slog.Crazy("[RRSIG->cache] Creating type entry for typeName=%q", typeName)
			rMap[typeName] = make(map[string]any)
		} else {
			slog.Crazy("[RRSIG->cache] Found existing typeName=%q entry", typeName)
		}

		typedMap := rMap[typeName].(map[string]any)
		slog.Crazy("[RRSIG->cache] typedMap keys for type %q before insert: %v", typeName, maps.Keys(typedMap))

		beforeLen := 0
		if existing := typedMap[name]; existing != nil {
			if list, ok := existing.([]interface{}); ok {
				beforeLen = len(list)
			}
		}
		typedMap[name] = []interface{}{rrsigTyped}
		afterLen := len(typedMap[name].([]interface{}))

		slog.Crazy("[RRSIG->cache] Stored RRSIG under name=%q, zone=%q, coveredType=%q, total=%d (was %d)", name, zone, typeName, afterLen, beforeLen)
		z.mu.Unlock()

		slog.Debug("Successfully signed RRSet for %q with key %q (keyTag=%d)", name, keyName, storedKey.KeyTag)
	}

	_ = z.persist(zone)
}
