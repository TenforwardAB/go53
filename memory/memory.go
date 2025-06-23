package memory

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"go53/internal"
	"go53/storage"
	"log"
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
	defer z.mu.Unlock()
	zones := z.cache["zones"]
	if _, ok := zones[zone]; !ok {
		zones[zone] = make(map[string]map[string]any)
	}
	if _, ok := zones[zone][rtype]; !ok {
		zones[zone][rtype] = make(map[string]any)
	}
	zones[zone][rtype][name] = record
	return z.persist(zone)
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
		log.Println("rtype is: ", rtype)
		log.Println("builder is:", builder)
		if !ok {
			log.Println("NOT OK IN GetZone")
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
	defer z.mu.Unlock()
	zones := z.cache["zones"]
	if recType, ok := zones[zone][rtype]; ok {
		delete(recType, name)
		return z.persist(zone)
	}
	return errors.New("record type not found")

}

func normalizeRecord(input interface{}) (map[string]interface{}, bool) {
	switch v := input.(type) {
	case map[string]interface{}:
		return v, true
	case map[string]string:
		out := make(map[string]interface{})
		for k, val := range v {
			out[k] = val
		}
		return out, true
	case struct {
		Ip  string
		TTL int
	}: // unlikely to work unless you're unmarshaling to struct
		return map[string]interface{}{"ip": v.Ip, "ttl": v.TTL}, true
	default:
		// fallback for []interface{} with positional data
		if arr, ok := v.([]interface{}); ok && len(arr) == 2 {
			if ip, ok1 := arr[0].(string); ok1 {
				if ttl, ok2 := arr[1].(float64); ok2 {
					return map[string]interface{}{"ip": ip, "ttl": int(ttl)}, true
				}
			}
		}
	}
	return nil, false
}
