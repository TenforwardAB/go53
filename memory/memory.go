package memory

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"go53/internal"
	"go53/storage"
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
	if !ok {
		return nil, errors.New("zones cache missing")
	}

	zoneMap, ok := zonesMap[sanitizedZone]
	if !ok {
		return nil, errors.New("zone not found")
	}

	var allRRs []dns.RR

	for rtype, namesMap := range zoneMap {
		builder, ok := internal.RRBuilders[rtype]
		if !ok {
			continue // skip other unknown recordtypes
		}

		for name, rawRecords := range namesMap {
			records, ok := rawRecords.([]interface{})
			if !ok {
				continue
			}

			fqdn := sanitizedZone
			if name != "@" {
				fqdn = name + "." + sanitizedZone
			}

			for _, rec := range records {
				if m, ok := rec.(map[string]interface{}); ok {
					rr := builder(fqdn, m)
					if rr != nil {
						allRRs = append(allRRs, rr)
					}
				}
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
