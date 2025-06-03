package memory

import (
	"errors"
	"fmt"
	"go53/internal"
	"go53/storage"
	"sync"
)

type InMemoryZoneStore struct {
	cache   map[string]map[string]map[string]any
	storage storage.Storage
	mu      sync.RWMutex
}

func NewZoneStore(s storage.Storage) (*InMemoryZoneStore, error) {
	zs := &InMemoryZoneStore{
		cache:   make(map[string]map[string]map[string]any),
		storage: s,
	}
	if err := zs.loadFromStorage(); err != nil {
		return nil, err
	}
	fmt.Printf("Estimated deep size: %d bytes\n", internal.DeepSize(zs.cache))
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
		z.cache[zone] = decoded
	}
	return nil
}

func (z *InMemoryZoneStore) persist(zone string) error {
	data, err := encodeZoneData(z.cache[zone])
	if err != nil {
		return err
	}
	return z.storage.SaveZone(zone, data)
}

func (z *InMemoryZoneStore) AddRecord(zone, rtype, name string, record any) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	if _, ok := z.cache[zone]; !ok {
		z.cache[zone] = make(map[string]map[string]any)
	}
	if _, ok := z.cache[zone][rtype]; !ok {
		z.cache[zone][rtype] = make(map[string]any)
	}
	z.cache[zone][rtype][name] = record
	return z.persist(zone)
}

func (z *InMemoryZoneStore) GetRecord(zone, rtype, name string) (string, string, any, bool) {
	z.mu.RLock()
	defer z.mu.RUnlock()
	recType, ok := z.cache[zone][rtype]
	if !ok {
		return "", "", nil, false
	}
	rec, exists := recType[name]
	return zone, rtype, rec, exists
}

func (z *InMemoryZoneStore) DeleteRecord(zone, rtype, name string) error {
	z.mu.Lock()
	defer z.mu.Unlock()
	if recType, ok := z.cache[zone][rtype]; ok {
		delete(recType, name)
		return z.persist(zone)
	}
	return errors.New("record type not found")
}
