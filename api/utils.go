package api

import (
	"fmt"
	"go53/internal"
	"go53/types"
	"go53/zone/rtypes"
)

func UpdateSOASerial(zoneName string) error {
	store := rtypes.GetMemStore()
	if store == nil {
		return fmt.Errorf("memstore is not initialized")
	}

	sanitizedZone, err := internal.SanitizeFQDN(zoneName)
	if err != nil {
		return err
	}

	_, _, raw, found := store.GetRecord(sanitizedZone, string(types.TypeSOA), sanitizedZone)
	if !found {
		return fmt.Errorf("SOA not found for zone %s", zoneName)
	}

	var existing types.SOARecord
	switch v := raw.(type) {
	case types.SOARecord:
		existing = v
	case map[string]interface{}:
		existing = types.SOARecord{
			Ns:      v["ns"].(string),
			Mbox:    v["mbox"].(string),
			Serial:  uint32(v["serial"].(float64)),
			Refresh: uint32(v["refresh"].(float64)),
			Retry:   uint32(v["retry"].(float64)),
			Expire:  uint32(v["expire"].(float64)),
			Minimum: uint32(v["minimum"].(float64)),
			TTL:     uint32(v["ttl"].(float64)),
		}
	default:
		return fmt.Errorf("invalid SOA record format")
	}

	existing.Serial = internal.NextSerial(existing.Serial)
	return store.AddRecord(sanitizedZone, string(types.TypeSOA), sanitizedZone, existing)
}
