package dnsutils

import (
	"fmt"
	"github.com/miekg/dns"
	"go53/internal"
	"go53/recshape"
	"go53/types"
	"go53/zone"
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

	_, _, raw, found := store.GetRecord(sanitizedZone, string(types.TypeSOA), "@")
	if !found {
		err := zone.AddRecord(dns.TypeSOA, sanitizedZone, "@", map[string]interface{}{}, nil)
		if err != nil {
			return err
		}
		return fmt.Errorf("SOA not found for zone %s", zoneName)
	}

	existing, ok := recshape.Single(raw, recshape.SOARecord)
	if !ok {
		return fmt.Errorf("invalid SOA record format")
	}

	existing.Serial = internal.NextSerial(existing.Serial)
	return store.AddRecord(sanitizedZone, string(types.TypeSOA), "@", existing) //TODO: why not use zone.AddRecord?
}
