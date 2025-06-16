package tmp

import (
	"errors"
	"fmt"
	"go53/zone/rtypes"
	"log"

	"github.com/miekg/dns"
	"go53/internal"
	"go53/types"
)

type NSRecord struct{}

func (NSRecord) Add(zone, name string, value interface{}, ttl *uint32) error {
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN sanitize check failed")
	}

	m, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("NSRecord expects value to be a JSON object, got %T", value)
	}

	rawNS, ok := m["ns"]
	if !ok {
		return fmt.Errorf("NSRecord expects field 'ns'")
	}
	nsHost, ok := rawNS.(string)
	if !ok {
		return fmt.Errorf("NSRecord: field 'ns' must be a string, got %T", rawNS)
	}

	sanitizedNS, err := internal.SanitizeFQDN(nsHost)
	if err != nil {
		return fmt.Errorf("NSRecord: invalid NS FQDN %q", nsHost)
	}

	TTL := uint32(3600)
	if ttl != nil {
		TTL = *ttl
	}

	if rtypes.memStore == nil {
		return errors.New("memory store not initialized")
	}

	key := name
	if key == "" {
		key = "@"
	}
	_, _, existing, found := rtypes.memStore.GetRecord(sanitizedZone, string(types.TypeNS), key)

	var currentList []string
	var currentTTL uint32 = TTL

	if found {
		switch v := existing.(type) {
		case types.NSRecord:
			currentList = v.NS
			currentTTL = v.TTL
		case map[string]interface{}:
			if arr, ok := v["ns"].([]interface{}); ok {
				for _, item := range arr {
					if s, ok := item.(string); ok {
						currentList = append(currentList, s)
					}
				}
			}
			if t, ok := v["ttl"].(float64); ok {
				currentTTL = uint32(t)
			}
		}
	}

	for _, existingNS := range currentList {
		if existingNS == sanitizedNS {
			return nil
		}
	}
	currentList = append(currentList, sanitizedNS)

	rec := types.NSRecord{
		NS:  currentList,
		TTL: currentTTL,
	}
	return rtypes.memStore.AddRecord(sanitizedZone, string(types.TypeNS), key, rec)
}

func (NSRecord) Lookup(host string) (dns.RR, bool) {
	zone, name, ok := internal.SplitName(host)
	if !ok {
		return nil, false
	}
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return nil, false
	}
	if rtypes.memStore == nil {
		return nil, false
	}

	key := name
	if key == "" {
		key = "@"
	}

	_, _, val, ok := rtypes.memStore.GetRecord(sanitizedZone, string(types.TypeNS), key)
	log.Printf("Value is: %v\n", val)
	if !ok {
		return nil, false
	}

	var nsList []string
	var ttl uint32 = 3600

	switch v := val.(type) {
	case types.NSRecord:
		nsList = v.NS
		ttl = v.TTL
	case map[string]interface{}:
		if arr, ok := v["ns"].([]interface{}); ok {
			for _, item := range arr {
				if s, ok := item.(string); ok {
					nsList = append(nsList, s)
				}
			}
		}
		if t, ok := v["ttl"].(float64); ok {
			ttl = uint32(t)
		}
	default:
		return nil, false
	}

	if len(nsList) == 0 {
		return nil, false
	}

	return &dns.NS{
		Hdr: dns.RR_Header{
			Name:   host,
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Ns: nsList[0],
	}, true
}

func (NSRecord) Delete(host string) error {
	zone, name, ok := internal.SplitName(host)
	if !ok {
		return errors.New("invalid host format")
	}
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN sanitize check failed")
	}
	if rtypes.memStore == nil {
		return errors.New("memory store not initialized")
	}

	key := name
	if key == "" {
		key = "@"
	}

	_, _, val, found := rtypes.memStore.GetRecord(sanitizedZone, string(types.TypeNS), key)
	if !found {
		return nil
	}

	nsToRemove, err := internal.SanitizeFQDN(host)
	if err != nil {
		return errors.New("FQDN sanitize check failed")
	}

	var newList []string
	var ttl uint32 = 3600

	switch v := val.(type) {
	case types.NSRecord:
		ttl = v.TTL
		for _, entry := range v.NS {
			if entry != nsToRemove {
				newList = append(newList, entry)
			}
		}
	case map[string]interface{}:
		if arr, ok := v["ns"].([]interface{}); ok {
			for _, item := range arr {
				if s, ok := item.(string); ok && s != nsToRemove {
					newList = append(newList, s)
				}
			}
		}
		if t, ok := v["ttl"].(float64); ok {
			ttl = uint32(t)
		}
	}

	if len(newList) == 0 {
		return rtypes.memStore.DeleteRecord(sanitizedZone, string(types.TypeNS), key)
	}

	rec := types.NSRecord{
		NS:  newList,
		TTL: ttl,
	}
	return rtypes.memStore.AddRecord(sanitizedZone, string(types.TypeNS), key, rec)
}

func (NSRecord) Type() uint16 {
	return dns.TypeNS
}

func init() {
	rtypes.Register(NSRecord{})
}
