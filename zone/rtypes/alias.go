package rtypes

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"go53/internal"
	"go53/types"
)

type ALIASRecord struct{}

func (ALIASRecord) Add(zone, name string, value interface{}, ttl *uint32) error {
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN sanitize check failed")
	}

	m, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("ALIASRecord expects value to be a JSON object, got %T", value)
	}

	rawTarget, ok := m["target"]
	if !ok {
		return fmt.Errorf("ALIASRecord expects field 'target'")
	}
	target, ok := rawTarget.(string)
	if !ok {
		return fmt.Errorf("ALIASRecord: field 'target' must be a string, got %T", rawTarget)
	}

	sanitizedTarget, err := internal.SanitizeFQDN(target)
	if err != nil {
		return fmt.Errorf("ALIASRecord: invalid target FQDN %q", target)
	}

	TTL := uint32(60)
	if ttl != nil {
		TTL = *ttl
	}

	if memStore == nil {
		return errors.New("memory store not initialized")
	}

	key := normalizeRecordKey(sanitizedZone, name)

	owner := sanitizedZone
	if key != "@" {
		owner = key + "." + sanitizedZone
	}
	if strings.EqualFold(sanitizedTarget, owner) {
		return fmt.Errorf("ALIASRecord: target %q must not point to itself", sanitizedTarget)
	}

	rec := types.ALIASRecord{
		Target: sanitizedTarget,
		TTL:    TTL,
	}
	return memStore.AddRecord(sanitizedZone, string(types.TypeALIAS), key, rec)
}

func (ALIASRecord) Lookup(host string) ([]dns.RR, bool) {
	return nil, false
}

func (ALIASRecord) Delete(host string, value interface{}) error {
	zone, name, ok := internal.SplitName(host)
	if !ok {
		return errors.New("invalid host format")
	}
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return errors.New("FQDN sanitize check failed")
	}
	if memStore == nil {
		return errors.New("memory store not initialized")
	}

	if err := memStore.DeleteRecord(sanitizedZone, string(types.TypeALIAS), name); err != nil {
		return err
	}
	_ = memStore.DeleteRecord(sanitizedZone, string(types.TypeA), name)
	_ = memStore.DeleteRecord(sanitizedZone, string(types.TypeAAAA), name)
	return nil
}

func (ALIASRecord) Type() uint16 {
	return types.AliasTypeCode
}

func GetALIAS(zone, name string) (types.ALIASRecord, bool) {
	if memStore == nil {
		return types.ALIASRecord{}, false
	}
	sanitizedZone, err := internal.SanitizeFQDN(zone)
	if err != nil {
		return types.ALIASRecord{}, false
	}
	_, _, val, ok := memStore.GetRecord(sanitizedZone, string(types.TypeALIAS), name)
	if !ok {
		return types.ALIASRecord{}, false
	}
	return aliasFromStored(val)
}

func aliasFromStored(val any) (types.ALIASRecord, bool) {
	switch v := val.(type) {
	case types.ALIASRecord:
		return v, v.Target != ""
	case map[string]interface{}:
		rec := types.ALIASRecord{TTL: 60}
		if tgt, ok := v["target"].(string); ok {
			rec.Target = tgt
		}
		if t, ok := v["ttl"].(float64); ok {
			rec.TTL = uint32(t)
		}
		return rec, rec.Target != ""
	default:
		return types.ALIASRecord{}, false
	}
}

func init() {
	Register(ALIASRecord{})
}
