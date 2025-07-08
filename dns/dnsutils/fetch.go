package dnsutils

import (
	"encoding/json"
	"fmt"
	"go53/config"
	"go53/internal"
	"go53/types"
	"go53/zone"
	"log"
	"reflect"
	"strings"

	"github.com/TenforwardAB/slog"
	"github.com/miekg/dns"
)

func ImportRecords(rrtype string, zoneName string, data interface{}) error {
	var zoneData types.ZoneData
	var fromAPI bool
	slog.Crazy("[fetch.go:ImportRecords] data is: ", data)
	switch v := data.(type) {

	case []dns.RR:
		fromAPI = false
		santitizedZone, _ := internal.SanitizeFQDN(zoneName)
		err := zone.DeleteZone(santitizedZone)
		if err != nil {
			return err
		}
		slog.Crazy("[fetch.go:ImportRecords] v in data.(type) is: ", v)
		zoneData = internal.RRToZoneData(v)
		slog.Crazy("[fetch.go:ImportRecords] zoneData: %v", zoneData)

	case map[string]interface{}:
		// JSON input for 'multi'
		if rrtype != "multi" {
			return fmt.Errorf("expected 'multi' rrtype for JSON map input")
		}
		fromAPI = true
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("failed to re-marshal input: %w", err)
		}
		if err := json.Unmarshal(b, &zoneData); err != nil {
			return fmt.Errorf("failed to decode input into ZoneData: %w", err)
		}

	default:
		return fmt.Errorf("unsupported data type for import")
	}

	return importFromZoneData(zoneName, zoneData, fromAPI)
}

func importFromZoneData(zoneName string, zd types.ZoneData, fromAPI bool) error {
	add := func(rrtype uint16, name string, rec interface{}, ttl uint32) error {
		b, _ := json.Marshal(rec)
		var out map[string]interface{}
		if err := json.Unmarshal(b, &out); err != nil {
			return err
		}
		log.Println("Adding", name, "to", out)
		return zone.AddRecord(rrtype, zoneName, name, out, &ttl)
	}

	val := reflect.ValueOf(zd)
	typ := reflect.TypeOf(zd)

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		value := val.Field(i)

		jsonTag := field.Tag.Get("json")
		if jsonTag == "" || value.IsZero() {
			continue
		}
		rrTypeStr := strings.ToUpper(strings.Split(jsonTag, ",")[0])
		rrType, err := dns.StringToType[rrTypeStr]
		if !err {
			continue
		}

		switch value.Kind() {
		case reflect.Map:
			for _, key := range value.MapKeys() {
				recVal := value.MapIndex(key)
				name := key.String()

				// CNAME, DNAME, NSEC etc. (one record per name)
				if recVal.Type().Kind() == reflect.Struct {
					if err := add(rrType, name, recVal.Interface(), uint32(recVal.FieldByName("TTL").Uint())); err != nil {
						return err
					}
					continue
				}

				// multiple records per name (slices)
				for j := 0; j < recVal.Len(); j++ {
					rec := recVal.Index(j).Interface()
					ttl := recVal.Index(j).FieldByName("TTL").Uint()
					if err := add(rrType, name, rec, uint32(ttl)); err != nil {
						return err
					}
				}
			}

		case reflect.Ptr:
			if value.IsNil() {
				continue
			}
			if field.Name == "SOA" {
				elem := value.Elem()
				if !elem.IsValid() {
					continue
				}
				ttlField := elem.FieldByName("TTL")
				var ttl uint32
				if ttlField.IsValid() && ttlField.Kind() == reflect.Uint32 {
					ttl = uint32(ttlField.Uint())
				}
				if err := add(dns.TypeSOA, zoneName, value.Interface(), ttl); err != nil {
					return err
				}
			}
		}
	}

	if fromAPI {
		if err := UpdateSOASerial(zoneName); err != nil {
			log.Printf("warning: failed to update SOA serial: %v", err)
		} else if config.AppConfig.GetLive().Mode != "secondary" {
			go ScheduleNotify(zoneName)
		}
	}

	return nil
}
