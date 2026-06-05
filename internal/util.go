package internal

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"go53/types"
	"reflect"
	"regexp"
	"strings"
	"time"
)

func SplitName(name string) (zone, host string, ok bool) {
	name = strings.TrimSuffix(name, ".")
	parts := strings.Split(name, ".")
	if len(parts) < 2 {
		return "", "", false // cannot form a zone from less than 2 parts
	}

	zone = strings.Join(parts[len(parts)-2:], ".") // last 2 parts = zone
	host = strings.Join(parts[:len(parts)-2], ".") // remaining = host
	if host == "" {
		host = "@" // root of zone
	}
	return zone, host, true
}

func RRTypeStringToUint16(s string) (uint16, error) {
	t, ok := dns.StringToType[strings.ToUpper(s)]
	if !ok || t == 0 {
		return 0, fmt.Errorf("unknown RR type: %s", s)
	}
	return t, nil
}

func NextSerial(old uint32) uint32 {
	now := time.Now().UTC()
	// YYMDD format: 2-digit year, month, day
	year := now.Year() % 100
	date := uint32(year*1e4 + int(now.Month())*1e2 + now.Day()) // e.g. 2507130

	if old == 0 {
		return date*1e3 + 1 // start with 001
	}

	oldDate := old / 1e3
	oldSeq := old % 1e3

	if oldDate == date {
		return oldDate*1e3 + (oldSeq + 1)
	}
	return date*1e3 + 1
}

func SanitizeFQDN(fqdn string) (string, error) {
	if fqdn == "@" || fqdn == "@." {
		return "@", nil
	}

	var validFQDN = regexp.MustCompile(`(?i)^[a-z0-9-\.]+$`)
	fqdn = strings.TrimSpace(fqdn)

	if fqdn == "" {
		return "", errors.New("FQDN cannot be empty")
	}

	if !validFQDN.MatchString(fqdn) {
		return "", errors.New("FQDN contains invalid characters")
	}

	fqdn = dns.Fqdn(fqdn)

	return fqdn, nil
}

func MergeStructs(dst, src interface{}) {
	dstVal := reflect.ValueOf(dst).Elem()
	srcVal := reflect.ValueOf(src).Elem()

	for i := 0; i < dstVal.NumField(); i++ {
		dstField := dstVal.Field(i)
		srcField := srcVal.Field(i)

		if !dstField.CanSet() {
			continue
		}

		switch dstField.Kind() {
		case reflect.Struct:
			if !isZeroValue(srcField) {
				MergeStructs(dstField.Addr().Interface(), srcField.Addr().Interface())
			}

		case reflect.String:
			if srcField.String() != "" {
				dstField.SetString(srcField.String())
			}

		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			if srcField.Int() != 0 {
				dstField.SetInt(srcField.Int())
			}

		case reflect.Bool:
			if srcField.Bool() {
				dstField.SetBool(srcField.Bool())
			}

		case reflect.Float32, reflect.Float64:
			if srcField.Float() != 0 {
				dstField.SetFloat(srcField.Float())
			}
		}
	}
}

func ParseToDNSKEYRecord(m map[string]interface{}) (types.DNSKEYRecord, bool) {
	rec := types.DNSKEYRecord{
		TTL:      3600,
		Protocol: 3,
	}

	if f, ok := m["flags"].(float64); ok {
		rec.Flags = uint16(f)
	}
	if p, ok := m["protocol"].(float64); ok {
		rec.Protocol = uint8(p)
	}
	if a, ok := m["algorithm"].(float64); ok {
		rec.Algorithm = uint8(a)
	}
	if pk, ok := m["public_key"].(string); ok {
		rec.PublicKey = pk
	}
	if t, ok := m["ttl"].(float64); ok {
		rec.TTL = uint32(t)
	}

	return rec, rec.PublicKey != ""
}

func isZeroValue(v reflect.Value) bool {
	return reflect.DeepEqual(v.Interface(), reflect.Zero(v.Type()).Interface())
}
