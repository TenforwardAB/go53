package internal

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"reflect"
	"regexp"
	"strings"
	"time"

	"go53/memory"
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
	date := uint32(now.Year()*1e4 + int(now.Month())*1e2 + now.Day()) // t.ex. 20250610

	if old == 0 {
		return date*10 + 1
	}

	tmp := old
	digits := 0
	for tmp > 0 {
		tmp /= 10
		digits++
	}
	seqDigits := digits - 8
	if seqDigits < 1 {
		seqDigits = 1
	}

	pow10 := uint32(1)
	for i := 0; i < seqDigits; i++ {
		pow10 *= 10
	}

	oldDate := old / pow10
	oldSeq := old % pow10

	if oldDate == date {
		return oldDate*pow10 + (oldSeq + 1)
	}
	return date*10 + 1
}

func SanitizeFQDN(fqdn string) (string, error) {

	var validFQDN = regexp.MustCompile(`(?i)^[a-z0-9-\.]+$`)
	fqdn = strings.TrimSpace(fqdn)

	if fqdn == "" {
		return "", errors.New("FQDN cannot be empty")
	}

	if !validFQDN.MatchString(fqdn) {
		return "", errors.New("FQDN contains invalid characters")
	}

	labels := strings.Split(strings.TrimSuffix(fqdn, "."), ".")
	for _, label := range labels {
		if label == "" {
			return "", errors.New("FQDN has empty label")
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", errors.New("FQDN label cannot start or end with '-'")
		}
	}

	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}

	return fqdn, nil
}

func HasOtherRecords[T any](
	memStore *memory.InMemoryZoneStore,
	zone, name string,
	excludeType uint16,
	registry map[uint16]T,
) (bool, uint16) {
	if memStore == nil {
		return false, 0
	}

	for rrtype := range registry {
		if rrtype == excludeType {
			continue
		}
		_, _, _, found := memStore.GetRecord(zone, fmt.Sprintf("%d", rrtype), name)
		if found {
			return true, rrtype
		}
	}
	return false, 0
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

func isZeroValue(v reflect.Value) bool {
	return reflect.DeepEqual(v.Interface(), reflect.Zero(v.Type()).Interface())
}
