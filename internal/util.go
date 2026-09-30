package internal

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"go53/types"
	"reflect"
	"strings"
	"sync"
	"time"
)

var splitNameResolver = struct {
	sync.RWMutex
	fn func(string) (string, string, bool)
}{}

func SetSplitNameResolver(fn func(string) (string, string, bool)) {
	splitNameResolver.Lock()
	splitNameResolver.fn = fn
	splitNameResolver.Unlock()
}

// SplitName splits a query name into its authoritative zone and the owner
// relative to it ("@" at the apex). The zone is returned as an absolute,
// canonical name: callers pass it straight to SanitizeFQDN, which is then a
// no-op instead of re-adding a trailing dot on every DNS query (#40).
func SplitName(name string) (zone, host string, ok bool) {
	splitNameResolver.RLock()
	resolver := splitNameResolver.fn
	splitNameResolver.RUnlock()
	if resolver != nil {
		if zone, host, ok := resolver(name); ok {
			return zone, host, true
		}
	}

	// No store attached (tests, tooling): last two labels form the zone.
	name = strings.TrimSuffix(name, ".")
	parts := strings.Split(name, ".")
	if len(parts) < 2 {
		return "", "", false // cannot form a zone from less than 2 parts
	}

	zone = strings.Join(parts[len(parts)-2:], ".") + "." // last 2 parts = zone
	host = strings.Join(parts[:len(parts)-2], ".")       // remaining = host
	if host == "" {
		host = "@" // root of zone
	}
	return zone, host, true
}

func RRTypeStringToUint16(s string) (uint16, error) {
	upper := strings.ToUpper(s)
	if upper == string(types.TypeALIAS) {
		return types.AliasTypeCode, nil
	}
	t, ok := dns.StringToType[upper]
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

	fqdn = strings.TrimSpace(fqdn)

	if fqdn == "" {
		return "", errors.New("FQDN cannot be empty")
	}

	if strings.HasPrefix(fqdn, "*.") {
		rest, err := SanitizeFQDN(strings.TrimPrefix(fqdn, "*."))
		if err != nil {
			return "", err
		}
		if rest == "@" {
			return "", errors.New("wildcard FQDN cannot target @")
		}
		return "*." + rest, nil
	}

	if !validFQDNChars(fqdn) {
		return "", errors.New("FQDN contains invalid characters")
	}

	// DNS names are case-insensitive; canonicalize to lowercase so the store
	// can rely on exact key matches.
	fqdn = strings.ToLower(dns.Fqdn(fqdn))

	return fqdn, nil
}

// validFQDNChars reports whether s consists only of [A-Za-z0-9._-]. It runs on
// every DNS query, so it is a byte loop rather than a regexp (which used to be
// compiled per call and dominated Lookup's cost, #60).
func validFQDNChars(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
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

		case reflect.Map, reflect.Slice:
			if !srcField.IsNil() && srcField.Len() > 0 {
				dstField.Set(srcField)
			}
		}
	}
}

func isZeroValue(v reflect.Value) bool {
	return reflect.DeepEqual(v.Interface(), reflect.Zero(v.Type()).Interface())
}
