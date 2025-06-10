package internal

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
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

func DeepSize(v interface{}) uintptr {
	visited := make(map[uintptr]bool)
	return deepSize(reflect.ValueOf(v), visited)
}

func deepSize(val reflect.Value, visited map[uintptr]bool) uintptr {
	switch val.Kind() {
	case reflect.Ptr:
		if val.IsNil() {
			return 0
		}
		ptr := val.Pointer()
		if visited[ptr] {
			return 0
		}
		visited[ptr] = true
		return deepSize(val.Elem(), visited)
	case reflect.Interface:
		if val.IsNil() {
			return 0
		}
		return deepSize(val.Elem(), visited)
	case reflect.Map:
		size := uintptr(0)
		for _, key := range val.MapKeys() {
			size += deepSize(key, visited)
			size += deepSize(val.MapIndex(key), visited)
		}
		return size
	case reflect.Slice, reflect.Array:
		size := uintptr(0)
		for i := 0; i < val.Len(); i++ {
			size += deepSize(val.Index(i), visited)
		}
		return size
	case reflect.String:
		return uintptr(len(val.String()))
	default:
		return val.Type().Size()
	}
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
