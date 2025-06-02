package internal

import "strings"

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
