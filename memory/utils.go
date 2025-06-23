package memory

import (
	"fmt"
	"reflect"
)

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

func HasOtherRecords[T any](
	memStore *InMemoryZoneStore,
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
