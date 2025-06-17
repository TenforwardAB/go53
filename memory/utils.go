package memory

import "reflect"

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
