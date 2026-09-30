// Package recshape This file is part of the go53 project.
//
// This file is licensed under the European Union Public License (EUPL) v1.2.
// You may only use this work in compliance with the License.
// You may obtain a copy of the License at:
//
//	https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed "as is",
// without any warranty or conditions of any kind.
//
// Copyleft (c) 2026 - Tenforward AB. All rights reserved.
//
// This file: recshape.go is part of the go53 authoritative DNS server.

// Package recshape decodes the values held in the in-memory zone store into
// typed records, whatever shape a writer left them in.
//
// The store keeps every RRset as an untyped value. Depending on who wrote it,
// the same RRset can be a typed slice ([]types.MXRecord), a slice of maps, a
// slice of interfaces holding maps (what encoding/json produces after a restart
// or replication), or for single-record types a lone struct or map. Numbers
// arrive as float64 from JSON, as uint32 from typed writers and as int from
// tests. Every reader used to carry its own type switch over a subset of those
// shapes; this package is the one place that knows them all.
//
// Decode never changes what is stored (the stored value is hashed as-is for
// distributed anti-entropy, see docs/internal/issue57-record-shape-decoding.md)
// and never copies the maps it reads through.
package recshape

import (
	"encoding/json"
	"math"
	"strconv"
)

// Row is one record's fields exactly as a writer stored them.
type Row map[string]any

// appendRows decodes every map row in a dynamic stored value through from and
// appends the accepted records to out. No closure and no intermediate slice,
// so the only allocation on this path is the caller's out. Returns ok=false
// for nil and for anything that is not one of the map shapes, so callers can
// distinguish "empty" from "unknown".
func appendRows[T any](out []T, v any, from func(Row) (T, bool)) ([]T, bool) {
	switch s := v.(type) {
	case nil:
		return out, false
	case []Row:
		for _, r := range s {
			if rec, ok := from(r); ok {
				out = append(out, rec)
			}
		}
	case Row:
		if rec, ok := from(s); ok {
			out = append(out, rec)
		}
	case map[string]any:
		if rec, ok := from(s); ok {
			out = append(out, rec)
		}
	case []map[string]any:
		for _, m := range s {
			if rec, ok := from(m); ok {
				out = append(out, rec)
			}
		}
	case []any:
		for _, item := range s {
			var r Row
			switch m := item.(type) {
			case map[string]any:
				r = m
			case Row:
				r = m
			default:
				continue
			}
			if rec, ok := from(r); ok {
				out = append(out, rec)
			}
		}
	default:
		return out, false
	}
	return out, true
}

// rowCount returns how many rows a map shape holds, for pre-sizing.
func rowCount(v any) int {
	switch s := v.(type) {
	case []Row:
		return len(s)
	case []map[string]any:
		return len(s)
	case []any:
		return len(s)
	case Row, map[string]any:
		return 1
	}
	return 0
}

func identityRow(r Row) (Row, bool) { return r, true }

// Rows folds a dynamic stored value into rows. Typed values are not handled
// here; Decode deals with those first so this is only reached for the map
// shapes. Returns ok=false for nil and for anything that is not one of the map
// shapes, so callers can distinguish "empty" from "unknown".
func Rows(v any) ([]Row, bool) {
	out, ok := appendRows(make([]Row, 0, rowCount(v)), v, identityRow)
	if !ok {
		return nil, false
	}
	return out, true
}

// Decode returns the typed records held in v.
//
//	[]T    returned as-is: no copy, no allocation
//	T      wrapped in a one-element slice
//	[]any  whose elements are all T: rebuilt as []T (typed writers that went
//	       through a []any, e.g. the DNSSEC signer)
//	other  each map row through from; rows from rejects are skipped
//
// ok=false means v is not a shape this package knows; an empty result with
// ok=true means the shape was known but held no usable record of type T.
func Decode[T any](v any, from func(Row) (T, bool)) ([]T, bool) {
	switch t := v.(type) {
	case []T:
		return t, true
	case T:
		return []T{t}, true
	case *T:
		if t == nil {
			return nil, false
		}
		return []T{*t}, true
	case []any:
		if typed, ok := typedElements[T](t); ok {
			return typed, true
		}
	}
	out, ok := appendRows(make([]T, 0, rowCount(v)), v, from)
	if !ok {
		return nil, false
	}
	return out, true
}

// typedElements rebuilds a []any as []T when every element is a T or *T.
// A mixed or map-holding slice returns ok=false and falls through to Rows.
func typedElements[T any](items []any) ([]T, bool) {
	if len(items) == 0 {
		return nil, false
	}
	// Check before allocating: the common []any-of-maps shape must cost
	// nothing here.
	for _, item := range items {
		switch t := item.(type) {
		case T:
		case *T:
			if t == nil {
				return nil, false
			}
		default:
			return nil, false
		}
	}
	out := make([]T, 0, len(items))
	for _, item := range items {
		switch t := item.(type) {
		case T:
			out = append(out, t)
		case *T:
			out = append(out, *t)
		}
	}
	return out, true
}

// Single is Decode for single-record types (SOA, CNAME, DNAME, SPF, ALIAS,
// NSEC, NSEC3, NSEC3PARAM). It returns the first usable record and, unlike
// Decode, allocates nothing for a typed value or a single map.
func Single[T any](v any, from func(Row) (T, bool)) (T, bool) {
	var zero T
	switch t := v.(type) {
	case T:
		return t, true
	case *T:
		if t == nil {
			return zero, false
		}
		return *t, true
	case Row:
		return from(t)
	case map[string]any:
		return from(t)
	case []T:
		if len(t) == 0 {
			return zero, false
		}
		return t[0], true
	}
	recs, ok := Decode(v, from)
	if !ok || len(recs) == 0 {
		return zero, false
	}
	return recs[0], true
}

// String returns the field as a string. Missing or non-string → ok=false.
func (r Row) String(key string) (string, bool) {
	s, ok := r[key].(string)
	return s, ok
}

// Bool returns the field as a bool. Missing or non-bool → ok=false.
func (r Row) Bool(key string) (bool, bool) {
	b, ok := r[key].(bool)
	return b, ok
}

// Strings returns a list-of-strings field, accepting []string and the []any of
// string that encoding/json produces. Non-string elements are skipped.
func (r Row) Strings(key string) ([]string, bool) {
	switch v := r[key].(type) {
	case []string:
		return v, true
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out, true
	}
	return nil, false
}

// Uint64 returns a numeric field as uint64. It accepts every Go integer and
// float kind plus json.Number, and rejects (ok=false) negatives, fractions and
// values that do not fit: a wrapped TTL is never served.
func (r Row) Uint64(key string) (uint64, bool) {
	v, ok := r[key]
	if !ok {
		return 0, false
	}
	return toUint64(v)
}

// Uint32 is Uint64 bounded to uint32.
func (r Row) Uint32(key string) (uint32, bool) {
	n, ok := r.Uint64(key)
	if !ok || n > math.MaxUint32 {
		return 0, false
	}
	return uint32(n), true
}

// Uint16 is Uint64 bounded to uint16.
func (r Row) Uint16(key string) (uint16, bool) {
	n, ok := r.Uint64(key)
	if !ok || n > math.MaxUint16 {
		return 0, false
	}
	return uint16(n), true
}

// Uint8 is Uint64 bounded to uint8.
func (r Row) Uint8(key string) (uint8, bool) {
	n, ok := r.Uint64(key)
	if !ok || n > math.MaxUint8 {
		return 0, false
	}
	return uint8(n), true
}

// TTL returns the "ttl" field, or def when it is missing or unusable.
func (r Row) TTL(def uint32) uint32 {
	if ttl, ok := r.Uint32("ttl"); ok {
		return ttl
	}
	return def
}

func toUint64(v any) (uint64, bool) {
	switch n := v.(type) {
	case float64:
		return floatToUint64(n)
	case float32:
		return floatToUint64(float64(n))
	case int:
		return intToUint64(int64(n))
	case int8:
		return intToUint64(int64(n))
	case int16:
		return intToUint64(int64(n))
	case int32:
		return intToUint64(int64(n))
	case int64:
		return intToUint64(n)
	case uint:
		return uint64(n), true
	case uint8:
		return uint64(n), true
	case uint16:
		return uint64(n), true
	case uint32:
		return uint64(n), true
	case uint64:
		return n, true
	case json.Number:
		if u, err := strconv.ParseUint(n.String(), 10, 64); err == nil {
			return u, true
		}
		if f, err := n.Float64(); err == nil {
			return floatToUint64(f)
		}
	}
	return 0, false
}

func floatToUint64(f float64) (uint64, bool) {
	if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f != math.Trunc(f) || f >= math.MaxUint64 {
		return 0, false
	}
	return uint64(f), true
}

func intToUint64(i int64) (uint64, bool) {
	if i < 0 {
		return 0, false
	}
	return uint64(i), true
}
