// Package rtypes This file is part of the go53 project.
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
// Copyleft (c) 2025 - Tenforward AB. All rights reserved.
//
// Created on 6/3/25 by joyider <andre(-at-)sess.se>
//
// This file: rtypes.go is part of the go53 authoritative DNS server.

// Package rtypes provides a thin abstraction layer for managing DNS record storage
// using an in-memory cache with persistent backend support. It acts as a bridge
// between zone record logic and backend implementations, allowing zone data to be
// loaded, stored, and updated in a consistent manner.
//
// This package is intended to be used by higher-level DNS record logic to persist
// and retrieve DNS resource records via an abstracted memory layer.
package rtypes

import (
	"strings"

	"github.com/miekg/dns"
	"go53/internal"
	"go53/memory"
)

type RRType interface {
	Add(zone, name string, value interface{}, ttl *uint32) error
	Lookup(name string) ([]dns.RR, bool)
	Delete(host string, value interface{}) error
	Type() uint16
}

// memStore is the internal singleton reference to the in-memory zone store.
// It should be initialized with a call to InitMemoryStore before any record
// operations are performed.
var memStore *memory.InMemoryZoneStore
var registry = make(map[uint16]RRType)

// InitMemoryStore initializes the package-level zone store.
//
// This function must be called exactly once at program startup,
// after a memory store instance is created. All rtypes functions
// will then use this shared zone store for record access and updates.
//
// Example:
//
//	store, _ := memory.NewZoneStore(backend)
//	rtypes.InitMemoryStore(store)
//
// Arguments:
//   - store: a pointer to a memory.InMemoryZoneStore instance, created and loaded by the caller.
func InitMemoryStore(store *memory.InMemoryZoneStore) {
	memStore = store
	if store == nil {
		internal.SetSplitNameResolver(nil)
		return
	}
	internal.SetSplitNameResolver(store.AuthoritativeNameParts)
}

func GetMemStore() *memory.InMemoryZoneStore {
	return memStore
}

func Register(rr RRType) {
	registry[rr.Type()] = rr
}

func Get(rrtype uint16) (RRType, bool) {
	rr, ok := registry[rrtype]
	return rr, ok
}

func GetRegistry() map[uint16]RRType {
	return registry
}

// normalizeRecordKey converts an Add name argument to the short-label storage key
// that Lookup derives via SplitName, so Add and Lookup always agree on the key.
//
// Only absolute FQDNs (trailing dot) need normalization: "go53.test." → "@",
// "www.go53.test." → "www". Multi-label short labels like "_sip._tcp" or
// "5.4.3.2.in-addr.arpa" (no trailing dot) pass through unchanged, as does "@".
func normalizeRecordKey(sanitizedZone, name string) string {
	if strings.HasSuffix(name, ".") {
		stripped := strings.TrimSuffix(name, sanitizedZone)
		stripped = strings.TrimSuffix(stripped, ".")
		if stripped == "" {
			return "@"
		}
		return stripped
	}
	if name == "" {
		return "@"
	}
	return name
}
