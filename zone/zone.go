// Package zone This file is part of the go53 project.
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
// Created on 6/13/25 by andrek <andre(-at-)sess.se>
//
// This file: zone.go is part of the go53 authoritative DNS server.
package zone

import (
	"fmt"
	"github.com/miekg/dns"
	"go53/zone/rtypes"
)

// AddRecord adds a DNS record of the specified type to the in-memory store for a given zone.
//
// The function delegates the operation to the handler registered for the specified RR type.
// The handler is responsible for constructing and storing the appropriate record.
//
// Parameters:
//   - rrtype: The DNS resource record type (e.g., dns.TypeA, dns.TypeMX).
//   - zone:   The zone to which the record belongs.
//   - name:   The record's name (relative or fully qualified).
//   - value:  The record's value (type depends on the RR type).
//   - ttl:    Optional TTL for the record; nil to use default.
//
// Returns:
//   - error: An error if the RR type is unknown or the handler fails to add the record.
func AddRecord(rrtype uint16, zone, name string, value interface{}, ttl *uint32) error {
	rr, ok := rtypes.Get(rrtype)
	if !ok {
		return fmt.Errorf("unknown rrtype: %d", rrtype)
	}
	return rr.Add(zone, name, value, ttl)
}

// LookupRecord retrieves DNS records of the specified type for a given name.
//
// The function delegates the lookup to the handler associated with the RR type.
// If the handler exists and the records are found, they are returned.
//
// Parameters:
//   - rrtype: The DNS resource record type (e.g., dns.TypeSOA, dns.TypeA).
//   - name:   The name to query (must match the stored record name).
//
// Returns:
//   - []dns.RR: A slice of matching DNS resource records.
//   - bool:     True if records were found; false otherwise or if the RR type is unknown.
func LookupRecord(rrtype uint16, name string) ([]dns.RR, bool) {
	rr, ok := rtypes.Get(rrtype)
	if !ok {
		return nil, false
	}
	return rr.Lookup(name)
}

// DeleteRecord deletes a specific DNS record of the given type and name.
//
// The function passes the deletion request to the corresponding handler for
// the RR type. The value is used to uniquely identify which record to delete.
//
// Parameters:
//   - rrtype: The DNS resource record type (e.g., dns.TypeTXT).
//   - name:   The name of the record to delete.
//   - value:  The record value to match for deletion.
//
// Returns:
//   - error: An error if the RR type is unknown or the deletion fails.
func DeleteRecord(rrtype uint16, name string, value interface{}) error {
	rr, ok := rtypes.Get(rrtype)
	if !ok {
		return fmt.Errorf("unknown rrtype: %d", rrtype)
	}
	return rr.Delete(name, value)
}

// DeleteZone removes all records for a specific DNS zone from the in-memory store.
// Which also purges the zone from persistent storage.
//
// The function uses the general memory store abstraction and removes the entire zone,
// effectively purging all associated resource records across all types.
//
// Parameters:
//   - zone: The zone name to delete.
//
// Returns:
//   - error: An error if the memory store is not initialized or the deletion fails.
func DeleteZone(zone string) error {
	mem := rtypes.GetMemStore()
	if mem == nil {
		return fmt.Errorf("memory store is not initialized")
	}
	return mem.DeleteZone(zone)
}
