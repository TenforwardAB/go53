// Package memory This file is part of the go53 project.
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
// This file: ownerindex.go is part of the go53 authoritative DNS server.

package memory

import (
	"strings"

	"github.com/miekg/dns"
)

// Owner index (#40).
//
// Negative answers, wildcard synthesis, delegation checks and DNSSEC denial
// all ask "does this owner exist in the zone, and with which types?" for every
// candidate label of the query name. Answering that from the record map means
// iterating every rtype map per candidate; on an NXDOMAIN that dominated the
// query. The index keeps, per zone, the set of relative owners that carry at
// least one record of a type that counts for existence (shouldMaintainNSEC)
// and a bitmask of those types, so each check is one map lookup.
//
// Maintenance: incrementally in AddRecord/PutRecordRaw/DeleteRecord(Raw) and
// DeleteZone, and rebuilt from the record map in loadFromStorage. The writers
// that bypass AddRecord (NSEC/NSEC3 chain rebuild, RRSIG store) only touch
// types the index excludes, so they need no hook. Both readers and writers run
// under z.mu like the record map itself.

// typeBits is a set of rtypes. Bits are assigned on first sight; a zone with
// more than 64 distinct maintained types counts the overflow in ownerEntry.
type typeBits uint64

type ownerEntry struct {
	bits  typeBits
	extra uint16 // records of types beyond the 64 bit slots
}

type ownerIndex map[string]ownerEntry // relative owner -> types present

// rtypeBitSlots assigns bit positions to rtype names. Written only under the
// store's write lock (every mutation path holds it); read under RLock.
var rtypeBitSlots = map[string]uint8{}

const maxTypeBits = 64

func rtypeBit(rtype string, assign bool) (typeBits, bool) {
	if slot, ok := rtypeBitSlots[rtype]; ok {
		return 1 << slot, true
	}
	if !assign || len(rtypeBitSlots) >= maxTypeBits {
		return 0, false
	}
	slot := uint8(len(rtypeBitSlots))
	rtypeBitSlots[rtype] = slot
	return 1 << slot, true
}

func (z *InMemoryZoneStore) ownerIndexFor(zone string, create bool) ownerIndex {
	idx, ok := z.ownerIdx[zone]
	if !ok && create {
		idx = ownerIndex{}
		z.ownerIdx[zone] = idx
	}
	return idx
}

// indexOwnerLocked records that owner carries rtype in zone.
func (z *InMemoryZoneStore) indexOwnerLocked(zone, rtype, owner string) {
	if !shouldMaintainNSEC(rtype) {
		return
	}
	idx := z.ownerIndexFor(zone, true)
	e := idx[owner]
	if bit, ok := rtypeBit(rtype, true); ok {
		e.bits |= bit
	} else {
		e.extra++
	}
	idx[owner] = e
}

// unindexOwnerLocked records that owner no longer carries rtype in zone.
func (z *InMemoryZoneStore) unindexOwnerLocked(zone, rtype, owner string) {
	if !shouldMaintainNSEC(rtype) {
		return
	}
	idx := z.ownerIndexFor(zone, false)
	if idx == nil {
		return
	}
	e, ok := idx[owner]
	if !ok {
		return
	}
	if bit, ok := rtypeBit(rtype, false); ok {
		e.bits &^= bit
	} else if e.extra > 0 {
		e.extra--
	}
	if e.bits == 0 && e.extra == 0 {
		delete(idx, owner)
		return
	}
	idx[owner] = e
}

// rebuildOwnerIndexLocked derives the index for zone from the record map.
func (z *InMemoryZoneStore) rebuildOwnerIndexLocked(zone string) {
	zoneMap, ok := z.cache["zones"][zone]
	if !ok {
		delete(z.ownerIdx, zone)
		return
	}
	idx := make(ownerIndex)
	z.ownerIdx[zone] = idx
	for rtype, names := range zoneMap {
		if !shouldMaintainNSEC(rtype) {
			continue
		}
		bit, hasBit := rtypeBit(rtype, true)
		for owner := range names {
			e := idx[owner]
			if hasBit {
				e.bits |= bit
			} else {
				e.extra++
			}
			idx[owner] = e
		}
	}
}

// ownerEntryLocked returns the index entry for an absolute or relative owner
// name in zone. ok=false when the name is outside the zone.
func (z *InMemoryZoneStore) ownerEntryLocked(zone, name string) (ownerEntry, bool) {
	rel, ok := relativeOwner(zone, name)
	if !ok {
		return ownerEntry{}, false
	}
	idx := z.ownerIndexFor(zone, false)
	if idx == nil {
		return ownerEntry{}, false
	}
	e, ok := idx[rel]
	return e, ok
}

// ownerExistsLocked reports whether name has any record of a type that counts
// for existence (see shouldMaintainNSEC).
func (z *InMemoryZoneStore) ownerExistsLocked(zone, name string) bool {
	_, ok := z.ownerEntryLocked(zone, name)
	return ok
}

// ownerHasTypeLocked reports whether name has an RRset of rtype.
func (z *InMemoryZoneStore) ownerHasTypeLocked(zone, name, rtype string) bool {
	if shouldMaintainNSEC(rtype) {
		e, ok := z.ownerEntryLocked(zone, name)
		if !ok {
			return false
		}
		if bit, has := rtypeBit(rtype, false); has {
			return e.bits&bit != 0
		}
		if e.extra == 0 {
			return false
		}
		// Overflow type: fall through to the record map.
	}
	rel, ok := relativeOwner(zone, name)
	if !ok {
		return false
	}
	zoneMap, ok := z.cache["zones"][zone]
	if !ok {
		return false
	}
	_, ok = zoneMap[rtype][rel]
	return ok
}

// canonQuery lower-cases and makes absolute without allocating when the name
// already is.
func canonQuery(name string) string {
	return strings.ToLower(dns.Fqdn(name))
}

// relativeOwner returns the owner relative to zone ("@" at the apex).
func relativeOwner(zone, name string) (string, bool) {
	fqdn := canonQuery(name)
	zoneFQDN := canonQuery(zone)
	switch {
	case fqdn == zoneFQDN:
		return "@", true
	case len(fqdn) > len(zoneFQDN) && strings.HasSuffix(fqdn, zoneFQDN) && fqdn[len(fqdn)-len(zoneFQDN)-1] == '.':
		return fqdn[:len(fqdn)-len(zoneFQDN)-1], true
	default:
		return "", false
	}
}

// labelStarts returns the byte offsets at which each label of an absolute
// name starts, from the leftmost label down to the root. For "a.b.c." that is
// [0, 2, 4]. Walking these is how the closest-encloser and delegation
// searches visit ancestors without splitting or joining strings.
func labelStarts(fqdn string, buf []int) []int {
	buf = append(buf[:0], 0)
	for i := 0; i < len(fqdn)-1; i++ {
		if fqdn[i] == '.' {
			buf = append(buf, i+1)
		}
	}
	return buf
}

// closestEncloserLocked finds the longest existing ancestor of name (or name
// itself) within zone. It returns the encloser, the next-closer name (one
// label below the encloser towards the query) and the wildcard at the
// encloser, all absolute.
func (z *InMemoryZoneStore) closestEncloserLocked(zone, name string) (string, string, string, bool) {
	qname := canonQuery(name)
	zoneFQDN := canonQuery(zone)
	if _, inZone := relativeOwner(zoneFQDN, qname); !inZone {
		return "", "", "", false
	}
	var starts [64]int
	for i, start := range labelStarts(qname, starts[:0]) {
		candidate := qname[start:]
		if len(candidate) < len(zoneFQDN) {
			break // above the apex
		}
		if !z.ownerExistsLocked(zoneFQDN, candidate) {
			continue
		}
		nextCloser := qname
		if i > 0 {
			nextCloser = qname[labelStarts(qname, starts[:0])[i-1]:]
		}
		return candidate, nextCloser, "*." + candidate, true
	}
	return "", "", "", false
}

// closestDelegationLocked finds the nearest ancestor of name below the apex
// that is a delegation point (NS without SOA).
func (z *InMemoryZoneStore) closestDelegationLocked(zone, name string) (string, bool) {
	qname := canonQuery(name)
	zoneFQDN := canonQuery(zone)
	if _, inZone := relativeOwner(zoneFQDN, qname); !inZone {
		return "", false
	}
	var starts [64]int
	for _, start := range labelStarts(qname, starts[:0]) {
		candidate := qname[start:]
		if len(candidate) <= len(zoneFQDN) {
			return "", false // reached the apex
		}
		if z.ownerHasTypeLocked(zoneFQDN, candidate, "NS") && !z.ownerHasTypeLocked(zoneFQDN, candidate, "SOA") {
			return candidate, true
		}
	}
	return "", false
}
