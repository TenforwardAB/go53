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
// This file: records.go is part of the go53 authoritative DNS server.

package recshape

import (
	"strings"

	"go53/types"
)

// Row → typed record constructors, one per record type, using the JSON field
// names of the types structs. These decode values already in the store, so
// they are lenient the way the readers they replace were: numeric fields
// default to zero and the TTL to DefaultTTL. A constructor returns ok=false
// only when the field that identifies the record is missing, in which case
// the row is not a servable record and Decode skips it.
//
// Input validation of API payloads stays in each rtype's Add.

// DefaultTTL is applied when a stored record carries no usable ttl.
const DefaultTTL uint32 = 3600

// DefaultALIASTTL is the ALIAS default; flattened answers refresh often.
const DefaultALIASTTL uint32 = 60

func ARecord(r Row) (types.ARecord, bool) {
	ip, ok := r.String("ip")
	if !ok || ip == "" {
		return types.ARecord{}, false
	}
	return types.ARecord{IP: ip, TTL: r.TTL(DefaultTTL)}, true
}

func AAAARecord(r Row) (types.AAAARecord, bool) {
	ip, ok := r.String("ip")
	if !ok || ip == "" {
		return types.AAAARecord{}, false
	}
	return types.AAAARecord{IP: ip, TTL: r.TTL(DefaultTTL)}, true
}

func NSRecord(r Row) (types.NSRecord, bool) {
	ns, ok := r.String("ns")
	if !ok || ns == "" {
		return types.NSRecord{}, false
	}
	return types.NSRecord{NS: ns, TTL: r.TTL(DefaultTTL)}, true
}

func MXRecord(r Row) (types.MXRecord, bool) {
	host, ok := r.String("host")
	if !ok || host == "" {
		return types.MXRecord{}, false
	}
	prio, _ := r.Uint16("priority")
	return types.MXRecord{Host: host, Priority: prio, TTL: r.TTL(DefaultTTL)}, true
}

func PTRRecord(r Row) (types.PTRRecord, bool) {
	ptr, ok := r.String("ptr")
	if !ok || ptr == "" {
		return types.PTRRecord{}, false
	}
	return types.PTRRecord{Ptr: ptr, TTL: r.TTL(DefaultTTL)}, true
}

// TXTRecord leaves Chunks empty; readers re-chunk from Text when needed.
func TXTRecord(r Row) (types.TXTRecord, bool) {
	text, ok := r.String("text")
	if !ok {
		return types.TXTRecord{}, false
	}
	return types.TXTRecord{Text: text, TTL: r.TTL(DefaultTTL)}, true
}

// SPFRecord leaves Chunks empty; readers re-chunk from Text when needed.
func SPFRecord(r Row) (types.SPFRecord, bool) {
	text, ok := r.String("text")
	if !ok {
		return types.SPFRecord{}, false
	}
	return types.SPFRecord{Text: text, TTL: r.TTL(DefaultTTL)}, true
}

func SRVRecord(r Row) (types.SRVRecord, bool) {
	target, ok := r.String("target")
	if !ok || target == "" {
		return types.SRVRecord{}, false
	}
	prio, _ := r.Uint16("priority")
	weight, _ := r.Uint16("weight")
	port, _ := r.Uint16("port")
	return types.SRVRecord{Priority: prio, Weight: weight, Port: port, Target: target, TTL: r.TTL(DefaultTTL)}, true
}

func CNAMERecord(r Row) (types.CNAMERecord, bool) {
	target, ok := r.String("target")
	if !ok || target == "" {
		return types.CNAMERecord{}, false
	}
	return types.CNAMERecord{Target: target, TTL: r.TTL(DefaultTTL)}, true
}

func DNAMERecord(r Row) (types.DNAMERecord, bool) {
	target, ok := r.String("target")
	if !ok || target == "" {
		return types.DNAMERecord{}, false
	}
	return types.DNAMERecord{Target: target, TTL: r.TTL(DefaultTTL)}, true
}

func ALIASRecord(r Row) (types.ALIASRecord, bool) {
	target, ok := r.String("target")
	if !ok || target == "" {
		return types.ALIASRecord{}, false
	}
	return types.ALIASRecord{Target: target, TTL: r.TTL(DefaultALIASTTL)}, true
}

func CAARecord(r Row) (types.CAARecord, bool) {
	tag, ok := r.String("tag")
	if !ok || tag == "" {
		return types.CAARecord{}, false
	}
	value, _ := r.String("value")
	flag, _ := r.Uint8("flag")
	return types.CAARecord{Flag: flag, Tag: tag, Value: value, TTL: r.TTL(DefaultTTL)}, true
}

// SOARecord accepts the lowercase JSON names and, for compatibility with
// zone data written by early releases, their capitalised variants ("Ns",
// "Serial", ...). Ns and Mbox are made absolute.
func SOARecord(r Row) (types.SOARecord, bool) {
	ns, ok := soaString(r, "ns")
	if !ok {
		return types.SOARecord{}, false
	}
	mbox, ok := soaString(r, "mbox")
	if !ok {
		return types.SOARecord{}, false
	}
	rec := types.SOARecord{Ns: fqdn(ns), Mbox: fqdn(mbox)}
	rec.Serial, _ = soaUint32(r, "serial")
	rec.Refresh, _ = soaUint32(r, "refresh")
	rec.Retry, _ = soaUint32(r, "retry")
	rec.Expire, _ = soaUint32(r, "expire")
	rec.Minimum, _ = soaUint32(r, "minimum")
	rec.TTL, _ = soaUint32(r, "ttl")
	return rec, true
}

// soaLegacyKeys maps each SOA field to the capitalised key early releases
// persisted, so the fallback costs a map lookup and no allocation.
var soaLegacyKeys = map[string]string{
	"ns": "Ns", "mbox": "Mbox", "serial": "Serial", "refresh": "Refresh",
	"retry": "Retry", "expire": "Expire", "minimum": "Minimum", "ttl": "TTL",
}

func soaKey(r Row, key string) string {
	if _, ok := r[key]; ok {
		return key
	}
	if legacy, ok := soaLegacyKeys[key]; ok {
		if _, ok := r[legacy]; ok {
			return legacy
		}
	}
	return key
}

func soaString(r Row, key string) (string, bool) {
	s, ok := r.String(soaKey(r, key))
	return s, ok && s != ""
}

func soaUint32(r Row, key string) (uint32, bool) {
	return r.Uint32(soaKey(r, key))
}

func fqdn(s string) string {
	if strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}

// DNSKEYRecord defaults Protocol to 3 (RFC 4034 §2.1.2) and requires a key.
func DNSKEYRecord(r Row) (types.DNSKEYRecord, bool) {
	pk, ok := r.String("public_key")
	if !ok || pk == "" {
		return types.DNSKEYRecord{}, false
	}
	rec := types.DNSKEYRecord{PublicKey: pk, Protocol: 3, TTL: r.TTL(DefaultTTL)}
	rec.Flags, _ = r.Uint16("flags")
	if p, ok := r.Uint8("protocol"); ok {
		rec.Protocol = p
	}
	rec.Algorithm, _ = r.Uint8("algorithm")
	return rec, true
}

func CDNSKEYRecord(r Row) (types.CDNSKEYRecord, bool) {
	k, ok := DNSKEYRecord(r)
	if !ok {
		return types.CDNSKEYRecord{}, false
	}
	return types.CDNSKEYRecord{Flags: k.Flags, Protocol: k.Protocol, Algorithm: k.Algorithm, PublicKey: k.PublicKey, TTL: k.TTL}, true
}

// DSRecord normalises the digest to upper-case hex, as the DS/CDS writers do.
func DSRecord(r Row) (types.DSRecord, bool) {
	digest, ok := r.String("digest")
	digest = strings.ToUpper(strings.TrimSpace(digest))
	if !ok || digest == "" {
		return types.DSRecord{}, false
	}
	rec := types.DSRecord{Digest: digest, TTL: r.TTL(DefaultTTL)}
	rec.KeyTag, _ = r.Uint16("key_tag")
	rec.Algorithm, _ = r.Uint8("algorithm")
	rec.DigestType, _ = r.Uint8("digest_type")
	return rec, true
}

func CDSRecord(r Row) (types.CDSRecord, bool) {
	d, ok := DSRecord(r)
	if !ok {
		return types.CDSRecord{}, false
	}
	return types.CDSRecord{KeyTag: d.KeyTag, Algorithm: d.Algorithm, DigestType: d.DigestType, Digest: d.Digest, TTL: d.TTL}, true
}

func NSECRecord(r Row) (types.NSECRecord, bool) {
	next, ok := r.String("next_domain")
	if !ok || next == "" {
		return types.NSECRecord{}, false
	}
	typesList, _ := r.Strings("types")
	return types.NSECRecord{NextDomain: next, Types: typesList, TTL: r.TTL(DefaultTTL)}, true
}

func NSEC3Record(r Row) (types.NSEC3Record, bool) {
	next, ok := r.String("next_hashed")
	if !ok || next == "" {
		return types.NSEC3Record{}, false
	}
	rec := types.NSEC3Record{NextHashed: next, TTL: r.TTL(DefaultTTL)}
	rec.Salt, _ = r.String("salt")
	rec.HashAlg, _ = r.Uint8("hash_algorithm")
	rec.Flags, _ = r.Uint8("flags")
	rec.Iterations, _ = r.Uint16("iterations")
	rec.Types, _ = r.Strings("types")
	return rec, true
}

// NSEC3ParamRecord has no identifying field: any row decodes.
func NSEC3ParamRecord(r Row) (types.NSEC3ParamRecord, bool) {
	rec := types.NSEC3ParamRecord{TTL: r.TTL(DefaultTTL)}
	rec.Salt, _ = r.String("salt")
	rec.HashAlgorithm, _ = r.Uint8("hash_algorithm")
	rec.Flags, _ = r.Uint8("flags")
	rec.Iterations, _ = r.Uint16("iterations")
	return rec, true
}
