package rtypes

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"go53/internal"
	"go53/types"
)

// Shape parity (#57): the same records, stored in every shape a writer can
// leave them in, must be served identically by the query path (rtypes Lookup)
// and by the AXFR/signing path (internal.RRBuilders), and Delete with a value
// must remove exactly that value on every shape (#59).
//
// knownGaps lists the combinations that fail today. A gap that starts passing
// fails this test until it is removed from the list, so the list can only
// shrink and always describes the current state.
//
// #57 closed every shape gap and #62 the last non-shape one; the list is
// empty and must stay so.

var knownGaps = map[string]string{}

type paritySpec struct {
	rrtype uint16
	owner  string // "@" for apex
	typed  any    // []types.X for list types, types.X for single-record types
	list   bool
	// deleteValue removes exactly the first record, in the type's own Delete
	// convention (string or map). nil = Delete parity not applicable.
	deleteValue any
}

func paritySpecs() []paritySpec {
	return []paritySpec{
		{dns.TypeA, "www", []types.ARecord{{IP: "192.0.2.1", TTL: 300}, {IP: "192.0.2.2", TTL: 300}, {IP: "192.0.2.3", TTL: 300}}, true, "192.0.2.1"},
		{dns.TypeAAAA, "www", []types.AAAARecord{{IP: "2001:db8::1", TTL: 300}, {IP: "2001:db8::2", TTL: 300}}, true, "2001:db8::1"},
		{dns.TypeNS, "@", []types.NSRecord{{NS: "ns1.example.", TTL: 300}, {NS: "ns2.example.", TTL: 300}}, true, "ns1.example."},
		{dns.TypeMX, "@", []types.MXRecord{{Host: "mx1.example.", Priority: 10, TTL: 300}, {Host: "mx2.example.", Priority: 20, TTL: 300}}, true,
			map[string]interface{}{"host": "mx1.example.", "priority": float64(10)}},
		{dns.TypePTR, "1", []types.PTRRecord{{Ptr: "a.example.", TTL: 300}, {Ptr: "b.example.", TTL: 300}}, true, "a.example."},
		{dns.TypeTXT, "txt", []types.TXTRecord{{Text: "first value", TTL: 300}, {Text: "second value", TTL: 300}}, true, "first value"},
		{dns.TypeSRV, "_sip._tcp", []types.SRVRecord{{Priority: 10, Weight: 5, Port: 5060, Target: "sip1.example.", TTL: 300}, {Priority: 20, Weight: 5, Port: 5061, Target: "sip2.example.", TTL: 300}}, true,
			map[string]interface{}{"target": "sip1.example.", "port": float64(5060)}},
		{dns.TypeCAA, "@", []types.CAARecord{{Flag: 0, Tag: "issue", Value: "ca1.example", TTL: 300}, {Flag: 0, Tag: "issue", Value: "ca2.example", TTL: 300}}, true,
			map[string]interface{}{"flag": float64(0), "tag": "issue", "value": "ca1.example"}},
		{dns.TypeCNAME, "alias", types.CNAMERecord{Target: "www.example.", TTL: 300}, false, nil},
		{dns.TypeDNAME, "old", types.DNAMERecord{Target: "new.example.", TTL: 300}, false, nil},
		{dns.TypeSPF, "spf", types.SPFRecord{Text: "v=spf1 -all", TTL: 300}, false, nil},
		{dns.TypeSOA, "@", types.SOARecord{Ns: "ns1.example.", Mbox: "hostmaster.example.", Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: 300, TTL: 3600}, false, nil},
		// DNSSEC list types at a non-apex owner, so Lookup does not merge in the
		// zone's own key material. DS/CDS Delete only support the whole RRset.
		{dns.TypeDS, "child", []types.DSRecord{{KeyTag: 1, Algorithm: 13, DigestType: 2, Digest: "AABB", TTL: 300}, {KeyTag: 2, Algorithm: 13, DigestType: 2, Digest: "CCDD", TTL: 300}}, true, nil},
		{dns.TypeCDS, "child", []types.CDSRecord{{KeyTag: 1, Algorithm: 13, DigestType: 2, Digest: "AABB", TTL: 300}, {KeyTag: 2, Algorithm: 13, DigestType: 2, Digest: "CCDD", TTL: 300}}, true, nil},
		{dns.TypeDNSKEY, "child", []types.DNSKEYRecord{{Flags: 256, Protocol: 3, Algorithm: 13, PublicKey: "AAAA", TTL: 300}, {Flags: 257, Protocol: 3, Algorithm: 13, PublicKey: "BBBB", TTL: 300}}, true,
			map[string]interface{}{"flags": float64(256), "algorithm": float64(13), "public_key": "AAAA"}},
		{dns.TypeCDNSKEY, "child", []types.CDNSKEYRecord{{Flags: 256, Protocol: 3, Algorithm: 13, PublicKey: "AAAA", TTL: 300}, {Flags: 257, Protocol: 3, Algorithm: 13, PublicKey: "BBBB", TTL: 300}}, true,
			map[string]interface{}{"flags": float64(256), "algorithm": float64(13), "public_key": "AAAA"}},
		// Denial records. NSEC3 owners are uppercase base32 hashes; the next
		// hash must decode as base32hex (20 bytes for SHA-1).
		{dns.TypeNSEC, "b", types.NSECRecord{NextDomain: "c.example.", Types: []string{"A", "RRSIG", "NSEC"}, TTL: 300}, false, nil},
		{dns.TypeNSEC3, "0P9MHAVEQVM6T7VBL5LOP2U3T4RH46HU", types.NSEC3Record{HashAlg: 1, Flags: 0, Iterations: 0, Salt: "-", NextHashed: "2T7B4G4VSA5SMI47K61MV5BV1A22BOJR", Types: []string{"A", "RRSIG"}, TTL: 300}, false, nil},
		{dns.TypeNSEC3PARAM, "@", types.NSEC3ParamRecord{HashAlgorithm: 1, Flags: 0, Iterations: 0, Salt: "-", TTL: 300}, false, nil},
		// ALIAS is never served directly (its Lookup returns nil, false by
		// design; the flattener materialises A/AAAA), so it has no parity row.
	}
}

type parityShape struct {
	name  string
	value any
}

func parityJSON(t *testing.T, v any) any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// parityShapes derives every writer shape from the typed value.
func parityShapes(t *testing.T, spec paritySpec) []parityShape {
	t.Helper()
	shapes := []parityShape{
		{"typed", spec.typed},
		{"json", parityJSON(t, spec.typed)}, // after restart / replication / restore
	}
	if !spec.list {
		return shapes
	}
	items := parityJSON(t, spec.typed).([]interface{})
	mapSlice := make([]map[string]interface{}, 0, len(items))
	mapSliceU32 := make([]map[string]interface{}, 0, len(items))
	for _, it := range items {
		m := it.(map[string]interface{})
		mapSlice = append(mapSlice, m)
		u := make(map[string]interface{}, len(m))
		for k, v := range m {
			u[k] = v
		}
		u["ttl"] = uint32(m["ttl"].(float64)) // typed-writer ttl inside a map (RRSIG/ALIAS style)
		mapSliceU32 = append(mapSliceU32, u)
	}
	// []any holding the typed structs: what a typed writer that went through
	// a []interface{} leaves behind (the signer does this for RRSIG).
	var anyTyped []interface{}
	switch tv := spec.typed.(type) {
	case []types.ARecord:
		for _, r := range tv {
			anyTyped = append(anyTyped, r)
		}
	case []types.AAAARecord:
		for _, r := range tv {
			anyTyped = append(anyTyped, r)
		}
	case []types.NSRecord:
		for _, r := range tv {
			anyTyped = append(anyTyped, r)
		}
	case []types.MXRecord:
		for _, r := range tv {
			anyTyped = append(anyTyped, r)
		}
	case []types.PTRRecord:
		for _, r := range tv {
			anyTyped = append(anyTyped, r)
		}
	case []types.TXTRecord:
		for _, r := range tv {
			anyTyped = append(anyTyped, r)
		}
	case []types.SRVRecord:
		for _, r := range tv {
			anyTyped = append(anyTyped, r)
		}
	case []types.CAARecord:
		for _, r := range tv {
			anyTyped = append(anyTyped, r)
		}
	case []types.DSRecord:
		for _, r := range tv {
			anyTyped = append(anyTyped, r)
		}
	case []types.CDSRecord:
		for _, r := range tv {
			anyTyped = append(anyTyped, r)
		}
	case []types.DNSKEYRecord:
		for _, r := range tv {
			anyTyped = append(anyTyped, r)
		}
	case []types.CDNSKEYRecord:
		for _, r := range tv {
			anyTyped = append(anyTyped, r)
		}
	default:
		t.Fatalf("parityShapes: add a case for %T", spec.typed)
	}
	return append(shapes,
		parityShape{"mapslice", mapSlice},
		parityShape{"mapslice-u32", mapSliceU32},
		parityShape{"anytyped", anyTyped},
	)
}

// rrStrings renders RRs as "ttl TYPE rdata" so RRsets stored in different
// zones (one per shape) compare equal when they carry the same data.
func rrStrings(rrs []dns.RR) []string {
	out := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		hdr := rr.Header()
		rdata := strings.TrimPrefix(rr.String(), hdr.String())
		out = append(out, strings.ToLower(fmt.Sprintf("%d %s %s", hdr.Ttl, dns.TypeToString[hdr.Rrtype], rdata)))
	}
	sort.Strings(out)
	return out
}

// gap reports whether key is a known gap; on a known gap that unexpectedly
// passed it fails the test so the list stays honest.
func gap(t *testing.T, key string, failed bool) {
	t.Helper()
	reason, known := knownGaps[key]
	switch {
	case failed && known:
		t.Skipf("known gap: %s", reason)
	case !failed && known:
		t.Fatalf("known gap %q now passes: remove it from knownGaps", key)
	}
}

func TestShapeParity(t *testing.T) {
	for _, spec := range paritySpecs() {
		typeName := dns.TypeToString[spec.rrtype]
		rr, ok := Get(spec.rrtype)
		if !ok {
			t.Fatalf("%s not registered", typeName)
		}
		builder, hasBuilder := internal.RRBuilders[typeName]
		shapes := parityShapes(t, spec)

		// Reference = the typed shape through Lookup, which every type serves
		// today except A (tracked as a gap and compared against json instead).
		refShape := "typed"
		if _, isGap := knownGaps[typeName+"/typed/lookup"]; isGap {
			refShape = "json"
		}
		var reference []string
		for i, s := range shapes {
			zone := fmt.Sprintf("parity-%s-%d.test.", strings.ToLower(typeName), i)
			host := zone
			if spec.owner != "@" {
				host = spec.owner + "." + zone
			}
			if err := GetMemStore().AddRecord(zone, typeName, spec.owner, s.value); err != nil {
				t.Fatalf("%s/%s: store: %v", typeName, s.name, err)
			}
			GetMemStore().WaitForSigning()

			t.Run(typeName+"/"+s.name+"/lookup", func(t *testing.T) {
				got, ok := rr.Lookup(host)
				failed := !ok || len(got) == 0
				if !failed && reference != nil {
					failed = strings.Join(rrStrings(got), "\n") != strings.Join(reference, "\n")
				}
				gap(t, typeName+"/"+s.name+"/lookup", failed)
				if !ok || len(got) == 0 {
					t.Fatalf("Lookup served nothing for shape %s (%T)", s.name, s.value)
				}
				if s.name == refShape {
					reference = rrStrings(got)
					return
				}
				if want, have := strings.Join(reference, "\n"), strings.Join(rrStrings(got), "\n"); want != have {
					t.Fatalf("Lookup differs from %s shape\n want:\n%s\n have:\n%s", refShape, want, have)
				}
			})

			if hasBuilder {
				t.Run(typeName+"/"+s.name+"/builder", func(t *testing.T) {
					if reference == nil {
						t.Skip("no reference yet")
					}
					got := builder(host, s.value)
					have := strings.Join(rrStrings(got), "\n")
					want := strings.Join(reference, "\n")
					gap(t, typeName+"/"+s.name+"/builder", have != want)
					if have != want {
						t.Fatalf("RRBuilder differs from Lookup\n want:\n%s\n have:\n%s", want, have)
					}
				})
			}

			if spec.deleteValue != nil {
				t.Run(typeName+"/"+s.name+"/delete", func(t *testing.T) {
					before, _ := rr.Lookup(host)
					err := rr.Delete(host, spec.deleteValue)
					after, _ := rr.Lookup(host)
					failed := err != nil || len(before) == 0 || len(after) != len(before)-1
					gap(t, typeName+"/"+s.name+"/delete", failed)
					if err != nil {
						t.Fatalf("Delete: %v", err)
					}
					if len(after) == 0 {
						t.Fatalf("Delete of one value emptied the RRset (%d before) — #59", len(before))
					}
					if len(after) != len(before)-1 {
						t.Fatalf("Delete removed %d records, want 1", len(before)-len(after))
					}
				})
			}
		}
	}
}

// TestKnownGapsAreReachable guards against typos in knownGaps: every key must
// name a type/shape/reader combination the parity test actually runs.
func TestKnownGapsAreReachable(t *testing.T) {
	valid := map[string]bool{}
	for _, spec := range paritySpecs() {
		typeName := dns.TypeToString[spec.rrtype]
		shapeNames := []string{"typed", "json"}
		if spec.list {
			shapeNames = append(shapeNames, "mapslice", "mapslice-u32", "anytyped")
		}
		for _, s := range shapeNames {
			valid[typeName+"/"+s+"/lookup"] = true
			if _, ok := internal.RRBuilders[typeName]; ok {
				valid[typeName+"/"+s+"/builder"] = true
			}
			if spec.deleteValue != nil {
				valid[typeName+"/"+s+"/delete"] = true
			}
		}
	}
	for key := range knownGaps {
		if !valid[key] {
			t.Errorf("knownGaps entry %q does not match any parity case", key)
		}
	}
}
