package rtypes

import (
	"testing"

	"go53/types"
)

func TestALIASRecordLifecycle(t *testing.T) {
	zone := "aliaslife.test"
	rr, ok := Get(types.AliasTypeCode)
	if !ok {
		t.Fatalf("ALIAS record type not registered")
	}

	if err := rr.Add(zone, "@", map[string]interface{}{"target": "edge.example.net."}, nil); err != nil {
		t.Fatalf("failed to add ALIAS record: %v", err)
	}

	rec, ok := GetALIAS(zone+".", "@")
	if !ok {
		t.Fatalf("expected stored ALIAS record")
	}
	if rec.Target != "edge.example.net." {
		t.Errorf("expected target edge.example.net., got %s", rec.Target)
	}
	if rec.TTL != 60 {
		t.Errorf("expected default TTL 60, got %d", rec.TTL)
	}

	if rrs, found := rr.Lookup(zone + "."); found || rrs != nil {
		t.Errorf("ALIAS must never be served on the wire")
	}

	if err := rr.Delete(zone+".", nil); err != nil {
		t.Fatalf("failed to delete ALIAS record: %v", err)
	}
	if _, ok := GetALIAS(zone+".", "@"); ok {
		t.Errorf("expected ALIAS record to be gone after delete")
	}
}

func TestALIASRejectsSelfTarget(t *testing.T) {
	rr, _ := Get(types.AliasTypeCode)
	err := rr.Add("selfalias.test", "@", map[string]interface{}{"target": "selfalias.test."}, nil)
	if err == nil {
		t.Fatalf("expected self-target ALIAS to be rejected")
	}
}

func TestALIASConflictsWithCNAME(t *testing.T) {
	zone := "aliasconflict.test"
	cname, _ := Get(dnsTypeCNAMEForTest())
	if err := cname.Add(zone, "www", map[string]interface{}{"target": "other.example.net."}, nil); err != nil {
		t.Fatalf("failed to add CNAME: %v", err)
	}

	alias, _ := Get(types.AliasTypeCode)
	if err := alias.Add(zone, "www", map[string]interface{}{"target": "edge.example.net."}, nil); err == nil {
		t.Fatalf("expected ALIAS on CNAME name to be rejected")
	}

	if err := alias.Add(zone, "app", map[string]interface{}{"target": "edge.example.net."}, nil); err != nil {
		t.Fatalf("failed to add ALIAS: %v", err)
	}
	if err := cname.Add(zone, "app", map[string]interface{}{"target": "other.example.net."}, nil); err == nil {
		t.Fatalf("expected CNAME on ALIAS name to be rejected")
	}
}

func dnsTypeCNAMEForTest() uint16 {
	return CNAMERecord{}.Type()
}
