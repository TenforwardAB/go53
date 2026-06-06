package distributed

import (
	"testing"

	"go53/config"
	"go53/memory"
	"go53/storage"
)

func TestMerkleTreeEmptyAndFilteredLeaves(t *testing.T) {
	svc := newMerkleOnlyService(t)

	empty, err := svc.MerkleZoneRoots()
	if err != nil {
		t.Fatalf("MerkleZoneRoots empty: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("empty roots = %#v", empty)
	}

	if err := svc.store.PutRecordRaw("example.test.", "A", "www", map[string]any{"ip": "192.0.2.1"}); err != nil {
		t.Fatalf("PutRecordRaw A: %v", err)
	}
	if err := svc.store.PutRecordRaw("example.test.", "AAAA", "www", map[string]any{"ip": "2001:db8::1"}); err != nil {
		t.Fatalf("PutRecordRaw AAAA: %v", err)
	}

	roots, err := svc.MerkleZoneRoots()
	if err != nil {
		t.Fatalf("MerkleZoneRoots: %v", err)
	}
	root := roots["example.test."]
	if root.LeafCount != 2 || root.Root == "" {
		t.Fatalf("root = %#v", root)
	}

	branches, err := svc.MerkleZoneBranches("example.test.")
	if err != nil {
		t.Fatalf("MerkleZoneBranches: %v", err)
	}
	if len(branches) == 0 {
		t.Fatalf("expected branches for two leaves")
	}
	var onePrefix string
	for prefix := range branches {
		onePrefix = prefix
		break
	}
	leaves, err := svc.MerkleZoneLeaves("example.test.", []string{onePrefix})
	if err != nil {
		t.Fatalf("MerkleZoneLeaves: %v", err)
	}
	if len(leaves) == 0 || len(leaves) > 2 {
		t.Fatalf("filtered leaves = %#v", leaves)
	}
	for entity := range leaves {
		if merkleBranchPrefix(entity) != onePrefix {
			t.Fatalf("leaf %q did not match requested prefix %q", entity, onePrefix)
		}
	}
}

func TestMerkleDifferingHelpersAreSorted(t *testing.T) {
	branches := merkleDifferingBranches(
		map[string]MerkleBranch{"b": {Hash: "same", LeafCount: 1}, "a": {Hash: "left", LeafCount: 1}},
		map[string]MerkleBranch{"b": {Hash: "same", LeafCount: 1}, "a": {Hash: "right", LeafCount: 1}, "c": {Hash: "new", LeafCount: 1}},
	)
	if len(branches) != 2 || branches[0] != "a" || branches[1] != "c" {
		t.Fatalf("branches = %#v", branches)
	}

	entities := merkleDifferingEntities(
		map[string]MerkleLeaf{"z": {Hash: "1"}, "a": {Hash: "same"}},
		map[string]MerkleLeaf{"z": {Hash: "2"}, "a": {Hash: "same"}, "m": {Hash: "3"}},
	)
	if len(entities) != 2 || entities[0] != "m" || entities[1] != "z" {
		t.Fatalf("entities = %#v", entities)
	}
}

func newMerkleOnlyService(t *testing.T) *Service {
	t.Helper()
	backend := &storage.MockStorage{}
	if err := backend.Init(); err != nil {
		t.Fatalf("init mock storage: %v", err)
	}
	storage.Backend = backend
	config.AppConfig = &config.ConfigManager{}
	config.AppConfig.Live = config.DefaultLiveConfig
	config.AppConfig.Live.DNSSECEnabled = false
	mem, err := memory.NewZoneStore(backend)
	if err != nil {
		t.Fatalf("new memory store: %v", err)
	}
	return &Service{store: mem, storage: backend}
}
