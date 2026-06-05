package distributed

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const merkleBranchPrefixLen = 2

type MerkleZoneRoot struct {
	Zone      string `json:"zone"`
	Root      string `json:"root"`
	LeafCount int    `json:"leaf_count"`
}

type MerkleBranch struct {
	Prefix    string `json:"prefix"`
	Hash      string `json:"hash"`
	LeafCount int    `json:"leaf_count"`
}

type MerkleLeaf struct {
	Entity string `json:"entity"`
	Hash   string `json:"hash"`
}

type zoneMerkleTree struct {
	Zone     string
	Root     string
	Branches map[string]MerkleBranch
	Leaves   map[string]MerkleLeaf
}

type merkleLeafPayload struct {
	Entity string `json:"entity"`
	Zone   string `json:"zone"`
	RRType string `json:"rrtype"`
	Name   string `json:"name"`
	Value  any    `json:"value"`
}

func (s *Service) merkleZoneRoots() (map[string]MerkleZoneRoot, error) {
	if s == nil || s.store == nil {
		return map[string]MerkleZoneRoot{}, nil
	}
	roots := map[string]MerkleZoneRoot{}
	for _, zone := range s.store.ZoneNamesSnapshot() {
		tree, err := s.merkleZoneTree(zone)
		if err != nil {
			return nil, err
		}
		roots[zone] = MerkleZoneRoot{
			Zone:      zone,
			Root:      tree.Root,
			LeafCount: len(tree.Leaves),
		}
	}
	return roots, nil
}

func (s *Service) MerkleZoneRoots() (map[string]MerkleZoneRoot, error) {
	return s.merkleZoneRoots()
}

func (s *Service) merkleZoneBranches(zone string) (map[string]MerkleBranch, error) {
	tree, err := s.merkleZoneTree(zone)
	if err != nil {
		return nil, err
	}
	return tree.Branches, nil
}

func (s *Service) MerkleZoneBranches(zone string) (map[string]MerkleBranch, error) {
	return s.merkleZoneBranches(zone)
}

func (s *Service) merkleZoneLeaves(zone string, prefixes []string) (map[string]MerkleLeaf, error) {
	tree, err := s.merkleZoneTree(zone)
	if err != nil {
		return nil, err
	}
	wanted := map[string]bool{}
	for _, prefix := range prefixes {
		wanted[strings.ToLower(strings.TrimSpace(prefix))] = true
	}
	out := map[string]MerkleLeaf{}
	for entity, leaf := range tree.Leaves {
		if len(wanted) == 0 || wanted[merkleBranchPrefix(entity)] {
			out[entity] = leaf
		}
	}
	return out, nil
}

func (s *Service) MerkleZoneLeaves(zone string, prefixes []string) (map[string]MerkleLeaf, error) {
	return s.merkleZoneLeaves(zone, prefixes)
}

func (s *Service) merkleZoneTree(zone string) (zoneMerkleTree, error) {
	tree := zoneMerkleTree{
		Zone:     zone,
		Branches: map[string]MerkleBranch{},
		Leaves:   map[string]MerkleLeaf{},
	}
	if s == nil || s.store == nil {
		tree.Root = merkleHashStrings(nil)
		return tree, nil
	}
	snapshot := s.store.ZoneRecordsSnapshot(zone)
	for rrtype, names := range snapshot {
		for name, value := range names {
			entity := entityKey(zone, rrtype, name)
			payload := merkleLeafPayload{
				Entity: entity,
				Zone:   zone,
				RRType: strings.ToUpper(strings.TrimSpace(rrtype)),
				Name:   strings.ToLower(strings.TrimSpace(name)),
				Value:  value,
			}
			hash, err := merkleHashJSON(payload)
			if err != nil {
				return tree, err
			}
			tree.Leaves[entity] = MerkleLeaf{Entity: entity, Hash: hash}
		}
	}

	branchLeaves := map[string][]string{}
	leafHashes := make([]string, 0, len(tree.Leaves))
	for entity, leaf := range tree.Leaves {
		prefix := merkleBranchPrefix(entity)
		branchLeaves[prefix] = append(branchLeaves[prefix], leaf.Hash)
		leafHashes = append(leafHashes, leaf.Hash)
	}
	for prefix, hashes := range branchLeaves {
		tree.Branches[prefix] = MerkleBranch{
			Prefix:    prefix,
			Hash:      merkleHashStrings(hashes),
			LeafCount: len(hashes),
		}
	}
	tree.Root = merkleHashStrings(leafHashes)
	return tree, nil
}

func merkleDifferingBranches(local, remote map[string]MerkleBranch) []string {
	keys := map[string]bool{}
	for key := range local {
		keys[key] = true
	}
	for key := range remote {
		keys[key] = true
	}
	out := make([]string, 0)
	for key := range keys {
		l, lok := local[key]
		r, rok := remote[key]
		if !lok || !rok || l.Hash != r.Hash || l.LeafCount != r.LeafCount {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

func merkleDifferingEntities(local, remote map[string]MerkleLeaf) []string {
	keys := map[string]bool{}
	for key := range local {
		keys[key] = true
	}
	for key := range remote {
		keys[key] = true
	}
	out := make([]string, 0)
	for key := range keys {
		l, lok := local[key]
		r, rok := remote[key]
		if !lok || !rok || l.Hash != r.Hash {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

func merkleBranchPrefix(entity string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(entity))))
	encoded := fmt.Sprintf("%x", sum[:])
	if len(encoded) < merkleBranchPrefixLen {
		return encoded
	}
	return encoded[:merkleBranchPrefixLen]
}

func merkleHashJSON(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

func merkleHashStrings(values []string) string {
	if len(values) == 0 {
		sum := sha256.Sum256(nil)
		return base64.RawStdEncoding.EncodeToString(sum[:])
	}
	sort.Strings(values)
	h := sha256.New()
	for _, value := range values {
		h.Write([]byte(value))
		h.Write([]byte{0})
	}
	return base64.RawStdEncoding.EncodeToString(h.Sum(nil))
}
