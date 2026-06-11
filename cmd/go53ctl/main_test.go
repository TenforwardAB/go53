package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestAcceptLocalConfigAddsPinnedPeerIdempotently(t *testing.T) {
	cfg := map[string]any{
		"distributed": map[string]any{
			"peers": "tls://10.0.0.10:53530",
			"peer_public_keys": map[string]any{
				"node-a": "pub-a",
			},
		},
	}

	patch := acceptLocalConfig(cfg, "node-b", "tls://10.0.0.11:53530", "pub-b")
	patch = acceptLocalConfig(map[string]any{"distributed": patch["distributed"]}, "node-b", "tls://10.0.0.11:53530", "pub-b")
	dist := patch["distributed"].(map[string]any)
	if got, want := dist["peers"], "tls://10.0.0.10:53530,tls://10.0.0.11:53530"; got != want {
		t.Fatalf("peers = %q, want %q", got, want)
	}
	keys := dist["peer_public_keys"].(map[string]string)
	if keys["node-a"] != "pub-a" || keys["node-b"] != "pub-b" {
		t.Fatalf("peer_public_keys = %#v", keys)
	}
}

func TestRemoveNodeLocalConfigClearsTwoNodePeer(t *testing.T) {
	cfg := map[string]any{
		"distributed": map[string]any{
			"peers": "tls://10.0.0.11:53530",
			"peer_public_keys": map[string]any{
				"node-b": "pub-b",
			},
		},
	}

	patch, err := removeNodeLocalConfig(cfg, "node-b", "")
	if err != nil {
		t.Fatalf("removeNodeLocalConfig: %v", err)
	}
	dist := patch["distributed"].(map[string]any)
	if got := dist["peers"]; got != "" {
		t.Fatalf("peers = %q, want empty", got)
	}
	keys := dist["peer_public_keys"].(map[string]string)
	if len(keys) != 0 {
		t.Fatalf("peer_public_keys = %#v, want empty", keys)
	}
}

func TestRemoveNodeLocalConfigRequiresPeerWhenAmbiguous(t *testing.T) {
	cfg := map[string]any{
		"distributed": map[string]any{
			"peers": "tls://10.0.0.11:53530,tls://10.0.0.12:53530",
			"peer_public_keys": map[string]any{
				"node-b": "pub-b",
				"node-c": "pub-c",
			},
		},
	}

	if _, err := removeNodeLocalConfig(cfg, "node-b", ""); err == nil {
		t.Fatalf("removeNodeLocalConfig without peer succeeded")
	}
	patch, err := removeNodeLocalConfig(cfg, "node-b", "tls://10.0.0.11:53530")
	if err != nil {
		t.Fatalf("removeNodeLocalConfig with peer: %v", err)
	}
	dist := patch["distributed"].(map[string]any)
	if got, want := dist["peers"], "tls://10.0.0.12:53530"; got != want {
		t.Fatalf("peers = %q, want %q", got, want)
	}
	keys := dist["peer_public_keys"].(map[string]string)
	if len(keys) != 1 || keys["node-c"] != "pub-c" {
		t.Fatalf("peer_public_keys = %#v, want only node-c", keys)
	}
}

func TestValidateAcceptOptionsChecksPinnedPublicKey(t *testing.T) {
	claims := clusterInviteClaims{JoinNodeID: "node-b", JoinSyncEndpoint: "tls://10.0.0.11:53530"}
	if err := validateAcceptOptions(claims, clusterAcceptOptions{
		JoinNodeID:       "node-b",
		JoinSyncEndpoint: "tls://10.0.0.11:53530",
		JoinPublicKey:    "not-base64",
	}); err == nil {
		t.Fatal("validateAcceptOptions accepted invalid public key")
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAcceptOptions(claims, clusterAcceptOptions{
		JoinNodeID:       "node-b",
		JoinSyncEndpoint: "tls://10.0.0.11:53530",
		JoinPublicKey:    base64.StdEncoding.EncodeToString(pub),
	}); err != nil {
		t.Fatalf("validateAcceptOptions rejected valid options: %v", err)
	}
}

func TestCompleteJoinClaimsDoesNotInventLoopbackSyncEndpoint(t *testing.T) {
	claims := completeJoinClaims(clusterInviteClaims{}, "", "", nil, nodeDiscovery{})
	if claims.JoinSyncEndpoint != "" {
		t.Fatalf("JoinSyncEndpoint = %q, want empty", claims.JoinSyncEndpoint)
	}
}

func TestApplyIssuerSyncEndpointOverride(t *testing.T) {
	claims := clusterInviteClaims{
		Issuer: "node-a",
		Nodes: map[string]clusterNode{
			"node-a": {SyncEndpoint: "tls://127.0.0.1:53530", PublicKey: "pub-a"},
		},
	}

	if err := applyIssuerSyncEndpointOverride(&claims, "tls://95.111.210.11:53530"); err != nil {
		t.Fatalf("applyIssuerSyncEndpointOverride: %v", err)
	}
	if got, want := claims.Nodes["node-a"].SyncEndpoint, "tls://95.111.210.11:53530"; got != want {
		t.Fatalf("issuer SyncEndpoint = %q, want %q", got, want)
	}
}
