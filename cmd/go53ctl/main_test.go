package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"strings"
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

func TestCompleteJoinClaimsFallsBackToHostnameNotTimestamp(t *testing.T) {
	host := shortHostname()
	if host == "" {
		t.Skip("no usable hostname in test environment")
	}
	claims := completeJoinClaims(clusterInviteClaims{}, "", "", nil, nodeDiscovery{})
	if claims.JoinNodeID != host {
		t.Fatalf("JoinNodeID = %q, want hostname %q", claims.JoinNodeID, host)
	}
}

func TestParseInterspersedFlagsHandlesTrailingFlag(t *testing.T) {
	cases := map[string][]string{
		"flag after positional":  {"xauth_key", "--generate"},
		"flag before positional": {"--generate", "xauth_key"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			fs := flag.NewFlagSet("config set", flag.ContinueOnError)
			generate := false
			fs.BoolVar(&generate, "generate", false, "")
			rest := parseInterspersedFlags(fs, args)
			if !generate {
				t.Fatalf("--generate not parsed for %v", args)
			}
			if len(rest) != 1 || rest[0] != "xauth_key" {
				t.Fatalf("positionals = %v, want [xauth_key]", rest)
			}
		})
	}
}

func TestParseInterspersedFlagsValueFlagAfterPositional(t *testing.T) {
	fs := flag.NewFlagSet("config set", flag.ContinueOnError)
	var socket string
	fs.StringVar(&socket, "socket", "", "")
	rest := parseInterspersedFlags(fs, []string{"xauth_key", "mykey", "--socket", "/tmp/x.sock"})
	if socket != "/tmp/x.sock" {
		t.Fatalf("socket = %q, want /tmp/x.sock", socket)
	}
	if len(rest) != 2 || rest[0] != "xauth_key" || rest[1] != "mykey" {
		t.Fatalf("positionals = %v, want [xauth_key mykey]", rest)
	}
}

func TestStripCompactFlag(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		want    []string
		compact bool
	}{
		{"absent", []string{"go53ctl", "config", "get"}, []string{"go53ctl", "config", "get"}, false},
		{"bare double dash", []string{"go53ctl", "config", "get", "--compact"}, []string{"go53ctl", "config", "get"}, true},
		{"bare single dash", []string{"go53ctl", "-compact", "config", "get"}, []string{"go53ctl", "config", "get"}, true},
		{"equals true", []string{"go53ctl", "--compact=true", "zones", "list"}, []string{"go53ctl", "zones", "list"}, true},
		{"equals false", []string{"go53ctl", "--compact=false", "zones", "list"}, []string{"go53ctl", "zones", "list"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			compactOutput = false
			got := stripCompactFlag(tc.args)
			if compactOutput != tc.compact {
				t.Fatalf("compactOutput = %v, want %v", compactOutput, tc.compact)
			}
			if strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Fatalf("args = %v, want %v", got, tc.want)
			}
		})
	}
	compactOutput = false
}

func TestFormatResponse(t *testing.T) {
	if got, ok := formatResponse([]byte(`{"b":1,"a":2}`), false); !ok || got != "{\n  \"b\": 1,\n  \"a\": 2\n}" {
		t.Fatalf("pretty JSON = %q ok=%v (key order must be preserved)", got, ok)
	}
	if got, ok := formatResponse([]byte(`{"b":1,"a":2}`), true); !ok || got != `{"b":1,"a":2}` {
		t.Fatalf("compact JSON = %q ok=%v", got, ok)
	}
	if got, ok := formatResponse([]byte("plain text\n"), false); !ok || got != "plain text" {
		t.Fatalf("non-JSON passthrough = %q ok=%v", got, ok)
	}
	if _, ok := formatResponse([]byte("\n"), false); ok {
		t.Fatalf("empty body should not print")
	}
}

func TestShortHostnameStripsDomain(t *testing.T) {
	if got := shortHostname(); got != "" && strings.ContainsRune(got, '.') {
		t.Fatalf("shortHostname returned non-short value %q", got)
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
