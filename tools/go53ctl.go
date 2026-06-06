package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v4"
)

const jwtAudienceClusterJoin = "go53 cluster join"

type repeatedFlag []string

func (r *repeatedFlag) String() string {
	return strings.Join(*r, ",")
}

func (r *repeatedFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value != "" {
		*r = append(*r, value)
	}
	return nil
}

type nodeDiscovery struct {
	NodeID          string `json:"node_id"`
	Mode            string `json:"mode"`
	Transport       string `json:"transport"`
	SyncEndpoint    string `json:"sync_endpoint"`
	PublicKey       string `json:"public_key"`
	Fingerprint     string `json:"fingerprint"`
	TLSEnabled      bool   `json:"tls_enabled"`
	TLSCertificate  string `json:"tls_certificate"`
	TLSFingerprint  string `json:"tls_fingerprint"`
	TLSPublicKeyPin string `json:"tls_public_key_pin"`
	Version         string `json:"version"`
}

type clusterNode struct {
	APIEndpoint     string `json:"api_endpoint"`
	SyncEndpoint    string `json:"sync_endpoint"`
	PublicKey       string `json:"public_key"`
	Fingerprint     string `json:"fingerprint,omitempty"`
	TLSPublicKeyPin string `json:"tls_public_key_pin,omitempty"`
}

type clusterInviteClaims struct {
	Issuer           string                 `json:"iss"`
	Audience         string                 `json:"aud"`
	ExpiresAt        int64                  `json:"exp"`
	IssuedAt         int64                  `json:"iat"`
	TokenID          string                 `json:"jti"`
	ClusterID        string                 `json:"cluster_id"`
	JoinNodeID       string                 `json:"join_node_id"`
	JoinAPIEndpoint  string                 `json:"join_api_endpoint"`
	JoinSyncEndpoint string                 `json:"join_sync_endpoint"`
	Transport        string                 `json:"transport"`
	SyncBindHost     string                 `json:"sync_bind_host"`
	SyncPort         string                 `json:"sync_port"`
	PushTimeoutMs    int                    `json:"push_timeout_ms"`
	ResyncIntervalS  int                    `json:"resync_interval_s"`
	UsageCount       int                    `json:"usage_count"`
	IssuerPublicKey  string                 `json:"issuer_public_key"`
	Nodes            map[string]clusterNode `json:"nodes"`
}

type distributedInviteRecord struct {
	TokenID    string `json:"jti"`
	ClusterID  string `json:"cluster_id"`
	JoinNodeID string `json:"join_node_id"`
	Issuer     string `json:"issuer"`
	Token      string `json:"token"`
	UsageCount int    `json:"usage_count"`
	UsedCount  int    `json:"used_count"`
	IssuedAt   int64  `json:"iat"`
	ExpiresAt  int64  `json:"exp"`
	CreatedAt  int64  `json:"created_at"`
	LastUsedAt int64  `json:"last_used_at,omitempty"`
}

type jwtHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid,omitempty"`
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "cluster" {
		handleCluster(os.Args[2:])
		return
	}

	var (
		dbPath    string
		listAll   bool
		listZone  string
		countOnly bool
	)

	flag.StringVar(&dbPath, "db", "../data/go53", "Path to BadgerDB")
	flag.BoolVar(&listAll, "list-all-zones", false, "List all zones with record type counts")
	flag.StringVar(&listZone, "list-zone", "", "List one specific zone")
	flag.BoolVar(&countOnly, "count-only", false, "Only print record counts")
	flag.Parse()

	if len(os.Args) == 1 {
		printMainUsage(false)
		os.Exit(0)
	}
	if os.Args[1] == "help" || os.Args[1] == "--help" || os.Args[1] == "-h" {
		printMainUsage(true)
		os.Exit(0)
	}

	absPath, err := filepath.Abs(dbPath)
	if err != nil {
		log.Fatal(err)
	}

	opts := badger.DefaultOptions(absPath).WithLogger(nil)
	db, err := badger.Open(opts)
	if err != nil {
		log.Fatalf("Failed to open BadgerDB: %v", err)
	}
	defer db.Close()

	switch {
	case listAll:
		handleListAllZones(db, countOnly)
	case listZone != "":
		handleListZone(db, listZone, countOnly)
	default:
		dumpAll(db)
	}
}

func printMainUsage(help bool) {
	fmt.Println(`Usage: go53ctl [COMMAND] [OPTIONS]

Commands:
  cluster invite       Create a JWT invite token for a new distributed node
  cluster join         Join/configure a distributed node from a JWT invite token`)
	if help {
		fmt.Println(`
Cluster examples:
  go53ctl cluster invite
  go53ctl cluster join --token TOKEN

Zone storage tools:
  go53ctl --list-all-zones --count-only
  go53ctl --list-zone go53.test
  go53ctl --list-zone go53.test --count-only`)
		return
	}
	fmt.Println(`
Zone storage tools:
  --db PATH            Path to BadgerDB (default: ../data/go53)
  --list-all-zones     List all zones with their record rtypes and counts
  --list-zone ZONE     List a specific zone's records
  --count-only         Only show record counts instead of full record data

Examples:
  go53ctl cluster invite
  go53ctl cluster join --token TOKEN --api http://10.0.0.11:8053 --sync-endpoint tls://10.0.0.11:53530
  go53ctl --list-all-zones --count-only`)
}

func handleListAllZones(db *badger.DB, countOnly bool) {
	result := make(map[string]map[string]map[string]interface{})

	err := db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			log.Println(item)
			zone := string(item.Key())

			err := item.Value(func(val []byte) error {
				// val holds JSON like: {"A": { ... }, "SOA": { ... }, …}
				var records map[string]map[string]interface{}
				if err := json.Unmarshal(val, &records); err != nil {
					fmt.Printf("Skipping %s: failed to unmarshal: %v\n", zone, err)
					return nil
				}

				result[zone] = make(map[string]map[string]interface{}, len(records))
				for rtype, entries := range records {
					result[zone][rtype] = entries
				}
				return nil
			})

			if err != nil {
				fmt.Printf("Error reading zone %s: %v\n", zone, err)
			}
		}
		return nil
	})

	if err != nil {
		log.Fatalf("DB read failed: %v", err)
	}

	if countOnly {
		for zone, types := range result {
			fmt.Printf("%s:\n", zone)
			for rtype, count := range types {
				fmt.Printf("  %s: %d\n", rtype, count)
			}
		}
	} else {
		printIndentedJSON(result)
	}
}

func handleListZone(db *badger.DB, zone string, countOnly bool) {
	err := db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(zone))
		if err != nil {
			return fmt.Errorf("zone '%s' not found", zone)
		}

		return item.Value(func(val []byte) error {
			var records map[string]map[string]interface{}
			if err := json.Unmarshal(val, &records); err != nil {
				return fmt.Errorf("unmarshal error: %v", err)
			}

			if countOnly {
				fmt.Printf("%s:\n", zone)
				for rtype, entries := range records {
					fmt.Printf("  %s: %d\n", rtype, len(entries))
				}
			} else {
				printIndentedJSON(records)
			}
			return nil
		})
	})

	if err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func dumpAll(db *badger.DB) {
	fmt.Println("Dumping all zones and all records...\n")
	err := db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			zone := string(item.Key())
			err := item.Value(func(val []byte) error {
				fmt.Printf("Zone: %s\n", zone)
				var raw json.RawMessage
				if err := json.Unmarshal(val, &raw); err != nil {
					fmt.Printf("  [Unparseable value]\n\n")
					return nil
				}
				printIndentedZoneValue(raw)
				return nil
			})
			if err != nil {
				fmt.Printf("Error reading zone %s: %v\n", zone, err)
			}
		}
		return nil
	})

	if err != nil {
		log.Fatalf("DB iteration failed: %v", err)
	}
}

func handleCluster(args []string) {
	if len(args) == 0 {
		printClusterUsage()
		os.Exit(1)
	}
	switch args[0] {
	case "invite":
		handleClusterInvite(args[1:])
	case "join":
		handleClusterJoin(args[1:])
	default:
		printClusterUsage()
		os.Exit(1)
	}
}

func printClusterUsage() {
	fmt.Println(`Usage:
  go53ctl cluster invite [--usage-count 1]
  go53ctl cluster join --token TOKEN [--api http://127.0.0.1:8053] [--sync-endpoint tls://HOST:PORT] [--dry-run]

cluster invite flags:
  --api                 Local issuer API endpoint, default http://127.0.0.1:8053
  --issuer-node         Existing node_id that signs the invite
  --issuer-private-key  Base64 Ed25519 private key for issuer node
  --cluster-id          Stable cluster identifier
  --join-node-id        Optional node ID for the new node; otherwise set during join
  --join-api-endpoint   Optional API endpoint for the new node; otherwise set during join
  --join-sync-endpoint  Optional distributed sync endpoint for the new node; otherwise set during join
  --node                Existing node API endpoint. Repeat for every current node.
  --ttl                 Invite lifetime, default 10m
  --usage-count         Number of allowed uses to record for this invite, default 1
  --transport           Distributed transport, default tls
  --sync-bind-host      Local bind host to configure on joining node, default 0.0.0.0
  --sync-port           Local sync port to configure on joining node, default derived from join sync endpoint or :53530
  --push-timeout-ms     Distributed push timeout, default 2000
  --resync-interval-s   Distributed resync interval, default 30

cluster join flags:
  --token               JWT invite token
  --api                 Local node API endpoint, default from token join_api_endpoint or http://127.0.0.1:8053
  --sync-endpoint       Advertised sync endpoint for this joining node, default from token or local discovery
  --dry-run             Print generated config and remote patches without applying them`)
}

func handleClusterInvite(args []string) {
	fs := flag.NewFlagSet("cluster invite", flag.ExitOnError)
	var nodes repeatedFlag
	var apiEndpoint, issuerNode, issuerPrivateKey, clusterID, joinNodeID, joinAPIEndpoint, joinSyncEndpoint string
	var ttl, transport, syncBindHost, syncPort string
	var pushTimeoutMs, resyncIntervalS, usageCount int
	fs.StringVar(&apiEndpoint, "api", "http://127.0.0.1:8053", "Local issuer API endpoint")
	fs.StringVar(&issuerNode, "issuer-node", "", "Existing node_id that signs the invite")
	fs.StringVar(&issuerPrivateKey, "issuer-private-key", "", "Base64 Ed25519 private key for issuer node")
	fs.StringVar(&clusterID, "cluster-id", "", "Stable cluster identifier")
	fs.StringVar(&joinNodeID, "join-node-id", "", "Node ID for the new node")
	fs.StringVar(&joinAPIEndpoint, "join-api-endpoint", "", "API endpoint where existing nodes can reach the new node")
	fs.StringVar(&joinSyncEndpoint, "join-sync-endpoint", "", "Distributed sync endpoint for the new node")
	fs.Var(&nodes, "node", "Existing node API endpoint. Repeat for every current node.")
	fs.StringVar(&ttl, "ttl", "10m", "Invite lifetime")
	fs.IntVar(&usageCount, "usage-count", 1, "Number of allowed uses to record for this invite")
	fs.StringVar(&transport, "transport", "tls", "Distributed transport")
	fs.StringVar(&syncBindHost, "sync-bind-host", "0.0.0.0", "Local bind host to configure on joining node")
	fs.StringVar(&syncPort, "sync-port", "", "Local sync port to configure on joining node")
	fs.IntVar(&pushTimeoutMs, "push-timeout-ms", 2000, "Distributed push timeout")
	fs.IntVar(&resyncIntervalS, "resync-interval-s", 30, "Distributed resync interval")
	_ = fs.Parse(args)

	localConfig, _ := fetchLiveConfig(apiEndpoint)
	localInfo, _ := fetchNodeDiscovery(apiEndpoint)
	if issuerNode == "" {
		issuerNode = localInfo.NodeID
	}
	if issuerPrivateKey == "" {
		issuerPrivateKey = stringFromPath(localConfig, "distributed", "private_key")
	}
	if clusterID == "" {
		clusterID = issuerNode
	}
	if transport == "" {
		transport = stringFromPath(localConfig, "distributed", "transport")
	}
	if syncBindHost == "" {
		syncBindHost = stringFromPath(localConfig, "distributed", "sync_bind_host")
	}
	if pushTimeoutMs == 0 {
		pushTimeoutMs = intFromPath(localConfig, "distributed", "push_timeout_ms")
	}
	if resyncIntervalS == 0 {
		resyncIntervalS = intFromPath(localConfig, "distributed", "resync_interval_s")
	}
	if len(nodes) == 0 && localInfo.NodeID != "" {
		nodes = append(nodes, strings.TrimRight(apiEndpoint, "/"))
		for _, peerAPI := range peerAPIEndpointsFromConfig(localConfig) {
			nodes = append(nodes, peerAPI)
		}
	}
	if usageCount <= 0 {
		log.Fatalf("--usage-count must be greater than zero")
	}
	if issuerNode == "" || issuerPrivateKey == "" || clusterID == "" || len(nodes) == 0 {
		log.Fatalf("missing required invite data; ensure local node is distributed or pass explicit flags")
	}
	duration, err := time.ParseDuration(ttl)
	if err != nil {
		log.Fatalf("invalid --ttl: %v", err)
	}
	if syncPort == "" {
		syncPort = syncPortFromEndpoint(joinSyncEndpoint)
	}
	privateKey, err := decodeEd25519PrivateKey(issuerPrivateKey)
	if err != nil {
		log.Fatal(err)
	}
	issuerPublicKey := base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))
	now := time.Now().Unix()
	tokenID, err := newTokenID()
	if err != nil {
		log.Fatal(err)
	}
	claims := clusterInviteClaims{
		Issuer:           issuerNode,
		Audience:         jwtAudienceClusterJoin,
		ExpiresAt:        time.Now().Add(duration).Unix(),
		IssuedAt:         now,
		TokenID:          tokenID,
		ClusterID:        clusterID,
		JoinNodeID:       joinNodeID,
		JoinAPIEndpoint:  strings.TrimRight(joinAPIEndpoint, "/"),
		JoinSyncEndpoint: joinSyncEndpoint,
		Transport:        strings.ToLower(strings.TrimSpace(transport)),
		SyncBindHost:     syncBindHost,
		SyncPort:         syncPort,
		PushTimeoutMs:    pushTimeoutMs,
		ResyncIntervalS:  resyncIntervalS,
		UsageCount:       usageCount,
		IssuerPublicKey:  issuerPublicKey,
		Nodes:            map[string]clusterNode{},
	}
	for _, endpoint := range nodes {
		info, err := fetchNodeDiscovery(endpoint)
		if err != nil {
			log.Fatalf("fetch %s: %v", endpoint, err)
		}
		if info.NodeID == "" || info.PublicKey == "" || info.SyncEndpoint == "" {
			log.Fatalf("node %s discovery is missing node_id, public_key, or sync_endpoint", endpoint)
		}
		claims.Nodes[info.NodeID] = clusterNode{
			APIEndpoint:     strings.TrimRight(endpoint, "/"),
			SyncEndpoint:    info.SyncEndpoint,
			PublicKey:       info.PublicKey,
			Fingerprint:     info.Fingerprint,
			TLSPublicKeyPin: info.TLSPublicKeyPin,
		}
	}
	for nodeID, publicKey := range stringMapFromPath(localConfig, "distributed", "peer_public_keys") {
		if _, ok := claims.Nodes[nodeID]; ok {
			continue
		}
		claims.Nodes[nodeID] = clusterNode{PublicKey: publicKey}
	}
	if _, ok := claims.Nodes[issuerNode]; !ok {
		log.Fatalf("issuer-node %q must be included in --node discovery endpoints", issuerNode)
	}
	if claims.Nodes[issuerNode].PublicKey != issuerPublicKey {
		log.Fatalf("issuer private key does not match public key advertised by %q", issuerNode)
	}
	token, err := signInviteJWT(claims, privateKey)
	if err != nil {
		log.Fatal(err)
	}
	record := distributedInviteRecord{
		TokenID:    claims.TokenID,
		ClusterID:  claims.ClusterID,
		JoinNodeID: claims.JoinNodeID,
		Issuer:     claims.Issuer,
		Token:      token,
		UsageCount: claims.UsageCount,
		UsedCount:  0,
		IssuedAt:   claims.IssuedAt,
		ExpiresAt:  claims.ExpiresAt,
		CreatedAt:  time.Now().Unix(),
	}
	if err := saveDistributedInviteAPI(apiEndpoint, record); err != nil {
		log.Fatalf("save distributed invite via API: %v", err)
	}
	fmt.Println(token)
}

func handleClusterJoin(args []string) {
	fs := flag.NewFlagSet("cluster join", flag.ExitOnError)
	var token, apiEndpoint, syncEndpoint string
	var dryRun bool
	fs.StringVar(&token, "token", "", "JWT invite token")
	fs.StringVar(&apiEndpoint, "api", "", "Local node API endpoint")
	fs.StringVar(&syncEndpoint, "sync-endpoint", "", "Advertised sync endpoint for this joining node")
	fs.BoolVar(&dryRun, "dry-run", false, "Print config and remote patches without applying them")
	_ = fs.Parse(args)
	if token == "" {
		fs.Usage()
		os.Exit(1)
	}
	claims, err := verifyInviteJWT(token)
	if err != nil {
		log.Fatal(err)
	}
	if apiEndpoint == "" {
		apiEndpoint = claims.JoinAPIEndpoint
	}
	if apiEndpoint == "" {
		apiEndpoint = "http://127.0.0.1:8053"
	}

	localConfig, _ := fetchLiveConfig(apiEndpoint)
	localInfo, _ := fetchNodeDiscovery(apiEndpoint)
	claims = completeJoinClaims(claims, apiEndpoint, syncEndpoint, localConfig, localInfo)
	privateKey, publicKey, err := joinKeyPair(localConfig)
	if err != nil {
		log.Fatal(err)
	}
	localPatch := joinLocalConfig(claims, privateKey)
	remotePatches := joinRemotePatches(claims, publicKey)

	if dryRun {
		printJSON("local config patch", localPatch)
		for endpoint, patch := range remotePatches {
			printJSON("remote config patch "+endpoint, patch)
		}
		return
	}
	if err := consumeDistributedInvite(claims); err != nil {
		log.Fatalf("consume invite: %v", err)
	}
	if err := patchConfig(apiEndpoint, localPatch); err != nil {
		log.Fatalf("patch local node %s: %v", apiEndpoint, err)
	}
	for endpoint, patch := range remotePatches {
		if err := patchConfig(endpoint, patch); err != nil {
			log.Fatalf("patch existing node %s: %v", endpoint, err)
		}
	}
	fmt.Printf("joined cluster %s as %s\n", claims.ClusterID, claims.JoinNodeID)
	fmt.Printf("local public_key: %s\n", publicKey)
}

func fetchNodeDiscovery(apiEndpoint string) (nodeDiscovery, error) {
	url := strings.TrimRight(apiEndpoint, "/") + "/.well-known/go53-node.json"
	var info nodeDiscovery
	if err := getJSON(url, &info); err != nil {
		return nodeDiscovery{}, err
	}
	return info, nil
}

func fetchLiveConfig(apiEndpoint string) (map[string]any, error) {
	var cfg map[string]any
	if err := getJSON(strings.TrimRight(apiEndpoint, "/")+"/api/config", &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func getJSON(url string, out any) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := responseError(resp); err != nil {
		return err
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func valueFromPath(root map[string]any, keys ...string) any {
	var current any = root
	for _, key := range keys {
		m, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = m[key]
	}
	return current
}

func stringFromPath(root map[string]any, keys ...string) string {
	value, _ := valueFromPath(root, keys...).(string)
	return value
}

func intFromPath(root map[string]any, keys ...string) int {
	switch v := valueFromPath(root, keys...).(type) {
	case float64:
		return int(v)
	case int:
		return v
	default:
		return 0
	}
}

func stringMapFromPath(root map[string]any, keys ...string) map[string]string {
	out := map[string]string{}
	switch m := valueFromPath(root, keys...).(type) {
	case map[string]any:
		for key, value := range m {
			if s, ok := value.(string); ok {
				out[key] = s
			}
		}
	case map[string]string:
		for key, value := range m {
			out[key] = value
		}
	}
	return out
}

func peerAPIEndpointsFromConfig(root map[string]any) []string {
	raw := stringFromPath(root, "distributed", "peers")
	if raw == "" {
		return nil
	}
	out := []string{}
	for _, peer := range strings.Split(raw, ",") {
		peer = strings.TrimSpace(peer)
		if peer == "" {
			continue
		}
		if strings.HasPrefix(peer, "http://") || strings.HasPrefix(peer, "https://") {
			out = append(out, strings.TrimRight(peer, "/"))
		}
	}
	return out
}

func completeJoinClaims(claims clusterInviteClaims, apiEndpoint, syncEndpoint string, localConfig map[string]any, localInfo nodeDiscovery) clusterInviteClaims {
	if syncEndpoint != "" {
		claims.JoinSyncEndpoint = strings.TrimSpace(syncEndpoint)
		claims.SyncPort = syncPortFromEndpoint(claims.JoinSyncEndpoint)
	}
	if claims.JoinNodeID == "" {
		claims.JoinNodeID = strings.TrimSpace(localInfo.NodeID)
	}
	if claims.JoinNodeID == "" {
		claims.JoinNodeID = stringFromPath(localConfig, "distributed", "node_id")
	}
	if claims.JoinNodeID == "" {
		claims.JoinNodeID = "node-" + time.Now().UTC().Format("20060102150405")
	}
	if claims.JoinAPIEndpoint == "" {
		claims.JoinAPIEndpoint = strings.TrimRight(apiEndpoint, "/")
	}
	if claims.JoinSyncEndpoint == "" {
		claims.JoinSyncEndpoint = strings.TrimSpace(syncEndpoint)
	}
	if claims.JoinSyncEndpoint == "" {
		claims.JoinSyncEndpoint = strings.TrimSpace(localInfo.SyncEndpoint)
	}
	if claims.JoinSyncEndpoint == "" {
		claims.JoinSyncEndpoint = "tls://127.0.0.1" + syncPortOrDefault(claims.SyncPort)
	}
	if claims.SyncPort == "" {
		claims.SyncPort = syncPortFromEndpoint(claims.JoinSyncEndpoint)
	}
	if claims.Transport == "" {
		claims.Transport = "tls"
	}
	if claims.SyncBindHost == "" {
		claims.SyncBindHost = "0.0.0.0"
	}
	if claims.PushTimeoutMs <= 0 {
		claims.PushTimeoutMs = 2000
	}
	if claims.ResyncIntervalS <= 0 {
		claims.ResyncIntervalS = 30
	}
	return claims
}

func joinKeyPair(localConfig map[string]any) (privateKeyB64 string, publicKeyB64 string, err error) {
	existing := strings.TrimSpace(stringFromPath(localConfig, "distributed", "private_key"))
	if existing == "" {
		return generateDistributedKeyPair()
	}
	privateKey, err := decodeEd25519PrivateKey(existing)
	if err != nil {
		return "", "", fmt.Errorf("local distributed private_key is invalid: %w", err)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return existing, base64.StdEncoding.EncodeToString(publicKey), nil
}

func joinLocalConfig(claims clusterInviteClaims, privateKey string) map[string]any {
	peerKeys := map[string]string{}
	peers := make([]string, 0, len(claims.Nodes))
	for nodeID, node := range claims.Nodes {
		peerKeys[nodeID] = node.PublicKey
		if node.SyncEndpoint != "" {
			peers = append(peers, node.SyncEndpoint)
		}
	}
	sortStrings(peers)
	return map[string]any{
		"mode": "distributed",
		"distributed": map[string]any{
			"node_id":           claims.JoinNodeID,
			"transport":         claims.Transport,
			"sync_bind_host":    claims.SyncBindHost,
			"sync_port":         claims.SyncPort,
			"peers":             strings.Join(peers, ","),
			"private_key":       privateKey,
			"peer_public_keys":  peerKeys,
			"push_timeout_ms":   claims.PushTimeoutMs,
			"resync_interval_s": claims.ResyncIntervalS,
		},
	}
}

func joinRemotePatches(claims clusterInviteClaims, joinPublicKey string) map[string]map[string]any {
	allNodes := make(map[string]clusterNode, len(claims.Nodes)+1)
	for nodeID, node := range claims.Nodes {
		allNodes[nodeID] = node
	}
	allNodes[claims.JoinNodeID] = clusterNode{
		APIEndpoint:  claims.JoinAPIEndpoint,
		SyncEndpoint: claims.JoinSyncEndpoint,
		PublicKey:    joinPublicKey,
	}
	out := map[string]map[string]any{}
	for nodeID, target := range claims.Nodes {
		if target.APIEndpoint == "" {
			continue
		}
		peers := make([]string, 0, len(allNodes)-1)
		peerKeys := map[string]string{}
		for peerID, peer := range allNodes {
			if peerID == nodeID {
				continue
			}
			if peer.SyncEndpoint != "" {
				peers = append(peers, peer.SyncEndpoint)
			}
			peerKeys[peerID] = peer.PublicKey
		}
		sortStrings(peers)
		out[target.APIEndpoint] = map[string]any{
			"distributed": map[string]any{
				"peers":            strings.Join(peers, ","),
				"peer_public_keys": peerKeys,
			},
		}
	}
	return out
}

func patchConfig(apiEndpoint string, patch map[string]any) error {
	return requestJSON(http.MethodPatch, strings.TrimRight(apiEndpoint, "/")+"/api/config", patch)
}

func saveDistributedInviteAPI(apiEndpoint string, record distributedInviteRecord) error {
	return requestJSON(http.MethodPost, strings.TrimRight(apiEndpoint, "/")+"/api/distributed/invites", record)
}

func consumeDistributedInvite(claims clusterInviteClaims) error {
	issuer, ok := claims.Nodes[claims.Issuer]
	if !ok || issuer.APIEndpoint == "" {
		return errors.New("invite does not include issuer API endpoint")
	}
	return requestNoBody(http.MethodPost, strings.TrimRight(issuer.APIEndpoint, "/")+"/api/distributed/invites/"+claims.TokenID+"/consume")
}

func requestNoBody(method, url string) error {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return responseError(resp)
}

func requestJSON(method, url string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return responseError(resp)
}

func responseError(resp *http.Response) error {
	if resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return nil
}

func signInviteJWT(claims clusterInviteClaims, privateKey ed25519.PrivateKey) (string, error) {
	header := jwtHeader{Algorithm: "EdDSA", Type: "JWT", KeyID: claims.Issuer}
	headerPart, err := marshalJWTPart(header)
	if err != nil {
		return "", err
	}
	claimsPart, err := marshalJWTPart(claims)
	if err != nil {
		return "", err
	}
	signingInput := headerPart + "." + claimsPart
	signature := ed25519.Sign(privateKey, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func verifyInviteJWT(token string) (clusterInviteClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return clusterInviteClaims{}, errors.New("invalid JWT format")
	}
	var header jwtHeader
	if err := unmarshalJWTPart(parts[0], &header); err != nil {
		return clusterInviteClaims{}, err
	}
	if header.Algorithm != "EdDSA" || header.Type != "JWT" {
		return clusterInviteClaims{}, errors.New("invite JWT must use EdDSA")
	}
	var claims clusterInviteClaims
	if err := unmarshalJWTPart(parts[1], &claims); err != nil {
		return clusterInviteClaims{}, err
	}
	if claims.Audience != jwtAudienceClusterJoin {
		return clusterInviteClaims{}, errors.New("invite JWT has wrong audience")
	}
	if claims.ExpiresAt <= time.Now().Unix() {
		return clusterInviteClaims{}, errors.New("invite JWT expired")
	}
	if claims.UsageCount <= 0 {
		return clusterInviteClaims{}, errors.New("invite JWT has invalid usage_count")
	}
	publicKey, err := decodeEd25519PublicKey(claims.IssuerPublicKey)
	if err != nil {
		return clusterInviteClaims{}, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return clusterInviteClaims{}, err
	}
	if !ed25519.Verify(publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		return clusterInviteClaims{}, errors.New("invite JWT signature verification failed")
	}
	if len(claims.Nodes) == 0 {
		return clusterInviteClaims{}, errors.New("invite JWT missing cluster nodes")
	}
	return claims, nil
}

func marshalJWTPart(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func unmarshalJWTPart(part string, out any) error {
	data, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func decodeEd25519PrivateKey(value string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, err
	}
	switch len(raw) {
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	default:
		return nil, fmt.Errorf("invalid Ed25519 private key length %d", len(raw))
	}
}

func decodeEd25519PublicKey(value string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key length %d", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

func generateDistributedKeyPair() (privateKeyB64 string, publicKeyB64 string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub), nil
}

func newTokenID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func syncPortFromEndpoint(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	idx := strings.LastIndex(endpoint, ":")
	if idx == -1 || idx == len(endpoint)-1 {
		return ":53530"
	}
	port := endpoint[idx+1:]
	if _, err := strconv.Atoi(port); err != nil {
		return ":53530"
	}
	return ":" + port
}

func syncPortOrDefault(port string) string {
	port = strings.TrimSpace(port)
	if port == "" {
		return ":53530"
	}
	if strings.HasPrefix(port, ":") {
		return port
	}
	return ":" + port
}

func printJSON(label string, value any) {
	fmt.Printf("%s:\n%s\n", label, indentedJSON(value, "", "  "))
}

func printIndentedJSON(value any) {
	fmt.Println(indentedJSON(value, "", "  "))
}

func printIndentedZoneValue(value any) {
	fmt.Printf("  %s\n\n", indentedJSON(value, "  ", "  "))
}

func indentedJSON(value any, prefix, indent string) string {
	data, _ := json.MarshalIndent(value, prefix, indent)
	return string(data)
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
