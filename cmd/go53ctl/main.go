package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v4"
)

const jwtAudienceClusterJoin = "go53 cluster join"

// defaultAdminSocketPath mirrors the server's default ADMIN_SOCKET. The local admin
// socket is the break-glass path: it serves the full API gated by filesystem
// permissions (group go53_admin) instead of API tokens, so it stays usable when the
// external IdP is unreachable.
const defaultAdminSocketPath = "/run/go53/admin.sock"

// apiClient carries every HTTP admin request. By default it dials TCP; useAdminSocket
// swaps in a transport that dials a Unix socket instead, so the same request helpers
// work over either transport without rewriting URLs (the socket dialer ignores the
// URL host).
var apiClient = http.DefaultClient

// useAdminSocket routes all subsequent admin requests over the given Unix socket. An
// empty path leaves the default TCP client in place.
func useAdminSocket(path string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	apiClient = socketClient(path)
}

func socketClient(path string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
		},
	}
}

// defaultAdminSocket resolves the admin socket path from GO53_ADMIN_SOCKET, falling
// back to the server default.
func defaultAdminSocket() string {
	if v := strings.TrimSpace(os.Getenv("GO53_ADMIN_SOCKET")); v != "" {
		return v
	}
	return defaultAdminSocketPath
}

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

type clusterInviteOptions struct {
	Nodes            repeatedFlag
	APIEndpoint      string
	IssuerNode       string
	IssuerPrivateKey string
	ClusterID        string
	JoinNodeID       string
	JoinAPIEndpoint  string
	JoinSyncEndpoint string
	TTL              string
	Transport        string
	SyncBindHost     string
	SyncPort         string
	PushTimeoutMs    int
	ResyncIntervalS  int
	UsageCount       int
}

type clusterJoinOptions struct {
	Token        string
	APIEndpoint  string
	SyncEndpoint string
	DryRun       bool
}

type inviteDiscovery struct {
	LocalConfig map[string]any
	LocalInfo   nodeDiscovery
}

type joinPlan struct {
	Claims        clusterInviteClaims
	LocalPatch    map[string]any
	RemotePatches map[string]map[string]any
	PublicKey     string
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "cluster" {
		handleCluster(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "api" {
		handleAPI(os.Args[2:])
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
  api METHOD PATH      Call any admin API route locally over the Unix socket (break-glass)
  cluster invite       Create a JWT invite token for a new distributed node
  cluster join         Join/configure a distributed node from a JWT invite token`)
	if help {
		fmt.Println(`
Local admin examples (Unix socket, no API token):
  go53ctl api GET /api/config
  go53ctl api PATCH /api/config '{"default_ttl":120}'

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
Local admin over Unix socket (break-glass, filesystem-gated):
  go53ctl api METHOD PATH [JSON_BODY]   Run 'go53ctl api' with no args for details
  Requires root or membership in the admin socket group (default go53_admin).

Zone storage tools:
  --db PATH            Path to BadgerDB (default: ../data/go53)
  --list-all-zones     List all zones with their record rtypes and counts
  --list-zone ZONE     List a specific zone's records
  --count-only         Only show record counts instead of full record data

Examples:
  go53ctl api GET /api/config
  go53ctl cluster invite
  go53ctl cluster join --token TOKEN --api http://10.0.0.11:8053 --sync-endpoint tls://10.0.0.11:53530
  go53ctl --list-all-zones --count-only`)
}

func handleListAllZones(db *badger.DB, countOnly bool) {
	result, err := loadAllZones(db)
	if err != nil {
		log.Fatalf("DB read failed: %v", err)
	}
	if countOnly {
		printAllZoneCounts(result)
		return
	}
	printIndentedJSON(result)
}

func handleListZone(db *badger.DB, zone string, countOnly bool) {
	records, err := loadZoneRecords(db, zone)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	if countOnly {
		printZoneCounts(zone, records)
		return
	}
	printIndentedJSON(records)
}

func dumpAll(db *badger.DB) {
	fmt.Println("Dumping all zones and all records...")
	fmt.Println()
	err := db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			zone := string(item.Key())
			if err := dumpZoneItem(zone, item); err != nil {
				fmt.Printf("Error reading zone %s: %v\n", zone, err)
			}
		}
		return nil
	})

	if err != nil {
		log.Fatalf("DB iteration failed: %v", err)
	}
}

func loadAllZones(db *badger.DB) (map[string]map[string]map[string]interface{}, error) {
	result := make(map[string]map[string]map[string]interface{})
	err := db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			log.Println(item)
			readZoneItem(result, string(item.Key()), item)
		}
		return nil
	})
	return result, err
}

func readZoneItem(result map[string]map[string]map[string]interface{}, zone string, item *badger.Item) {
	if err := item.Value(func(val []byte) error {
		var records map[string]map[string]interface{}
		if err := json.Unmarshal(val, &records); err != nil {
			fmt.Printf("Skipping %s: failed to unmarshal: %v\n", zone, err)
			return nil
		}
		result[zone] = records
		return nil
	}); err != nil {
		fmt.Printf("Error reading zone %s: %v\n", zone, err)
	}
}

func loadZoneRecords(db *badger.DB, zone string) (map[string]map[string]interface{}, error) {
	var records map[string]map[string]interface{}
	err := db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(zone))
		if err != nil {
			return fmt.Errorf("zone '%s' not found", zone)
		}
		return item.Value(func(val []byte) error {
			if err := json.Unmarshal(val, &records); err != nil {
				return fmt.Errorf("unmarshal error: %v", err)
			}
			return nil
		})
	})
	return records, err
}

func printAllZoneCounts(zones map[string]map[string]map[string]interface{}) {
	for zone, records := range zones {
		printZoneCounts(zone, records)
	}
}

func printZoneCounts(zone string, records map[string]map[string]interface{}) {
	fmt.Printf("%s:\n", zone)
	for rtype, entries := range records {
		fmt.Printf("  %s: %d\n", rtype, len(entries))
	}
}

func dumpZoneItem(zone string, item *badger.Item) error {
	return item.Value(func(val []byte) error {
		fmt.Printf("Zone: %s\n", zone)
		var raw json.RawMessage
		if err := json.Unmarshal(val, &raw); err != nil {
			fmt.Printf("  [Unparseable value]\n\n")
			return nil
		}
		printIndentedZoneValue(raw)
		return nil
	})
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

// handleAPI is the local break-glass admin client: a thin passthrough that calls any
// admin API route over the Unix socket (default) so the full API stays administrable
// without tokens when the IdP is down. Pass --api to target a TCP endpoint instead.
func handleAPI(args []string) {
	fs := flag.NewFlagSet("api", flag.ExitOnError)
	socket := fs.String("socket", defaultAdminSocket(), "Unix admin socket for local break-glass admin")
	apiBase := fs.String("api", "", "TCP API base URL (e.g. http://127.0.0.1:8053); overrides --socket")
	fs.Usage = printAPIUsage
	_ = fs.Parse(args)

	rest := fs.Args()
	if len(rest) < 2 {
		printAPIUsage()
		os.Exit(1)
	}
	method := strings.ToUpper(rest[0])
	reqPath := rest[1]
	if !strings.HasPrefix(reqPath, "/") {
		reqPath = "/" + reqPath
	}
	var body io.Reader
	if len(rest) >= 3 && rest[2] != "" {
		body = strings.NewReader(rest[2])
	}

	client := http.DefaultClient
	base := strings.TrimRight(*apiBase, "/")
	if *apiBase == "" {
		// The Unix dialer ignores the URL host, so any placeholder host works.
		client = socketClient(*socket)
		base = "http://go53-admin-socket"
	}

	req, err := http.NewRequest(method, base+reqPath, body)
	if err != nil {
		log.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if len(data) > 0 {
		fmt.Println(strings.TrimRight(string(data), "\n"))
	}
	if resp.StatusCode >= 300 {
		os.Exit(1)
	}
}

func printAPIUsage() {
	fmt.Println(`Usage:
  go53ctl api METHOD PATH [JSON_BODY] [flags]

Local break-glass admin over the Unix socket (filesystem-gated, no API token).
Requires root or membership in the admin socket group (default go53_admin).

Flags:
  --socket   Unix admin socket path (default $GO53_ADMIN_SOCKET or /run/go53/admin.sock)
  --api      TCP API base URL (e.g. http://127.0.0.1:8053); overrides --socket

Examples:
  go53ctl api GET /api/config
  go53ctl api PATCH /api/config '{"default_ttl":120}'
  go53ctl api POST /api/zones/example.com./records/A '{"name":"www.example.com.","ttl":300,"ip":"192.0.2.10"}'
  go53ctl api DELETE /api/zones/example.com./records/A/www.example.com.`)
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
	opts := parseClusterInviteOptions(args)
	discovery := discoverInviteDefaults(opts.APIEndpoint)
	opts.applyDefaults(discovery)
	if err := opts.validate(); err != nil {
		log.Fatal(err)
	}
	claims, privateKey, err := buildInviteClaims(opts, discovery.LocalConfig)
	if err != nil {
		log.Fatal(err)
	}
	if err := saveInvite(opts.APIEndpoint, claims, privateKey); err != nil {
		log.Fatal(err)
	}
}

func parseClusterInviteOptions(args []string) clusterInviteOptions {
	fs := flag.NewFlagSet("cluster invite", flag.ExitOnError)
	opts := clusterInviteOptions{}
	fs.StringVar(&opts.APIEndpoint, "api", "http://127.0.0.1:8053", "Local issuer API endpoint")
	fs.StringVar(&opts.IssuerNode, "issuer-node", "", "Existing node_id that signs the invite")
	fs.StringVar(&opts.IssuerPrivateKey, "issuer-private-key", "", "Base64 Ed25519 private key for issuer node")
	fs.StringVar(&opts.ClusterID, "cluster-id", "", "Stable cluster identifier")
	fs.StringVar(&opts.JoinNodeID, "join-node-id", "", "Node ID for the new node")
	fs.StringVar(&opts.JoinAPIEndpoint, "join-api-endpoint", "", "API endpoint where existing nodes can reach the new node")
	fs.StringVar(&opts.JoinSyncEndpoint, "join-sync-endpoint", "", "Distributed sync endpoint for the new node")
	fs.Var(&opts.Nodes, "node", "Existing node API endpoint. Repeat for every current node.")
	fs.StringVar(&opts.TTL, "ttl", "10m", "Invite lifetime")
	fs.IntVar(&opts.UsageCount, "usage-count", 1, "Number of allowed uses to record for this invite")
	fs.StringVar(&opts.Transport, "transport", "tls", "Distributed transport")
	fs.StringVar(&opts.SyncBindHost, "sync-bind-host", "0.0.0.0", "Local bind host to configure on joining node")
	fs.StringVar(&opts.SyncPort, "sync-port", "", "Local sync port to configure on joining node")
	fs.IntVar(&opts.PushTimeoutMs, "push-timeout-ms", 2000, "Distributed push timeout")
	fs.IntVar(&opts.ResyncIntervalS, "resync-interval-s", 30, "Distributed resync interval")
	_ = fs.Parse(args)
	return opts
}

func discoverInviteDefaults(apiEndpoint string) inviteDiscovery {
	localConfig, _ := fetchLiveConfig(apiEndpoint)
	localInfo, _ := fetchNodeDiscovery(apiEndpoint)
	return inviteDiscovery{LocalConfig: localConfig, LocalInfo: localInfo}
}

func (opts *clusterInviteOptions) applyDefaults(discovery inviteDiscovery) {
	if opts.IssuerNode == "" {
		opts.IssuerNode = discovery.LocalInfo.NodeID
	}
	if opts.IssuerPrivateKey == "" {
		opts.IssuerPrivateKey = stringFromPath(discovery.LocalConfig, "distributed", "private_key")
	}
	if opts.ClusterID == "" {
		opts.ClusterID = opts.IssuerNode
	}
	if opts.Transport == "" {
		opts.Transport = stringFromPath(discovery.LocalConfig, "distributed", "transport")
	}
	if opts.SyncBindHost == "" {
		opts.SyncBindHost = stringFromPath(discovery.LocalConfig, "distributed", "sync_bind_host")
	}
	if opts.PushTimeoutMs == 0 {
		opts.PushTimeoutMs = intFromPath(discovery.LocalConfig, "distributed", "push_timeout_ms")
	}
	if opts.ResyncIntervalS == 0 {
		opts.ResyncIntervalS = intFromPath(discovery.LocalConfig, "distributed", "resync_interval_s")
	}
	if len(opts.Nodes) == 0 && discovery.LocalInfo.NodeID != "" {
		opts.Nodes = append(opts.Nodes, defaultInviteNodes(opts.APIEndpoint, discovery.LocalConfig)...)
	}
	if opts.SyncPort == "" {
		opts.SyncPort = syncPortFromEndpoint(opts.JoinSyncEndpoint)
	}
}

func defaultInviteNodes(apiEndpoint string, localConfig map[string]any) []string {
	nodes := []string{strings.TrimRight(apiEndpoint, "/")}
	return append(nodes, peerAPIEndpointsFromConfig(localConfig)...)
}

func (opts clusterInviteOptions) validate() error {
	if opts.UsageCount <= 0 {
		return errors.New("--usage-count must be greater than zero")
	}
	if opts.IssuerNode == "" || opts.IssuerPrivateKey == "" || opts.ClusterID == "" || len(opts.Nodes) == 0 {
		return errors.New("missing required invite data; ensure local node is distributed or pass explicit flags")
	}
	return nil
}

func buildInviteClaims(opts clusterInviteOptions, localConfig map[string]any) (clusterInviteClaims, ed25519.PrivateKey, error) {
	duration, err := time.ParseDuration(opts.TTL)
	if err != nil {
		return clusterInviteClaims{}, nil, fmt.Errorf("invalid --ttl: %w", err)
	}
	privateKey, err := decodeEd25519PrivateKey(opts.IssuerPrivateKey)
	if err != nil {
		return clusterInviteClaims{}, nil, err
	}
	issuerPublicKey := base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))
	claims, err := newInviteClaims(opts, issuerPublicKey, duration)
	if err != nil {
		return clusterInviteClaims{}, nil, err
	}
	if err := populateInviteNodes(&claims, opts.Nodes, localConfig); err != nil {
		return clusterInviteClaims{}, nil, err
	}
	if err := validateInviteClaims(claims, issuerPublicKey); err != nil {
		return clusterInviteClaims{}, nil, err
	}
	return claims, privateKey, nil
}

func newInviteClaims(opts clusterInviteOptions, issuerPublicKey string, duration time.Duration) (clusterInviteClaims, error) {
	tokenID, err := newTokenID()
	if err != nil {
		return clusterInviteClaims{}, err
	}
	now := time.Now().Unix()
	return clusterInviteClaims{
		Issuer:           opts.IssuerNode,
		Audience:         jwtAudienceClusterJoin,
		ExpiresAt:        time.Now().Add(duration).Unix(),
		IssuedAt:         now,
		TokenID:          tokenID,
		ClusterID:        opts.ClusterID,
		JoinNodeID:       opts.JoinNodeID,
		JoinAPIEndpoint:  strings.TrimRight(opts.JoinAPIEndpoint, "/"),
		JoinSyncEndpoint: opts.JoinSyncEndpoint,
		Transport:        strings.ToLower(strings.TrimSpace(opts.Transport)),
		SyncBindHost:     opts.SyncBindHost,
		SyncPort:         opts.SyncPort,
		PushTimeoutMs:    opts.PushTimeoutMs,
		ResyncIntervalS:  opts.ResyncIntervalS,
		UsageCount:       opts.UsageCount,
		IssuerPublicKey:  issuerPublicKey,
		Nodes:            map[string]clusterNode{},
	}, nil
}

func populateInviteNodes(claims *clusterInviteClaims, nodes []string, localConfig map[string]any) error {
	for _, endpoint := range nodes {
		info, err := fetchNodeDiscovery(endpoint)
		if err != nil {
			return fmt.Errorf("fetch %s: %w", endpoint, err)
		}
		if info.NodeID == "" || info.PublicKey == "" || info.SyncEndpoint == "" {
			return fmt.Errorf("node %s discovery is missing node_id, public_key, or sync_endpoint", endpoint)
		}
		claims.Nodes[info.NodeID] = clusterNode{
			APIEndpoint:     strings.TrimRight(endpoint, "/"),
			SyncEndpoint:    info.SyncEndpoint,
			PublicKey:       info.PublicKey,
			Fingerprint:     info.Fingerprint,
			TLSPublicKeyPin: info.TLSPublicKeyPin,
		}
	}
	addConfiguredPeerKeys(claims, localConfig)
	return nil
}

func addConfiguredPeerKeys(claims *clusterInviteClaims, localConfig map[string]any) {
	for nodeID, publicKey := range stringMapFromPath(localConfig, "distributed", "peer_public_keys") {
		if _, ok := claims.Nodes[nodeID]; ok {
			continue
		}
		claims.Nodes[nodeID] = clusterNode{PublicKey: publicKey}
	}
}

func validateInviteClaims(claims clusterInviteClaims, issuerPublicKey string) error {
	if _, ok := claims.Nodes[claims.Issuer]; !ok {
		return fmt.Errorf("issuer-node %q must be included in --node discovery endpoints", claims.Issuer)
	}
	if claims.Nodes[claims.Issuer].PublicKey != issuerPublicKey {
		return fmt.Errorf("issuer private key does not match public key advertised by %q", claims.Issuer)
	}
	return nil
}

func saveInvite(apiEndpoint string, claims clusterInviteClaims, privateKey ed25519.PrivateKey) error {
	token, err := signInviteJWT(claims, privateKey)
	if err != nil {
		return err
	}
	if err := saveDistributedInviteAPI(apiEndpoint, inviteRecord(claims, token)); err != nil {
		return fmt.Errorf("save distributed invite via API: %w", err)
	}
	fmt.Println(token)
	return nil
}

func inviteRecord(claims clusterInviteClaims, token string) distributedInviteRecord {
	return distributedInviteRecord{
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
}

func handleClusterJoin(args []string) {
	opts := parseClusterJoinOptions(args)
	claims, err := verifyInviteJWT(opts.Token)
	if err != nil {
		log.Fatal(err)
	}
	opts.applyDefaults(claims)
	plan, err := buildJoinPlan(opts, claims)
	if err != nil {
		log.Fatal(err)
	}
	if opts.DryRun {
		printJoinPlan(plan)
		return
	}
	if err := applyJoinPlan(opts.APIEndpoint, plan); err != nil {
		log.Fatal(err)
	}
	printJoinOutput(plan)
}

func parseClusterJoinOptions(args []string) clusterJoinOptions {
	fs := flag.NewFlagSet("cluster join", flag.ExitOnError)
	opts := clusterJoinOptions{}
	fs.StringVar(&opts.Token, "token", "", "JWT invite token")
	fs.StringVar(&opts.APIEndpoint, "api", "", "Local node API endpoint")
	fs.StringVar(&opts.SyncEndpoint, "sync-endpoint", "", "Advertised sync endpoint for this joining node")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "Print config and remote patches without applying them")
	_ = fs.Parse(args)
	if opts.Token == "" {
		fs.Usage()
		os.Exit(1)
	}
	return opts
}

func (opts *clusterJoinOptions) applyDefaults(claims clusterInviteClaims) {
	if opts.APIEndpoint == "" {
		opts.APIEndpoint = claims.JoinAPIEndpoint
	}
	if opts.APIEndpoint == "" {
		opts.APIEndpoint = "http://127.0.0.1:8053"
	}
}

func buildJoinPlan(opts clusterJoinOptions, claims clusterInviteClaims) (joinPlan, error) {
	localConfig, _ := fetchLiveConfig(opts.APIEndpoint)
	localInfo, _ := fetchNodeDiscovery(opts.APIEndpoint)
	claims = completeJoinClaims(claims, opts.APIEndpoint, opts.SyncEndpoint, localConfig, localInfo)
	privateKey, publicKey, err := joinKeyPair(localConfig)
	if err != nil {
		return joinPlan{}, err
	}
	return joinPlan{
		Claims:        claims,
		LocalPatch:    joinLocalConfig(claims, privateKey),
		RemotePatches: joinRemotePatches(claims, publicKey),
		PublicKey:     publicKey,
	}, nil
}

func printJoinPlan(plan joinPlan) {
	printJSON("local config patch", plan.LocalPatch)
	for endpoint, patch := range plan.RemotePatches {
		printJSON("remote config patch "+endpoint, patch)
	}
}

func applyJoinPlan(apiEndpoint string, plan joinPlan) error {
	if err := consumeDistributedInvite(plan.Claims); err != nil {
		return fmt.Errorf("consume invite: %w", err)
	}
	if err := patchConfig(apiEndpoint, plan.LocalPatch); err != nil {
		return fmt.Errorf("patch local node %s: %w", apiEndpoint, err)
	}
	for endpoint, patch := range plan.RemotePatches {
		if err := patchConfig(endpoint, patch); err != nil {
			return fmt.Errorf("patch existing node %s: %w", endpoint, err)
		}
	}
	return nil
}

func printJoinOutput(plan joinPlan) {
	fmt.Printf("joined cluster %s as %s\n", plan.Claims.ClusterID, plan.Claims.JoinNodeID)
	fmt.Printf("local public_key: %s\n", plan.PublicKey)
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
	resp, err := apiClient.Get(url)
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
	claims.JoinNodeID = firstNonEmpty(
		claims.JoinNodeID,
		strings.TrimSpace(localInfo.NodeID),
		stringFromPath(localConfig, "distributed", "node_id"),
		"node-"+time.Now().UTC().Format("20060102150405"),
	)
	claims.JoinAPIEndpoint = firstNonEmpty(claims.JoinAPIEndpoint, strings.TrimRight(apiEndpoint, "/"))
	claims.JoinSyncEndpoint = firstNonEmpty(
		claims.JoinSyncEndpoint,
		strings.TrimSpace(syncEndpoint),
		strings.TrimSpace(localInfo.SyncEndpoint),
		"tls://127.0.0.1"+syncPortOrDefault(claims.SyncPort),
	)
	claims.SyncPort = firstNonEmpty(claims.SyncPort, syncPortFromEndpoint(claims.JoinSyncEndpoint))
	claims.Transport = firstNonEmpty(claims.Transport, "tls")
	claims.SyncBindHost = firstNonEmpty(claims.SyncBindHost, "0.0.0.0")
	claims.PushTimeoutMs = positiveOrDefault(claims.PushTimeoutMs, 2000)
	claims.ResyncIntervalS = positiveOrDefault(claims.ResyncIntervalS, 30)
	return claims
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func positiveOrDefault(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
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
	allNodes := joinAllNodes(claims, joinPublicKey)
	out := map[string]map[string]any{}
	for nodeID, target := range claims.Nodes {
		if target.APIEndpoint != "" {
			out[target.APIEndpoint] = remotePatchForNode(nodeID, allNodes)
		}
	}
	return out
}

func joinAllNodes(claims clusterInviteClaims, joinPublicKey string) map[string]clusterNode {
	allNodes := make(map[string]clusterNode, len(claims.Nodes)+1)
	for nodeID, node := range claims.Nodes {
		allNodes[nodeID] = node
	}
	allNodes[claims.JoinNodeID] = clusterNode{
		APIEndpoint:  claims.JoinAPIEndpoint,
		SyncEndpoint: claims.JoinSyncEndpoint,
		PublicKey:    joinPublicKey,
	}
	return allNodes
}

func remotePatchForNode(nodeID string, allNodes map[string]clusterNode) map[string]any {
	peers, peerKeys := remotePeersForNode(nodeID, allNodes)
	return map[string]any{
		"distributed": map[string]any{
			"peers":            strings.Join(peers, ","),
			"peer_public_keys": peerKeys,
		},
	}
}

func remotePeersForNode(nodeID string, allNodes map[string]clusterNode) ([]string, map[string]string) {
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
	return peers, peerKeys
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
	resp, err := apiClient.Do(req)
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
	resp, err := apiClient.Do(req)
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
