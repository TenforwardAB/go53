package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
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

	"go53/distributed"

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

func configureClusterAdmin(socketPath, apiEndpoint string) string {
	if strings.TrimSpace(apiEndpoint) != "" {
		apiClient = http.DefaultClient
		return strings.TrimRight(apiEndpoint, "/")
	}
	apiClient = socketClient(socketPath)
	return "http://go53-admin-socket"
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
	Socket           string
	APIEndpoint      string
	IssuerNode       string
	IssuerPrivateKey string
	ClusterID        string
	JoinNodeID       string
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
	Socket       string
	APIEndpoint  string
	SyncEndpoint string
	DryRun       bool
	NoRegister   bool
	AutoAccept   bool
}

type clusterAcceptOptions struct {
	Token            string
	Socket           string
	APIEndpoint      string
	JoinNodeID       string
	JoinSyncEndpoint string
	JoinPublicKey    string
	DryRun           bool
}

type inviteDiscovery struct {
	LocalConfig map[string]any
	LocalInfo   nodeDiscovery
}

type joinPlan struct {
	Claims     clusterInviteClaims
	LocalPatch map[string]any
	Accept     clusterAcceptRequest
	PublicKey  string
	PrivateKey string
	AutoAccept bool
	Submitted  bool
	Registered bool
}

type clusterAcceptRequest struct {
	Token            string `json:"token"`
	JoinNodeID       string `json:"join_node_id"`
	JoinSyncEndpoint string `json:"join_sync_endpoint"`
	JoinPublicKey    string `json:"join_public_key"`
}

type syncFrame struct {
	Type        string                   `json:"type"`
	JoinRequest *distributed.JoinRequest `json:"join_request,omitempty"`
	AutoAccept  bool                     `json:"auto_accept,omitempty"`
	Applied     bool                     `json:"applied,omitempty"`
	Error       string                   `json:"error,omitempty"`
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
	if len(os.Args) > 1 && handleAdminCommand(os.Args[1], os.Args[2:]) {
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
  config               Read or patch live runtime config
  zones                List, delete, import, or export zones
  records              List, add, get, patch, or delete records
  catalog              Inspect catalog-zone status and members
  secondary            Trigger secondary transfer fetches
  notify               Schedule DNS NOTIFY
  tsig                 Manage TSIG keys
  dnskeys              Manage DNSSEC keys
  ds|cds|cdnskey       Generate parent-signaling records
  distributed          Inspect and repair distributed state
  docs                 Fetch OpenAPI docs or Swagger HTML
  cluster invite       Create a JWT invite token for a new distributed node
  cluster join         Configure and self-register a new node from a JWT invite token
  cluster accept       Manually accept a joined node on an existing cluster node`)
	if help {
		fmt.Println(`
Local admin examples (Unix socket, no API token):
  go53ctl config get
  go53ctl config patch '{"default_ttl":120}'
  go53ctl zones list --limit 50
  go53ctl records add example.com. A '{"name":"www","ttl":300,"ip":"192.0.2.10"}'
  go53ctl records get example.com. A www.example.com.
  go53ctl zones export example.com. > example.com.zone
  go53ctl docs openapi > openapi.yaml

Raw API passthrough:
  go53ctl api GET /api/config
  go53ctl api PATCH /api/config '{"default_ttl":120}'

Cluster examples:
  go53ctl cluster invite
  go53ctl cluster join --token TOKEN --sync-endpoint tls://10.0.0.11:53530
  go53ctl cluster pending
  go53ctl cluster approve node-b
  go53ctl cluster join --token TOKEN --sync-endpoint tls://10.0.0.11:53530 --auto-accept

Zone storage tools:
  go53ctl --list-all-zones --count-only
  go53ctl --list-zone go53.test
  go53ctl --list-zone go53.test --count-only`)
		return
	}
	fmt.Println(`
Local admin over Unix socket (break-glass, filesystem-gated):
  go53ctl COMMAND [SUBCOMMAND] [ARGS]    Run 'go53ctl help' for all commands
  go53ctl api METHOD PATH [JSON_BODY]    Raw route passthrough
  Requires root or membership in the admin socket group (default go53_admin).

Zone storage tools:
  --db PATH            Path to BadgerDB (default: ../data/go53)
  --list-all-zones     List all zones with their record rtypes and counts
  --list-zone ZONE     List a specific zone's records
  --count-only         Only show record counts instead of full record data

Examples:
  go53ctl config get
  go53ctl records add example.com. A '{"name":"www","ip":"192.0.2.10"}'
  go53ctl catalog status
  go53ctl cluster invite
  go53ctl cluster join --token TOKEN --sync-endpoint tls://10.0.0.11:53530
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
	case "accept":
		handleClusterAccept(args[1:])
	case "pending":
		handleClusterPending(args[1:])
	case "approve":
		handleClusterApprove(args[1:])
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

type adminOptions struct {
	Socket string
	API    string
	Limit  int
	Offset int
}

func handleAdminCommand(command string, args []string) bool {
	switch command {
	case "config":
		handleAdminConfig(args)
	case "zones":
		handleAdminZones(args)
	case "records":
		handleAdminRecords(args)
	case "catalog":
		handleAdminCatalog(args)
	case "secondary":
		handleAdminSecondary(args)
	case "notify":
		handleAdminNotify(args)
	case "tsig":
		handleAdminTSIG(args)
	case "dnskeys":
		handleAdminDNSKeys(args)
	case "ds", "cds", "cdnskey":
		handleAdminParentSignal(command, args)
	case "distributed":
		handleAdminDistributed(args)
	case "docs":
		handleAdminDocs(args)
	default:
		return false
	}
	return true
}

func newAdminFlagSet(name string, withPaging bool) (*flag.FlagSet, *adminOptions) {
	opts := &adminOptions{Socket: defaultAdminSocket(), Limit: 100}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.StringVar(&opts.Socket, "socket", opts.Socket, "Unix admin socket path")
	fs.StringVar(&opts.API, "api", "", "TCP API base URL; overrides --socket")
	if withPaging {
		fs.IntVar(&opts.Limit, "limit", 100, "Page size for list endpoints")
		fs.IntVar(&opts.Offset, "offset", 0, "Page offset for list endpoints")
	}
	return fs, opts
}

func adminEndpoint(opts adminOptions) (*http.Client, string) {
	if strings.TrimSpace(opts.API) != "" {
		return http.DefaultClient, strings.TrimRight(opts.API, "/")
	}
	return socketClient(opts.Socket), "http://go53-admin-socket"
}

func adminRequest(opts adminOptions, method, path, body, contentType string) ([]byte, error) {
	client, base := adminEndpoint(opts)
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, base+path, reader)
	if err != nil {
		return nil, err
	}
	if body != "" {
		if contentType == "" {
			contentType = "application/json"
		}
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return data, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(data)))
	}
	return data, nil
}

func mustAdminRequest(opts adminOptions, method, path, body, contentType string) {
	data, err := adminRequest(opts, method, path, body, contentType)
	if err != nil {
		log.Fatal(err)
	}
	printResponse(data)
}

func printResponse(data []byte) {
	if len(data) > 0 {
		fmt.Println(strings.TrimRight(string(data), "\n"))
	}
}

func pageQuery(opts adminOptions) string {
	return fmt.Sprintf("?limit=%d&offset=%d", opts.Limit, opts.Offset)
}

func requireArgs(args []string, n int, usage func()) {
	if len(args) < n {
		usage()
		os.Exit(1)
	}
}

func handleAdminConfig(args []string) {
	if len(args) == 0 {
		printConfigUsage()
		os.Exit(1)
	}
	fs, opts := newAdminFlagSet("config "+args[0], false)
	_ = fs.Parse(args[1:])
	rest := fs.Args()
	switch args[0] {
	case "get":
		mustAdminRequest(*opts, http.MethodGet, "/api/config", "", "")
	case "patch":
		requireArgs(rest, 1, printConfigUsage)
		mustAdminRequest(*opts, http.MethodPatch, "/api/config", rest[0], "application/json")
	default:
		printConfigUsage()
		os.Exit(1)
	}
}

func printConfigUsage() {
	fmt.Println(`Usage:
  go53ctl config get [--socket PATH|--api URL]
  go53ctl config patch JSON [--socket PATH|--api URL]

Examples:
  go53ctl config get
  go53ctl config patch '{"auth":{"mode":"none"}}'`)
}

func handleAdminZones(args []string) {
	if len(args) == 0 {
		printZonesUsage()
		os.Exit(1)
	}
	withPaging := args[0] == "list"
	fs, opts := newAdminFlagSet("zones "+args[0], withPaging)
	_ = fs.Parse(args[1:])
	rest := fs.Args()
	switch args[0] {
	case "list":
		mustAdminRequest(*opts, http.MethodGet, "/api/zones"+pageQuery(*opts), "", "")
	case "delete":
		requireArgs(rest, 1, printZonesUsage)
		mustAdminRequest(*opts, http.MethodDelete, "/api/zones/"+rest[0], "", "")
	case "export":
		requireArgs(rest, 1, printZonesUsage)
		mustAdminRequest(*opts, http.MethodGet, "/api/zones/"+rest[0]+"/export", "", "")
	case "import":
		requireArgs(rest, 2, printZonesUsage)
		data, err := os.ReadFile(rest[1])
		if err != nil {
			log.Fatal(err)
		}
		mustAdminRequest(*opts, http.MethodPost, "/api/zones/"+rest[0]+"/import", string(data), "text/dns")
	default:
		printZonesUsage()
		os.Exit(1)
	}
}

func printZonesUsage() {
	fmt.Println(`Usage:
  go53ctl zones list [--limit N] [--offset N] [--socket PATH|--api URL]
  go53ctl zones delete ZONE [--socket PATH|--api URL]
  go53ctl zones export ZONE [--socket PATH|--api URL]
  go53ctl zones import ZONE FILE [--socket PATH|--api URL]

Examples:
  go53ctl zones list --limit 50
  go53ctl zones export example.com. > example.com.zone
  go53ctl zones import example.com. example.com.zone`)
}

func handleAdminRecords(args []string) {
	if len(args) == 0 {
		printRecordsUsage()
		os.Exit(1)
	}
	withPaging := args[0] == "list" || args[0] == "list-type"
	fs, opts := newAdminFlagSet("records "+args[0], withPaging)
	_ = fs.Parse(args[1:])
	rest := fs.Args()
	switch args[0] {
	case "list":
		requireArgs(rest, 1, printRecordsUsage)
		mustAdminRequest(*opts, http.MethodGet, "/api/zones/"+rest[0]+"/records"+pageQuery(*opts), "", "")
	case "list-type":
		requireArgs(rest, 2, printRecordsUsage)
		mustAdminRequest(*opts, http.MethodGet, "/api/zones/"+rest[0]+"/records/"+strings.ToUpper(rest[1])+pageQuery(*opts), "", "")
	case "add":
		requireArgs(rest, 3, printRecordsUsage)
		mustAdminRequest(*opts, http.MethodPost, "/api/zones/"+rest[0]+"/records/"+strings.ToUpper(rest[1]), rest[2], "application/json")
	case "get":
		requireArgs(rest, 3, printRecordsUsage)
		mustAdminRequest(*opts, http.MethodGet, "/api/zones/"+rest[0]+"/records/"+strings.ToUpper(rest[1])+"/"+rest[2], "", "")
	case "patch":
		requireArgs(rest, 4, printRecordsUsage)
		mustAdminRequest(*opts, http.MethodPatch, "/api/zones/"+rest[0]+"/records/"+strings.ToUpper(rest[1])+"/"+rest[2], rest[3], "application/json")
	case "delete":
		requireArgs(rest, 3, printRecordsUsage)
		body := ""
		if len(rest) > 3 {
			body = rest[3]
		}
		mustAdminRequest(*opts, http.MethodDelete, "/api/zones/"+rest[0]+"/records/"+strings.ToUpper(rest[1])+"/"+rest[2], body, "application/json")
	default:
		printRecordsUsage()
		os.Exit(1)
	}
}

func printRecordsUsage() {
	fmt.Println(`Usage:
  go53ctl records list ZONE [--limit N] [--offset N]
  go53ctl records list-type ZONE RRTYPE [--limit N] [--offset N]
  go53ctl records add ZONE RRTYPE JSON
  go53ctl records get ZONE RRTYPE NAME
  go53ctl records patch ZONE RRTYPE NAME JSON
  go53ctl records delete ZONE RRTYPE NAME [JSON_VALUE]

Examples:
  go53ctl records add example.com. A '{"name":"www","ttl":300,"ip":"192.0.2.10"}'
  go53ctl records get example.com. A www.example.com.
  go53ctl records delete example.com. A www.example.com.`)
}

func handleAdminCatalog(args []string) {
	if len(args) == 0 {
		printCatalogUsage()
		os.Exit(1)
	}
	withPaging := args[0] == "members"
	fs, opts := newAdminFlagSet("catalog "+args[0], withPaging)
	_ = fs.Parse(args[1:])
	switch args[0] {
	case "status":
		mustAdminRequest(*opts, http.MethodGet, "/api/catalog", "", "")
	case "members":
		mustAdminRequest(*opts, http.MethodGet, "/api/catalog/members"+pageQuery(*opts), "", "")
	default:
		printCatalogUsage()
		os.Exit(1)
	}
}

func printCatalogUsage() {
	fmt.Println(`Usage:
  go53ctl catalog status [--socket PATH|--api URL]
  go53ctl catalog members [--limit N] [--offset N] [--socket PATH|--api URL]`)
}

func handleAdminSecondary(args []string) {
	if len(args) == 0 || args[0] != "fetch" {
		printSecondaryUsage()
		os.Exit(1)
	}
	fs, opts := newAdminFlagSet("secondary fetch", false)
	_ = fs.Parse(args[1:])
	rest := fs.Args()
	requireArgs(rest, 1, printSecondaryUsage)
	mustAdminRequest(*opts, http.MethodPost, "/api/secondary/fetch/"+rest[0], "", "")
}

func printSecondaryUsage() {
	fmt.Println(`Usage:
  go53ctl secondary fetch ZONE [--socket PATH|--api URL]`)
}

func handleAdminNotify(args []string) {
	fs, opts := newAdminFlagSet("notify", false)
	_ = fs.Parse(args)
	rest := fs.Args()
	requireArgs(rest, 1, printNotifyUsage)
	mustAdminRequest(*opts, http.MethodPost, "/api/notify/"+rest[0], "", "")
}

func printNotifyUsage() {
	fmt.Println(`Usage:
  go53ctl notify ZONE [--socket PATH|--api URL]`)
}

func handleAdminTSIG(args []string) {
	if len(args) == 0 {
		printTSIGUsage()
		os.Exit(1)
	}
	fs, opts := newAdminFlagSet("tsig "+args[0], false)
	_ = fs.Parse(args[1:])
	rest := fs.Args()
	switch args[0] {
	case "list":
		mustAdminRequest(*opts, http.MethodGet, "/api/tsig", "", "")
	case "add":
		requireArgs(rest, 3, printTSIGUsage)
		body := fmt.Sprintf(`{"algorithm":%q,"secret":%q}`, rest[1], rest[2])
		mustAdminRequest(*opts, http.MethodPost, "/api/tsig/"+rest[0], body, "application/json")
	case "delete":
		requireArgs(rest, 1, printTSIGUsage)
		mustAdminRequest(*opts, http.MethodDelete, "/api/tsig/"+rest[0], "", "")
	default:
		printTSIGUsage()
		os.Exit(1)
	}
}

func printTSIGUsage() {
	fmt.Println(`Usage:
  go53ctl tsig list [--socket PATH|--api URL]
  go53ctl tsig add NAME ALGORITHM SECRET [--socket PATH|--api URL]
  go53ctl tsig delete NAME [--socket PATH|--api URL]`)
}

func handleAdminDNSKeys(args []string) {
	if len(args) == 0 {
		printDNSKeysUsage()
		os.Exit(1)
	}
	fs, opts := newAdminFlagSet("dnskeys "+args[0], false)
	_ = fs.Parse(args[1:])
	rest := fs.Args()
	switch args[0] {
	case "list":
		mustAdminRequest(*opts, http.MethodGet, "/api/dnskeys", "", "")
	case "get":
		requireArgs(rest, 1, printDNSKeysUsage)
		mustAdminRequest(*opts, http.MethodGet, "/api/dnskeys/"+rest[0], "", "")
	case "create":
		requireArgs(rest, 1, printDNSKeysUsage)
		mustAdminRequest(*opts, http.MethodPost, "/api/dnskeys?zone="+rest[0], "", "")
	case "rollover":
		requireArgs(rest, 1, printDNSKeysUsage)
		body := rest[0]
		if len(rest) >= 3 {
			body = fmt.Sprintf(`{"zone":%q,"role":%q,"algorithm":%q}`, rest[0], rest[1], rest[2])
		}
		mustAdminRequest(*opts, http.MethodPost, "/api/dnskeys/rollover", body, "application/json")
	case "lifecycle":
		requireArgs(rest, 2, printDNSKeysUsage)
		mustAdminRequest(*opts, http.MethodPatch, "/api/dnskeys/"+rest[0]+"/lifecycle", rest[1], "application/json")
	case "retire":
		requireArgs(rest, 1, printDNSKeysUsage)
		path := "/api/dnskeys/" + rest[0] + "/retire"
		if len(rest) > 1 {
			path += "?remove_after_days=" + rest[1]
		}
		mustAdminRequest(*opts, http.MethodPost, path, "", "")
	case "revoke":
		requireArgs(rest, 1, printDNSKeysUsage)
		path := "/api/dnskeys/" + rest[0] + "/revoke"
		if len(rest) > 1 {
			path += "?remove_after_days=" + rest[1]
		}
		mustAdminRequest(*opts, http.MethodPost, path, "", "")
	case "delete":
		requireArgs(rest, 1, printDNSKeysUsage)
		mustAdminRequest(*opts, http.MethodDelete, "/api/dnskeys/"+rest[0], "", "")
	default:
		printDNSKeysUsage()
		os.Exit(1)
	}
}

func printDNSKeysUsage() {
	fmt.Println(`Usage:
  go53ctl dnskeys list
  go53ctl dnskeys get ZONE
  go53ctl dnskeys create ZONE
  go53ctl dnskeys rollover JSON
  go53ctl dnskeys rollover ZONE ROLE ALGORITHM
  go53ctl dnskeys lifecycle KEYID JSON
  go53ctl dnskeys retire KEYID [REMOVE_AFTER_DAYS]
  go53ctl dnskeys revoke KEYID [REMOVE_AFTER_DAYS]
  go53ctl dnskeys delete KEYID`)
}

func handleAdminParentSignal(kind string, args []string) {
	fs, opts := newAdminFlagSet(kind, false)
	digest := fs.String("digest", "", "Comma-separated DNSSEC digest type numbers")
	ttl := fs.Int("ttl", 0, "TTL for CDS/CDNSKEY delete signaling")
	deleteSignal := fs.Bool("delete", false, "Return parent delete signaling records")
	_ = fs.Parse(args)
	rest := fs.Args()
	requireArgs(rest, 1, func() { printParentSignalUsage(kind) })
	path := "/api/" + kind + "/" + rest[0]
	query := []string{}
	if *digest != "" {
		query = append(query, "digest="+*digest)
	}
	if *deleteSignal {
		query = append(query, "delete=true")
	}
	if *ttl > 0 {
		query = append(query, fmt.Sprintf("ttl=%d", *ttl))
	}
	if len(query) > 0 {
		path += "?" + strings.Join(query, "&")
	}
	mustAdminRequest(*opts, http.MethodGet, path, "", "")
}

func printParentSignalUsage(kind string) {
	fmt.Printf(`Usage:
  go53ctl %s ZONE [--digest LIST] [--delete] [--ttl N] [--socket PATH|--api URL]
`, kind)
}

func handleAdminDistributed(args []string) {
	if len(args) == 0 {
		printDistributedUsage()
		os.Exit(1)
	}
	fs, opts := newAdminFlagSet("distributed "+args[0], false)
	_ = fs.Parse(args[1:])
	rest := fs.Args()
	switch args[0] {
	case "status":
		mustAdminRequest(*opts, http.MethodGet, "/api/distributed/status", "", "")
	case "keypair":
		mustAdminRequest(*opts, http.MethodPost, "/api/distributed/keypair", "", "")
	case "vector":
		mustAdminRequest(*opts, http.MethodGet, "/api/distributed/vector", "", "")
	case "events":
		path := "/api/distributed/events"
		if len(rest) > 0 {
			path += "?" + strings.Join(rest, "&")
		}
		mustAdminRequest(*opts, http.MethodGet, path, "", "")
	case "post-event":
		requireArgs(rest, 1, printDistributedUsage)
		path := "/api/distributed/events"
		if len(rest) > 1 && rest[1] == "resync" {
			path += "?resync=true"
		}
		mustAdminRequest(*opts, http.MethodPost, path, rest[0], "application/json")
	case "merkle-roots":
		mustAdminRequest(*opts, http.MethodGet, "/api/distributed/merkle/roots", "", "")
	case "merkle-branches":
		requireArgs(rest, 1, printDistributedUsage)
		mustAdminRequest(*opts, http.MethodGet, "/api/distributed/merkle/branches?zone="+rest[0], "", "")
	case "merkle-leaves":
		requireArgs(rest, 1, printDistributedUsage)
		mustAdminRequest(*opts, http.MethodPost, "/api/distributed/merkle/leaves", rest[0], "application/json")
	case "repair-events":
		requireArgs(rest, 1, printDistributedUsage)
		mustAdminRequest(*opts, http.MethodPost, "/api/distributed/merkle/repair-events", rest[0], "application/json")
	case "invite-save":
		requireArgs(rest, 1, printDistributedUsage)
		mustAdminRequest(*opts, http.MethodPost, "/api/distributed/invites", rest[0], "application/json")
	case "invite-consume":
		requireArgs(rest, 1, printDistributedUsage)
		mustAdminRequest(*opts, http.MethodPost, "/api/distributed/invites/"+rest[0]+"/consume", "", "")
	case "well-known":
		mustAdminRequest(*opts, http.MethodGet, "/.well-known/go53-node.json", "", "")
	default:
		printDistributedUsage()
		os.Exit(1)
	}
}

func printDistributedUsage() {
	fmt.Println(`Usage:
  go53ctl distributed status
  go53ctl distributed keypair
  go53ctl distributed vector
  go53ctl distributed events [origin=NODE] [after=N]
  go53ctl distributed post-event JSON [resync]
  go53ctl distributed merkle-roots
  go53ctl distributed merkle-branches ZONE
  go53ctl distributed merkle-leaves JSON
  go53ctl distributed repair-events JSON
  go53ctl distributed invite-save JSON
  go53ctl distributed invite-consume JTI
  go53ctl distributed well-known`)
}

func handleAdminDocs(args []string) {
	if len(args) == 0 {
		printDocsUsage()
		os.Exit(1)
	}
	fs, opts := newAdminFlagSet("docs "+args[0], false)
	_ = fs.Parse(args[1:])
	switch args[0] {
	case "openapi":
		mustAdminRequest(*opts, http.MethodGet, "/openapi.yaml", "", "")
	case "swagger":
		mustAdminRequest(*opts, http.MethodGet, "/swagger", "", "")
	default:
		printDocsUsage()
		os.Exit(1)
	}
}

func printDocsUsage() {
	fmt.Println(`Usage:
  go53ctl docs openapi [--socket PATH|--api URL]
  go53ctl docs swagger [--socket PATH|--api URL]`)
}

func printClusterUsage() {
	fmt.Println(`Usage:
  go53ctl cluster invite [--usage-count 1]
  go53ctl cluster join --token TOKEN --sync-endpoint tls://HOST:PORT [--dry-run]
  go53ctl cluster pending
  go53ctl cluster approve NODE
  go53ctl cluster accept --token TOKEN --join-node-id NODE --join-sync-endpoint tls://HOST:PORT --join-public-key KEY

cluster invite flags:
  --socket              Local issuer Unix admin socket, default from GO53_ADMIN_SOCKET or /run/go53/admin.sock
  --api                 TCP API base URL; overrides --socket
  --issuer-node         Existing node_id that signs the invite
  --issuer-private-key  Base64 Ed25519 private key for issuer node
  --cluster-id          Stable cluster identifier
  --join-node-id        Optional node ID for the new node; otherwise set during join
  --join-sync-endpoint  Optional distributed sync endpoint for the new node; otherwise set during join
  --ttl                 Invite lifetime, default 10m
  --usage-count         Number of allowed uses to record for this invite, default 1
  --transport           Distributed transport, default tls
  --sync-bind-host      Local bind host to configure on joining node, default 0.0.0.0
  --sync-port           Local sync port to configure on joining node, default derived from join sync endpoint
  --push-timeout-ms     Distributed push timeout, default 2000
  --resync-interval-s   Distributed resync interval, default 30

cluster join flags:
  --token               JWT invite token
  --socket              Local joining-node Unix admin socket, default from GO53_ADMIN_SOCKET or /run/go53/admin.sock
  --api                 TCP API base URL; overrides --socket
  --sync-endpoint       Advertised sync endpoint for this joining node, default from token or local discovery
  --auto-accept         Ask issuer to approve immediately instead of storing a pending request
  --no-register         Do not self-register with the issuer sync endpoint after local join
  --dry-run             Print generated local config patch and accept request without applying it

cluster pending/approve flags:
  --socket              Local issuer Unix admin socket, default from GO53_ADMIN_SOCKET or /run/go53/admin.sock
  --api                 TCP API base URL; overrides --socket

cluster accept flags:
  --token               JWT invite token
  --socket              Local existing-node Unix admin socket, default from GO53_ADMIN_SOCKET or /run/go53/admin.sock
  --api                 TCP API base URL; overrides --socket
  --join-node-id        Joining node_id printed by cluster join
  --join-sync-endpoint  Joining node sync endpoint printed by cluster join
  --join-public-key     Joining node public_key printed by cluster join
  --dry-run             Print generated local config patch without applying it`)
}

func handleClusterInvite(args []string) {
	opts := parseClusterInviteOptions(args)
	opts.APIEndpoint = configureClusterAdmin(opts.Socket, opts.APIEndpoint)
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
	fs.StringVar(&opts.Socket, "socket", defaultAdminSocket(), "Local issuer Unix admin socket")
	fs.StringVar(&opts.APIEndpoint, "api", "", "TCP API base URL; overrides --socket")
	fs.StringVar(&opts.IssuerNode, "issuer-node", "", "Existing node_id that signs the invite")
	fs.StringVar(&opts.IssuerPrivateKey, "issuer-private-key", "", "Base64 Ed25519 private key for issuer node")
	fs.StringVar(&opts.ClusterID, "cluster-id", "", "Stable cluster identifier")
	fs.StringVar(&opts.JoinNodeID, "join-node-id", "", "Node ID for the new node")
	fs.StringVar(&opts.JoinSyncEndpoint, "join-sync-endpoint", "", "Distributed sync endpoint for the new node")
	fs.StringVar(&opts.TTL, "ttl", "10m", "Invite lifetime")
	fs.IntVar(&opts.UsageCount, "usage-count", 1, "Number of allowed uses to record for this invite")
	fs.StringVar(&opts.Transport, "transport", "tls", "Distributed transport")
	fs.StringVar(&opts.SyncBindHost, "sync-bind-host", "0.0.0.0", "Local bind host to configure on joining node")
	fs.StringVar(&opts.SyncPort, "sync-port", "", "Local sync port to configure on joining node; defaults from join sync endpoint")
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
		opts.Nodes = append(opts.Nodes, defaultInviteNodes(opts.APIEndpoint)...)
	}
	if opts.SyncPort == "" {
		opts.SyncPort = syncPortFromEndpoint(opts.JoinSyncEndpoint)
	}
}

func defaultInviteNodes(apiEndpoint string) []string {
	return []string{strings.TrimRight(apiEndpoint, "/")}
}

func (opts clusterInviteOptions) validate() error {
	if opts.UsageCount <= 0 {
		return errors.New("--usage-count must be greater than zero")
	}
	if opts.IssuerNode == "" || opts.IssuerPrivateKey == "" || opts.ClusterID == "" {
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
		JoinAPIEndpoint:  "",
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
		return fmt.Errorf("issuer-node %q must be included in local discovery", claims.Issuer)
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
	opts.APIEndpoint = configureClusterAdmin(opts.Socket, opts.APIEndpoint)
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
	if !opts.NoRegister {
		applied, err := registerJoinWithIssuer(plan)
		if err != nil {
			log.Fatal(err)
		}
		plan.Submitted = true
		plan.Registered = applied
	}
	printJoinOutput(plan)
}

func parseClusterJoinOptions(args []string) clusterJoinOptions {
	fs := flag.NewFlagSet("cluster join", flag.ExitOnError)
	opts := clusterJoinOptions{}
	fs.StringVar(&opts.Token, "token", "", "JWT invite token")
	fs.StringVar(&opts.Socket, "socket", defaultAdminSocket(), "Local joining-node Unix admin socket")
	fs.StringVar(&opts.APIEndpoint, "api", "", "TCP API base URL; overrides --socket")
	fs.StringVar(&opts.SyncEndpoint, "sync-endpoint", "", "Advertised sync endpoint for this joining node")
	fs.BoolVar(&opts.AutoAccept, "auto-accept", false, "Ask issuer to approve immediately instead of storing a pending request")
	fs.BoolVar(&opts.NoRegister, "no-register", false, "Do not self-register with issuer sync endpoint")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "Print local config patch and accept request without applying them")
	_ = fs.Parse(args)
	if opts.Token == "" {
		fs.Usage()
		os.Exit(1)
	}
	return opts
}

func (opts *clusterJoinOptions) applyDefaults(claims clusterInviteClaims) {
	if opts.APIEndpoint == "" {
		opts.APIEndpoint = "http://go53-admin-socket"
	}
}

func buildJoinPlan(opts clusterJoinOptions, claims clusterInviteClaims) (joinPlan, error) {
	localConfig, _ := fetchLiveConfig(opts.APIEndpoint)
	localInfo, _ := fetchNodeDiscovery(opts.APIEndpoint)
	claims = completeJoinClaims(claims, opts.APIEndpoint, opts.SyncEndpoint, localConfig, localInfo)
	if strings.TrimSpace(claims.JoinSyncEndpoint) == "" {
		return joinPlan{}, errors.New("missing joining node sync endpoint; pass --sync-endpoint tls://HOST:PORT")
	}
	privateKey, publicKey, err := joinKeyPair(localConfig)
	if err != nil {
		return joinPlan{}, err
	}
	return joinPlan{
		Claims:     claims,
		LocalPatch: joinLocalConfig(claims, privateKey),
		Accept:     joinAcceptRequest(opts.Token, claims, publicKey),
		PublicKey:  publicKey,
		PrivateKey: privateKey,
		AutoAccept: opts.AutoAccept,
	}, nil
}

func printJoinPlan(plan joinPlan) {
	printJSON("local config patch", plan.LocalPatch)
	printJSON("local accept request for existing nodes", plan.Accept)
}

func applyJoinPlan(apiEndpoint string, plan joinPlan) error {
	if err := patchConfig(apiEndpoint, plan.LocalPatch); err != nil {
		return fmt.Errorf("patch local node %s: %w", apiEndpoint, err)
	}
	return nil
}

func printJoinOutput(plan joinPlan) {
	fmt.Printf("joined cluster %s as %s\n", plan.Claims.ClusterID, plan.Claims.JoinNodeID)
	fmt.Printf("local public_key: %s\n", plan.PublicKey)
	if !plan.Submitted {
		fmt.Println("self-registration skipped")
	} else if plan.AutoAccept && plan.Registered {
		fmt.Println("self-registration accepted by issuer")
	} else {
		fmt.Println("self-registration stored as pending on issuer")
		fmt.Printf("run on issuer: go53ctl cluster approve %s\n", plan.Claims.JoinNodeID)
	}
	fmt.Println("manual fallback command for existing nodes:")
	fmt.Printf("go53ctl cluster accept --token %s --join-node-id %s --join-sync-endpoint %s --join-public-key %s\n",
		plan.Accept.Token,
		plan.Accept.JoinNodeID,
		plan.Accept.JoinSyncEndpoint,
		plan.Accept.JoinPublicKey,
	)
}

func registerJoinWithIssuer(plan joinPlan) (bool, error) {
	issuer, ok := plan.Claims.Nodes[plan.Claims.Issuer]
	if !ok || strings.TrimSpace(issuer.SyncEndpoint) == "" {
		return false, errors.New("invite does not include issuer sync endpoint; rerun with --no-register and accept manually")
	}
	req, err := signedJoinRequest(plan)
	if err != nil {
		return false, err
	}
	resp, err := roundTripSyncFrame(issuer.SyncEndpoint, issuer.PublicKey, syncFrame{Type: "JOIN_REQUEST", JoinRequest: &req, AutoAccept: plan.AutoAccept})
	if err != nil {
		return false, fmt.Errorf("self-register with issuer %s: %w", issuer.SyncEndpoint, err)
	}
	if resp.Type == "ERROR" {
		return false, fmt.Errorf("self-register with issuer %s: %s", issuer.SyncEndpoint, resp.Error)
	}
	if resp.Type != "ACK" {
		return false, fmt.Errorf("self-register with issuer %s: unexpected response %q", issuer.SyncEndpoint, resp.Type)
	}
	return resp.Applied, nil
}

func signedJoinRequest(plan joinPlan) (distributed.JoinRequest, error) {
	req := distributed.JoinRequest{
		Token:            plan.Accept.Token,
		TokenID:          plan.Claims.TokenID,
		JoinNodeID:       plan.Accept.JoinNodeID,
		JoinSyncEndpoint: plan.Accept.JoinSyncEndpoint,
		JoinPublicKey:    plan.Accept.JoinPublicKey,
	}
	priv, err := decodeEd25519PrivateKey(plan.PrivateKey)
	if err != nil {
		return distributed.JoinRequest{}, err
	}
	req.Proof = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, distributed.JoinRequestPayload(req)))
	return req, nil
}

func handleClusterAccept(args []string) {
	opts := parseClusterAcceptOptions(args)
	opts.APIEndpoint = configureClusterAdmin(opts.Socket, opts.APIEndpoint)
	claims, err := verifyInviteJWT(opts.Token)
	if err != nil {
		log.Fatal(err)
	}
	if err := validateAcceptOptions(claims, opts); err != nil {
		log.Fatal(err)
	}
	localConfig, err := fetchLiveConfig(opts.APIEndpoint)
	if err != nil {
		log.Fatal(err)
	}
	localInfo, _ := fetchNodeDiscovery(opts.APIEndpoint)
	patch := acceptLocalConfig(localConfig, opts.JoinNodeID, opts.JoinSyncEndpoint, opts.JoinPublicKey)
	if opts.DryRun {
		printJSON("local config patch", patch)
		return
	}
	if localNodeID(localConfig, localInfo) == claims.Issuer {
		if err := consumeDistributedInvite(opts.APIEndpoint, claims.TokenID); err != nil {
			log.Fatalf("consume invite: %v", err)
		}
	}
	if err := patchConfig(opts.APIEndpoint, patch); err != nil {
		log.Fatalf("patch local node %s: %v", opts.APIEndpoint, err)
	}
	fmt.Printf("accepted node %s at %s\n", opts.JoinNodeID, opts.JoinSyncEndpoint)
}

func handleClusterPending(args []string) {
	fs, opts := newAdminFlagSet("cluster pending", false)
	_ = fs.Parse(args)
	mustAdminRequest(*opts, http.MethodGet, "/api/distributed/join-requests", "", "")
}

func handleClusterApprove(args []string) {
	fs, opts := newAdminFlagSet("cluster approve", false)
	_ = fs.Parse(args)
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Println("Usage: go53ctl cluster approve NODE [--socket PATH|--api URL]")
		os.Exit(1)
	}
	mustAdminRequest(*opts, http.MethodPost, "/api/distributed/join-requests/"+rest[0]+"/approve", "", "")
}

func parseClusterAcceptOptions(args []string) clusterAcceptOptions {
	fs := flag.NewFlagSet("cluster accept", flag.ExitOnError)
	opts := clusterAcceptOptions{}
	fs.StringVar(&opts.Token, "token", "", "JWT invite token")
	fs.StringVar(&opts.Socket, "socket", defaultAdminSocket(), "Local existing-node Unix admin socket")
	fs.StringVar(&opts.APIEndpoint, "api", "", "TCP API base URL; overrides --socket")
	fs.StringVar(&opts.JoinNodeID, "join-node-id", "", "Joining node ID")
	fs.StringVar(&opts.JoinSyncEndpoint, "join-sync-endpoint", "", "Joining node sync endpoint")
	fs.StringVar(&opts.JoinPublicKey, "join-public-key", "", "Joining node public key")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "Print config without applying it")
	_ = fs.Parse(args)
	if opts.Token == "" || opts.JoinNodeID == "" || opts.JoinSyncEndpoint == "" || opts.JoinPublicKey == "" {
		fs.Usage()
		os.Exit(1)
	}
	return opts
}

func validateAcceptOptions(claims clusterInviteClaims, opts clusterAcceptOptions) error {
	if claims.JoinNodeID != "" && claims.JoinNodeID != opts.JoinNodeID {
		return fmt.Errorf("join-node-id %q does not match invite join_node_id %q", opts.JoinNodeID, claims.JoinNodeID)
	}
	if claims.JoinSyncEndpoint != "" && claims.JoinSyncEndpoint != opts.JoinSyncEndpoint {
		return fmt.Errorf("join-sync-endpoint %q does not match invite join_sync_endpoint %q", opts.JoinSyncEndpoint, claims.JoinSyncEndpoint)
	}
	if _, err := decodeEd25519PublicKey(opts.JoinPublicKey); err != nil {
		return fmt.Errorf("invalid join-public-key: %w", err)
	}
	return nil
}

func joinAcceptRequest(token string, claims clusterInviteClaims, publicKey string) clusterAcceptRequest {
	return clusterAcceptRequest{
		Token:            token,
		JoinNodeID:       claims.JoinNodeID,
		JoinSyncEndpoint: claims.JoinSyncEndpoint,
		JoinPublicKey:    publicKey,
	}
}

func acceptLocalConfig(localConfig map[string]any, joinNodeID, joinSyncEndpoint, joinPublicKey string) map[string]any {
	peers := splitCSV(stringFromPath(localConfig, "distributed", "peers"))
	peers = appendUnique(peers, joinSyncEndpoint)
	sortStrings(peers)
	peerKeys := stringMapFromPath(localConfig, "distributed", "peer_public_keys")
	peerKeys[joinNodeID] = joinPublicKey
	return map[string]any{
		"distributed": map[string]any{
			"peers":            strings.Join(peers, ","),
			"peer_public_keys": peerKeys,
		},
	}
}

func localNodeID(localConfig map[string]any, localInfo nodeDiscovery) string {
	return firstNonEmpty(strings.TrimSpace(localInfo.NodeID), stringFromPath(localConfig, "distributed", "node_id"))
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

func completeJoinClaims(claims clusterInviteClaims, _ string, syncEndpoint string, localConfig map[string]any, localInfo nodeDiscovery) clusterInviteClaims {
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
	claims.JoinSyncEndpoint = firstNonEmpty(
		claims.JoinSyncEndpoint,
		strings.TrimSpace(syncEndpoint),
		strings.TrimSpace(localInfo.SyncEndpoint),
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

func splitCSV(value string) []string {
	out := []string{}
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func appendUnique(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
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

func patchConfig(apiEndpoint string, patch map[string]any) error {
	return requestJSON(http.MethodPatch, strings.TrimRight(apiEndpoint, "/")+"/api/config", patch)
}

func saveDistributedInviteAPI(apiEndpoint string, record distributedInviteRecord) error {
	return requestJSON(http.MethodPost, strings.TrimRight(apiEndpoint, "/")+"/api/distributed/invites", record)
}

func consumeDistributedInvite(apiEndpoint, tokenID string) error {
	return requestNoBody(http.MethodPost, strings.TrimRight(apiEndpoint, "/")+"/api/distributed/invites/"+tokenID+"/consume")
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

func roundTripSyncFrame(endpoint, expectedPublicKey string, req syncFrame) (syncFrame, error) {
	timeout := 2 * time.Second
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", syncPeerAddr(endpoint))
	if err != nil {
		return syncFrame{}, err
	}
	defer conn.Close()
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(endpoint)), "tls://") || strings.HasPrefix(strings.ToLower(strings.TrimSpace(endpoint)), "mtls://") {
		cfg := &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
			VerifyConnection: func(state tls.ConnectionState) error {
				return verifySyncPeerTLSKey(state, expectedPublicKey)
			},
		}
		tlsConn := tls.Client(conn, cfg)
		if err := tlsConn.Handshake(); err != nil {
			return syncFrame{}, err
		}
		conn = tlsConn
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := writeSyncFrame(conn, req); err != nil {
		return syncFrame{}, err
	}
	return readSyncFrame(conn)
}

func verifySyncPeerTLSKey(state tls.ConnectionState, expectedPublicKey string) error {
	if strings.TrimSpace(expectedPublicKey) == "" {
		return errors.New("invite does not include issuer public key")
	}
	if len(state.PeerCertificates) == 0 {
		return errors.New("missing issuer TLS certificate")
	}
	expected, err := decodeEd25519PublicKey(expectedPublicKey)
	if err != nil {
		return err
	}
	actual, ok := state.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return errors.New("issuer TLS certificate must use Ed25519")
	}
	if !actual.Equal(expected) {
		return errors.New("issuer TLS certificate does not match invite public key")
	}
	return nil
}

func syncPeerAddr(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)
	endpoint = strings.TrimPrefix(endpoint, "tcp://")
	endpoint = strings.TrimPrefix(endpoint, "tls://")
	endpoint = strings.TrimPrefix(endpoint, "mtls://")
	return endpoint
}

func writeSyncFrame(w io.Writer, f syncFrame) error {
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func readSyncFrame(r io.Reader) (syncFrame, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return syncFrame{}, err
	}
	size := binary.BigEndian.Uint32(hdr[:])
	if size == 0 || size > 16<<20 {
		return syncFrame{}, fmt.Errorf("invalid frame size %d", size)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return syncFrame{}, err
	}
	var out syncFrame
	if err := json.Unmarshal(data, &out); err != nil {
		return syncFrame{}, err
	}
	return out, nil
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
		return ""
	}
	port := endpoint[idx+1:]
	if _, err := strconv.Atoi(port); err != nil {
		return ""
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
