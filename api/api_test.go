package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go53/api"
	"go53/config"
	"go53/distributed"
	"go53/memory"
	"go53/security"
	"go53/storage"
	"go53/zone/rtypes"
)

// setupAPITest initialises in-memory storage, config, and zone store — the same
// minimal plumbing the handler unit tests use, but here we set up the full router so
// we can test it end-to-end through the HTTP layer.
func setupAPITest(t *testing.T) {
	t.Helper()
	backend := &storage.MockStorage{}
	if err := backend.Init(); err != nil {
		t.Fatalf("init mock storage: %v", err)
	}
	storage.Backend = backend
	config.AppConfig = &config.ConfigManager{}
	config.AppConfig.Live = config.DefaultLiveConfig
	config.AppConfig.Live.Mode = "primary"
	config.AppConfig.Live.DNSSECEnabled = false
	distributed.Default = nil

	mem, err := memory.NewZoneStore(backend)
	if err != nil {
		t.Fatalf("new memory store: %v", err)
	}
	rtypes.InitMemoryStore(mem)
	if err := security.LoadTSIGKeysFromStorage(); err != nil {
		t.Fatalf("load TSIG keys: %v", err)
	}
	t.Cleanup(func() { distributed.Default = nil })
}

func testBaseConfig() config.BaseConfig {
	return config.BaseConfig{
		BindHost: "127.0.0.1",
		APIPort:  ":0",
	}
}

// newTCPServer spins up an httptest.Server backed by NewRouter. This simulates the
// TCP API path through NewRouter directly. AuthMiddleware is applied by Start(), not
// NewRouter(), so these tests exercise the bare router used by the local admin socket.
func newTCPServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(api.NewRouter(testBaseConfig()))
	t.Cleanup(srv.Close)
	return srv
}

// newSocketServer starts the admin socket on a temp path and returns an *http.Client
// that dials it. Mirrors what go53ctl does with --socket.
func newSocketServer(t *testing.T) *http.Client {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "admin.sock")
	cfg := testBaseConfig()
	cfg.AdminSocket = sockPath
	cfg.AdminSocketGroup = "" // skip group chown in tests

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix %s: %v", sockPath, err)
	}
	if err := os.Chmod(sockPath, 0o600); err != nil {
		t.Fatalf("chmod socket: %v", err)
	}

	// Wrap the router with the same localAdminTag used in StartAdminSocket so the
	// IsLocalAdmin context value is set, then serve on the listener.
	handler := api.NewRouter(cfg)
	handler = api.WrapLocalAdminTag(handler)
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sockPath)
			},
		},
	}
}

// get is a concise helper for GET requests. The url host is ignored when client
// dials a unix socket (any placeholder works).
func get(t *testing.T, client *http.Client, base, path string) (int, []byte) {
	t.Helper()
	resp, err := client.Get(base + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func patch(t *testing.T, client *http.Client, base, path, body string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPatch, base+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("PATCH %s: %v", path, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func post(t *testing.T, client *http.Client, base, path, body string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func del(t *testing.T, client *http.Client, base, path string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodDelete, base+path, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("DELETE %s: %v", path, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// --- TCP API tests -----------------------------------------------------------

func TestTCPAPI_GetConfig(t *testing.T) {
	setupAPITest(t)
	srv := newTCPServer(t)

	code, body := get(t, http.DefaultClient, srv.URL, "/api/config")
	if code != http.StatusOK {
		t.Fatalf("GET /api/config = %d, want 200; body: %s", code, body)
	}
	var cfg config.LiveConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	if cfg.Mode != "primary" {
		t.Fatalf("mode = %q, want primary", cfg.Mode)
	}
}

func TestTCPAPI_PatchConfig(t *testing.T) {
	setupAPITest(t)
	srv := newTCPServer(t)

	code := patch(t, http.DefaultClient, srv.URL, "/api/config", `{"default_ttl":9999}`)
	if code != http.StatusNoContent {
		t.Fatalf("PATCH /api/config = %d, want 204", code)
	}

	_, body := get(t, http.DefaultClient, srv.URL, "/api/config")
	var cfg config.LiveConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.DefaultTTL != 9999 {
		t.Fatalf("default_ttl = %d after PATCH, want 9999", cfg.DefaultTTL)
	}
}

func TestTCPAPI_PatchConfig_FalseBool(t *testing.T) {
	setupAPITest(t)
	srv := newTCPServer(t)

	// Ensure enable_edns starts true.
	if !config.AppConfig.GetLive().EnableEDNS {
		t.Fatal("precondition: enable_edns must be true")
	}
	code := patch(t, http.DefaultClient, srv.URL, "/api/config", `{"enable_edns":false}`)
	if code != http.StatusNoContent {
		t.Fatalf("PATCH enable_edns=false = %d, want 204", code)
	}
	if config.AppConfig.GetLive().EnableEDNS {
		t.Fatal("enable_edns still true after PATCH false")
	}
}

func TestTCPAPI_WellKnown_UninitializedDistributed(t *testing.T) {
	setupAPITest(t) // distributed.Default is nil after this
	srv := newTCPServer(t)

	// The route exists but returns 503 when distributed mode is not initialised.
	// This is the expected state in primary/secondary mode with no cluster config.
	code, _ := get(t, http.DefaultClient, srv.URL, "/.well-known/go53-node.json")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("/.well-known/go53-node.json without distributed = %d, want 503", code)
	}
}

func TestTCPAPI_ZoneRecordLifecycle(t *testing.T) {
	setupAPITest(t)
	srv := newTCPServer(t)

	const zone = "example.test."
	recordPath := fmt.Sprintf("/api/zones/%s/records/A", zone)
	// The handler stores the name from the POST body as-is (short label). The GET and
	// DELETE URL must use the FQDN which LookupRecord splits back into zone+label.
	getPath := fmt.Sprintf("/api/zones/%s/records/A/www.example.test.", zone)

	// Create a record using the short label form matching how handlers store it.
	code := post(t, http.DefaultClient, srv.URL, recordPath,
		`{"name":"www","ttl":300,"ip":"192.0.2.1"}`)
	if code != http.StatusCreated {
		t.Fatalf("POST record = %d, want 201", code)
	}

	// Read it back via FQDN in the URL. The handler encodes []dns.RR so the A
	// address is in field "A", not "ip".
	code, body := get(t, http.DefaultClient, srv.URL, getPath)
	if code != http.StatusOK {
		t.Fatalf("GET record = %d, want 200; body: %s", code, body)
	}
	if !strings.Contains(string(body), "192.0.2.1") {
		t.Fatalf("GET response does not contain expected IP; body: %s", body)
	}

	// Delete it.
	code = del(t, http.DefaultClient, srv.URL, getPath)
	if code != http.StatusNoContent {
		t.Fatalf("DELETE record = %d, want 204", code)
	}

	// Gone.
	code, _ = get(t, http.DefaultClient, srv.URL, getPath)
	if code != http.StatusNotFound {
		t.Fatalf("GET deleted record = %d, want 404", code)
	}
}

func TestTCPAPI_DisabledInSecondaryMode(t *testing.T) {
	setupAPITest(t)
	config.AppConfig.Live.Mode = "secondary"
	srv := newTCPServer(t)

	code := post(t, http.DefaultClient, srv.URL, "/api/zones/example.test./records/A",
		`{"name":"www.example.test.","ttl":300,"ip":"192.0.2.1"}`)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("POST record in secondary mode = %d, want 503", code)
	}
}

func TestTCPAPI_InvalidRRType(t *testing.T) {
	setupAPITest(t)
	srv := newTCPServer(t)

	code := post(t, http.DefaultClient, srv.URL, "/api/zones/example.test./records/BOGUS",
		`{"name":"www.example.test.","ttl":300,"ip":"192.0.2.1"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("POST bogus RR type = %d, want 400", code)
	}
}

func TestTCPAPI_TSIGLifecycle(t *testing.T) {
	setupAPITest(t)
	srv := newTCPServer(t)

	// Add a TSIG key.
	code := post(t, http.DefaultClient, srv.URL, "/api/tsig/transfer-key.",
		`{"algorithm":"hmac-sha256.","secret":"c2VjcmV0MTIzNA=="}`)
	if code != http.StatusCreated {
		t.Fatalf("POST TSIG = %d, want 201", code)
	}

	// List it.
	code, body := get(t, http.DefaultClient, srv.URL, "/api/tsig")
	if code != http.StatusOK {
		t.Fatalf("GET /api/tsig = %d", code)
	}
	if !strings.Contains(string(body), "transfer-key.") {
		t.Fatalf("TSIG list does not contain transfer-key.: %s", body)
	}

	// Delete it.
	code = del(t, http.DefaultClient, srv.URL, "/api/tsig/transfer-key.")
	if code != http.StatusNoContent {
		t.Fatalf("DELETE TSIG = %d, want 204", code)
	}
}

func TestRouterAllManagementRoutes(t *testing.T) {
	setupAPITest(t)
	initDistributedForRouterTest(t)
	router := api.NewRouter(testBaseConfig())

	expectRoute(t, router, http.MethodGet, "/openapi.yaml", "", http.StatusOK)
	expectRoute(t, router, http.MethodGet, "/swagger", "", http.StatusOK)
	expectRoute(t, router, http.MethodGet, "/swagger/", "", http.StatusOK)
	expectRoute(t, router, http.MethodGet, "/api/config", "", http.StatusOK)
	expectRoute(t, router, http.MethodPatch, "/api/config", `{"primary":{"notify_debounce_ms":60000},"allow_transfer":""}`, http.StatusNoContent)
	expectRoute(t, router, http.MethodGet, "/.well-known/go53-node.json", "", http.StatusOK)

	expectRoute(t, router, http.MethodGet, "/api/zones", "", http.StatusOK)
	expectRoute(t, router, http.MethodPost, "/api/zones/route.test./records/SOA", `{"ttl":300,"ns":"ns1.route.test.","mbox":"hostmaster.route.test.","refresh":3600,"retry":600,"expire":86400,"minimum":300}`, http.StatusCreated)
	expectRoute(t, router, http.MethodPost, "/api/zones/route.test./records/A", `{"name":"www","ttl":300,"ip":"192.0.2.10"}`, http.StatusCreated)
	expectRoute(t, router, http.MethodGet, "/api/zones/route.test./records", "", http.StatusOK)
	expectRoute(t, router, http.MethodGet, "/api/zones/route.test./records/A", "", http.StatusOK)
	expectRoute(t, router, http.MethodPatch, "/api/zones/route.test./records/A/www.route.test.", `{"ttl":300,"ip":"192.0.2.11"}`, http.StatusNoContent)
	expectRoute(t, router, http.MethodGet, "/api/zones/route.test./records/A/www.route.test.", "", http.StatusOK)
	expectRoute(t, router, http.MethodGet, "/api/zones/route.test./export", "", http.StatusOK)
	expectRoute(t, router, http.MethodPost, "/api/zones/imported.test./import", "imported.test. 300 IN SOA ns1.imported.test. hostmaster.imported.test. 1 3600 600 86400 300\nimported.test. 300 IN NS ns1.imported.test.\nns1.imported.test. 300 IN A 192.0.2.53\n", http.StatusCreated)
	expectRoute(t, router, http.MethodGet, "/api/catalog", "", http.StatusOK)
	expectRoute(t, router, http.MethodGet, "/api/catalog/members", "", http.StatusOK)
	expectRoute(t, router, http.MethodPost, "/api/notify/route.test.", "", http.StatusAccepted)

	expectRoute(t, router, http.MethodGet, "/api/tsig", "", http.StatusOK)
	expectRoute(t, router, http.MethodPost, "/api/tsig/route-key.", `{"algorithm":"hmac-sha256.","secret":"cm91dGU="}`, http.StatusCreated)
	expectRoute(t, router, http.MethodDelete, "/api/tsig/route-key.", "", http.StatusNoContent)

	expectRoute(t, router, http.MethodGet, "/api/dnskeys", "", http.StatusOK)
	keyID := createRolloverKeyViaRouter(t, router)
	expectRoute(t, router, http.MethodGet, "/api/dnskeys/route.test", "", http.StatusOK)
	expectRoute(t, router, http.MethodPatch, "/api/dnskeys/"+keyID+"/lifecycle", `{"state":"active"}`, http.StatusOK)
	expectRoute(t, router, http.MethodGet, "/api/ds/route.test.", "", http.StatusOK)
	expectRoute(t, router, http.MethodGet, "/api/cds/route.test.", "", http.StatusOK)
	expectRoute(t, router, http.MethodGet, "/api/cdnskey/route.test.", "", http.StatusOK)
	expectRoute(t, router, http.MethodPost, "/api/dnskeys/"+keyID+"/retire?remove_after_days=1", "", http.StatusOK)
	expectRoute(t, router, http.MethodPost, "/api/dnskeys/"+keyID+"/revoke?remove_after_days=1", "", http.StatusOK)
	expectRoute(t, router, http.MethodDelete, "/api/dnskeys/"+keyID, "", http.StatusNoContent)

	expectRoute(t, router, http.MethodGet, "/api/distributed/status", "", http.StatusOK)
	expectRoute(t, router, http.MethodPost, "/api/distributed/keypair", "", http.StatusOK)
	expectRoute(t, router, http.MethodGet, "/api/distributed/vector", "", http.StatusOK)
	expectRoute(t, router, http.MethodGet, "/api/distributed/events", "", http.StatusOK)
	expectRoute(t, router, http.MethodPost, "/api/distributed/events?resync=true", `{`, http.StatusBadRequest)
	expectRoute(t, router, http.MethodGet, "/api/distributed/merkle/roots", "", http.StatusOK)
	expectRoute(t, router, http.MethodGet, "/api/distributed/merkle/branches?zone=route.test.", "", http.StatusOK)
	expectRoute(t, router, http.MethodPost, "/api/distributed/merkle/leaves", `{"zone":"route.test.","prefixes":[]}`, http.StatusOK)
	expectRoute(t, router, http.MethodPost, "/api/distributed/merkle/repair-events", `{"entities":[]}`, http.StatusOK)
	expectRoute(t, router, http.MethodPost, "/api/distributed/invites", `{"jti":"route-invite","usage_count":1}`, http.StatusNoContent)
	expectRoute(t, router, http.MethodPost, "/api/distributed/invites/route-invite/consume", "", http.StatusOK)
	expectRoute(t, router, http.MethodGet, "/api/distributed/join-requests", "", http.StatusOK)
	expectRoute(t, router, http.MethodPost, "/api/distributed/join-requests/missing/approve", "", http.StatusConflict)

	expectRoute(t, router, http.MethodDelete, "/api/zones/imported.test.", "", http.StatusNoContent)

	config.AppConfig.Live.Mode = "secondary"
	expectRoute(t, router, http.MethodPost, "/api/secondary/fetch/route.test.", "", http.StatusAccepted)
}

func TestRouterPagination(t *testing.T) {
	setupAPITest(t)
	router := api.NewRouter(testBaseConfig())
	for _, zone := range []string{"alpha.test.", "beta.test.", "gamma.test."} {
		expectRoute(t, router, http.MethodPost, "/api/zones/"+zone+"/records/SOA", fmt.Sprintf(`{"ttl":300,"ns":"ns1.%s","mbox":"hostmaster.%s","refresh":3600,"retry":600,"expire":86400,"minimum":300}`, zone, zone), http.StatusCreated)
	}
	expectRoute(t, router, http.MethodPost, "/api/zones/beta.test./records/A", `{"name":"a","ttl":300,"ip":"192.0.2.1"}`, http.StatusCreated)
	expectRoute(t, router, http.MethodPost, "/api/zones/beta.test./records/A", `{"name":"b","ttl":300,"ip":"192.0.2.2"}`, http.StatusCreated)
	expectRoute(t, router, http.MethodPost, "/api/zones/beta.test./records/TXT", `{"name":"txt","ttl":300,"text":"hello"}`, http.StatusCreated)

	zonesRec := routeRequest(router, http.MethodGet, "/api/zones?limit=2&offset=1", "")
	var zonesPage struct {
		Items  []string `json:"items"`
		Limit  int      `json:"limit"`
		Offset int      `json:"offset"`
		Total  int      `json:"total"`
	}
	if err := json.NewDecoder(zonesRec.Body).Decode(&zonesPage); err != nil {
		t.Fatalf("decode zones page: %v", err)
	}
	if zonesPage.Limit != 2 || zonesPage.Offset != 1 || zonesPage.Total != 3 || len(zonesPage.Items) != 2 {
		t.Fatalf("zones pagination = %#v", zonesPage)
	}

	recordsRec := routeRequest(router, http.MethodGet, "/api/zones/beta.test./records?limit=2&offset=1", "")
	var recordsPage struct {
		Items  []map[string]any `json:"items"`
		Limit  int              `json:"limit"`
		Offset int              `json:"offset"`
		Total  int              `json:"total"`
	}
	if err := json.NewDecoder(recordsRec.Body).Decode(&recordsPage); err != nil {
		t.Fatalf("decode records page: %v", err)
	}
	if recordsPage.Limit != 2 || recordsPage.Offset != 1 || recordsPage.Total != 4 || len(recordsPage.Items) != 2 {
		t.Fatalf("records pagination = %#v", recordsPage)
	}

	typeRec := routeRequest(router, http.MethodGet, "/api/zones/beta.test./records/A?limit=1&offset=1", "")
	var typePage struct {
		Items  []map[string]any `json:"items"`
		Limit  int              `json:"limit"`
		Offset int              `json:"offset"`
		Total  int              `json:"total"`
	}
	if err := json.NewDecoder(typeRec.Body).Decode(&typePage); err != nil {
		t.Fatalf("decode type page: %v", err)
	}
	if typePage.Limit != 1 || typePage.Offset != 1 || typePage.Total != 2 || len(typePage.Items) != 1 {
		t.Fatalf("type pagination = %#v", typePage)
	}
}

func TestAuthMiddlewareNoneAllowsRequest(t *testing.T) {
	setupAPITest(t)
	config.AppConfig.Live.Auth.Mode = "none"

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	api.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("AuthMiddleware none status = %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestAuthMiddlewareXAuthKey(t *testing.T) {
	setupAPITest(t)
	key := strings.Repeat("a", 48)
	config.AppConfig.Live.Auth.Mode = "x-auth-key"
	config.AppConfig.Live.Auth.XAuthKey = key

	handler := api.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("X-Auth-Key", key)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("AuthMiddleware x-auth-key valid status = %d body=%q", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("X-Auth-Key", "wrong")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("AuthMiddleware x-auth-key wrong status = %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestAuthMiddlewareXAuthKeyRequiresConfiguredKey(t *testing.T) {
	setupAPITest(t)
	config.AppConfig.Live.Auth.Mode = "x-auth-key"
	config.AppConfig.Live.Auth.XAuthKey = strings.Repeat("a", 47)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	api.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be reached")
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("AuthMiddleware short x_auth_key status = %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestAuthMiddlewareFutureModesFailClosed(t *testing.T) {
	for _, mode := range []string{"oidc"} {
		t.Run(mode, func(t *testing.T) {
			setupAPITest(t)
			config.AppConfig.Live.Auth.Mode = mode

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/probe", nil)
			api.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fatal("handler should not be reached")
			})).ServeHTTP(rec, req)

			if rec.Code != http.StatusNotImplemented {
				t.Fatalf("AuthMiddleware %s status = %d body=%q", mode, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestAuthMiddlewareLocalAdminBypassesAuthMode(t *testing.T) {
	setupAPITest(t)
	config.AppConfig.Live.Auth.Mode = "oidc"

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	handler := api.WrapLocalAdminTag(api.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("local admin AuthMiddleware status = %d body=%q", rec.Code, rec.Body.String())
	}
}

func initDistributedForRouterTest(t *testing.T) {
	t.Helper()
	privateKey, publicKey, err := distributed.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	config.AppConfig.Live.Mode = "distributed"
	config.AppConfig.Live.Version = "test-version"
	config.AppConfig.Live.Distributed.NodeID = "node-a"
	config.AppConfig.Live.Distributed.PrivateKey = privateKey
	config.AppConfig.Live.Distributed.PeerPublicKeys = map[string]string{"node-a": publicKey}
	config.AppConfig.Live.Distributed.SyncBindHost = "127.0.0.1"
	config.AppConfig.Live.Distributed.SyncPort = ":53530"
	distributed.Init(rtypes.GetMemStore())
	t.Cleanup(func() { distributed.Default = nil })
}

func routeRequest(router http.Handler, method, path, body string) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func expectRoute(t *testing.T, router http.Handler, method, path, body string, want int) *httptest.ResponseRecorder {
	t.Helper()
	rec := routeRequest(router, method, path, body)
	if rec.Code != want {
		t.Fatalf("%s %s = %d, want %d; body=%q", method, path, rec.Code, want, rec.Body.String())
	}
	return rec
}

func createRolloverKeyViaRouter(t *testing.T, router http.Handler) string {
	t.Helper()
	rec := expectRoute(t, router, http.MethodPost, "/api/dnskeys/rollover", `{"zone":"route.test.","role":"ksk","algorithm":"ED25519"}`, http.StatusCreated)
	var created struct {
		KeyID string `json:"keyid"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&created); err != nil {
		t.Fatalf("decode rollover key: %v", err)
	}
	if created.KeyID == "" {
		t.Fatal("rollover keyid is empty")
	}
	return created.KeyID
}

// --- Admin socket tests -------------------------------------------------------

func TestSocketAPI_GetConfig(t *testing.T) {
	setupAPITest(t)
	config.AppConfig.Live.Auth.XAuthKey = strings.Repeat("b", 48)
	client := newSocketServer(t)
	base := "http://go53-local"

	code, body := get(t, client, base, "/api/config")
	if code != http.StatusOK {
		t.Fatalf("socket GET /api/config = %d; body: %s", code, body)
	}
	var cfg config.LiveConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.Mode != "primary" {
		t.Fatalf("mode = %q, want primary", cfg.Mode)
	}
	if cfg.Auth.XAuthKey != "" {
		t.Fatalf("GET /api/config exposed x_auth_key = %q", cfg.Auth.XAuthKey)
	}
}

func TestTCPAPI_XAuthKeyRouteRequiresLocalAdmin(t *testing.T) {
	setupAPITest(t)
	srv := newTCPServer(t)

	code, _ := get(t, http.DefaultClient, srv.URL, "/api/config/auth/x-auth-key")
	if code != http.StatusForbidden {
		t.Fatalf("TCP GET x-auth-key route = %d, want 403", code)
	}
}

func TestSocketAPI_XAuthKeyRoute(t *testing.T) {
	setupAPITest(t)
	client := newSocketServer(t)
	base := "http://go53-local"
	key := strings.Repeat("c", 48)

	code := patch(t, client, base, "/api/config/auth/x-auth-key", `{"x_auth_key":"`+key+`"}`)
	if code != http.StatusNoContent {
		t.Fatalf("socket PATCH x-auth-key = %d, want 204", code)
	}
	if config.AppConfig.GetLive().Auth.XAuthKey != key {
		t.Fatalf("stored x_auth_key = %q, want %q", config.AppConfig.GetLive().Auth.XAuthKey, key)
	}

	code, body := get(t, client, base, "/api/config/auth/x-auth-key")
	if code != http.StatusOK {
		t.Fatalf("socket GET x-auth-key = %d; body: %s", code, body)
	}
	if !strings.Contains(string(body), key) || !strings.Contains(string(body), `"configured":true`) {
		t.Fatalf("socket GET x-auth-key body = %s", body)
	}
}

func TestSocketAPI_PatchConfig(t *testing.T) {
	setupAPITest(t)
	client := newSocketServer(t)
	base := "http://go53-local"

	code := patch(t, client, base, "/api/config", `{"default_ttl":7777}`)
	if code != http.StatusNoContent {
		t.Fatalf("socket PATCH /api/config = %d, want 204", code)
	}
	if config.AppConfig.GetLive().DefaultTTL != 7777 {
		t.Fatalf("default_ttl = %d, want 7777", config.AppConfig.GetLive().DefaultTTL)
	}
}

func TestSocketAPI_ZoneRecordLifecycle(t *testing.T) {
	setupAPITest(t)
	client := newSocketServer(t)
	base := "http://go53-local"

	const zone = "socket.test."
	recordPath := fmt.Sprintf("/api/zones/%s/records/A", zone)
	getPath := fmt.Sprintf("/api/zones/%s/records/A/ns1.socket.test.", zone)

	code := post(t, client, base, recordPath,
		`{"name":"ns1","ttl":60,"ip":"10.0.0.1"}`)
	if code != http.StatusCreated {
		t.Fatalf("socket POST record = %d, want 201", code)
	}

	code, body := get(t, client, base, getPath)
	if code != http.StatusOK {
		t.Fatalf("socket GET record = %d; body: %s", code, body)
	}
	if !strings.Contains(string(body), "10.0.0.1") {
		t.Fatalf("socket GET response does not contain expected IP; body: %s", body)
	}
}

// TestSocketAPI_IsLocalAdminContextSet verifies that the IsLocalAdmin flag is
// propagated through the context for requests arriving over the admin socket.
// A dedicated handler is registered on a fresh mux so the test does not depend on
// any production handler knowing about the flag.
func TestSocketAPI_IsLocalAdminContextSet(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "ctx-test.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var capturedIsLocal bool
	mux := http.NewServeMux()
	mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		capturedIsLocal = api.IsLocalAdmin(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	handler := api.WrapLocalAdminTag(mux)
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sockPath)
			},
		},
	}
	resp, err := client.Get("http://go53-local/probe")
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	resp.Body.Close()

	if !capturedIsLocal {
		t.Fatal("IsLocalAdmin = false on socket request, want true")
	}
}

// TestTCPAPI_IsLocalAdminContextNotSet ensures a plain TCP request does NOT carry
// the local-admin context flag so auth middleware can trust the flag as a gating
// signal rather than something that can be forged over the network.
func TestTCPAPI_IsLocalAdminContextNotSet(t *testing.T) {
	var capturedIsLocal bool
	mux := http.NewServeMux()
	mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		capturedIsLocal = api.IsLocalAdmin(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	// Deliberately do NOT wrap with WrapLocalAdminTag.
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/probe")
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	resp.Body.Close()

	if capturedIsLocal {
		t.Fatal("IsLocalAdmin = true on TCP request, want false")
	}
}
