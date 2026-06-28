package api_test

import (
	"archive/tar"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"go53/api"
	"go53/config"
	"go53/storage"
	"go53/wal"
)

func TestBackupWALRequiresLocalAdmin(t *testing.T) {
	backend := &storage.MockStorage{}
	if err := backend.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	storage.Backend = backend
	config.AppConfig = &config.ConfigManager{}
	config.AppConfig.SetLive(config.DefaultLiveConfig)

	if _, err := wal.Append(wal.KindConfig, wal.OpUpsert, "", "", "", "config", "live", []byte(`{"default_ttl":120}`)); err != nil {
		t.Fatalf("Append: %v", err)
	}

	router := api.NewRouter(config.DefaultBaseConfig)
	req := httptest.NewRequest(http.MethodGet, "/api/backup/wal", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("plain backup status = %d, want 403", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/backup/wal?after=0", nil)
	rec = httptest.NewRecorder()
	api.WrapLocalAdminTag(router).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("local backup status = %d body=%q, want 200", rec.Code, rec.Body.String())
	}
	if got := rec.Body.Bytes(); len(got) < len(wal.Magic) || string(got[:len(wal.Magic)]) != string(wal.Magic) {
		t.Fatalf("backup body missing WAL magic: %q", got)
	}
}

func TestBackupCreateRequiresLocalAdmin(t *testing.T) {
	backend := &storage.MockStorage{}
	if err := backend.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	backend.Zones["example.test."] = []byte("zone-data")
	storage.Backend = backend
	config.AppConfig = &config.ConfigManager{}
	config.AppConfig.SetLive(config.DefaultLiveConfig)

	router := api.NewRouter(config.DefaultBaseConfig)
	req := httptest.NewRequest(http.MethodGet, "/api/backup", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("plain backup status = %d, want 403", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/backup", nil)
	rec = httptest.NewRecorder()
	api.WrapLocalAdminTag(router).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("local backup status = %d body=%q, want 200", rec.Code, rec.Body.String())
	}
	tr := tar.NewReader(rec.Body)
	foundManifest := false
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar read: %v", err)
		}
		if h.Name == "manifest.json" {
			foundManifest = true
		}
	}
	if !foundManifest {
		t.Fatalf("backup tar missing manifest.json")
	}
}
