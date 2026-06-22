// Package api
// This file is part of the go53 project.
//
// This file is licensed under the European Union Public License (EUPL) v1.2.
// You may only use this work in compliance with the License.
// You may obtain a copy of the License at:
//
//	https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed "as is",
// without any warranty or conditions of any kind.
//
// Copyleft (c) 2025 - Tenforward AB. All rights reserved.
//
// This file: health_test.go is part of the go53 authoritative DNS server.
package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// sentinel handler that records whether the wrapped handler was reached.
func TestWithHealth(t *testing.T) {
	fellThrough := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fellThrough = true
		w.WriteHeader(http.StatusTeapot)
	})
	h := withHealth(next)

	t.Run("healthz is always 200 and bypasses next", func(t *testing.T) {
		fellThrough = false
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("healthz = %d, want 200", rec.Code)
		}
		if fellThrough {
			t.Fatal("healthz should not reach the wrapped handler")
		}
	})

	t.Run("readyz reflects the ready flag", func(t *testing.T) {
		SetReady(false)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("readyz (not ready) = %d, want 503", rec.Code)
		}

		SetReady(true)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("readyz (ready) = %d, want 200", rec.Code)
		}
	})

	t.Run("other paths fall through unchanged", func(t *testing.T) {
		fellThrough = false
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/zones", nil))
		if !fellThrough {
			t.Fatal("non-health path should reach the wrapped handler")
		}
		if rec.Code != http.StatusTeapot {
			t.Fatalf("fall-through code = %d, want 418", rec.Code)
		}
	})

	t.Run("non-GET on health path falls through", func(t *testing.T) {
		fellThrough = false
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/healthz", nil))
		if !fellThrough {
			t.Fatal("POST /healthz should fall through, not be intercepted")
		}
	})
}
