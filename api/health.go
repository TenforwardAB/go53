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
// This file: health.go is part of the go53 authoritative DNS server.
package api

import (
	"net/http"
	"sync/atomic"
)

// ready reports whether the server has finished startup and can serve traffic.
var ready atomic.Bool

// SetReady marks the server as ready (true) or not ready (false) for the
// /readyz probe.
func SetReady(v bool) { ready.Store(v) }

// withHealth answers liveness (/healthz) and readiness (/readyz) probes before
// the auth middleware runs
func withHealth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			switch r.URL.Path {
			case "/healthz":
				writeHealth(w, true)
				return
			case "/readyz":
				writeHealth(w, ready.Load())
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func writeHealth(w http.ResponseWriter, ok bool) {
	if !ok {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}
