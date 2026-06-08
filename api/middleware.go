// Package api This file is part of the go53 project.
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
// Created on 6/4/25::8:17PM by joyider <andre(-at-)sess.se>
//
// This file: middleware.go is part of the go53 authoritative DNS server.
package api

import (
	"net/http"
	"strings"

	"go53/config"
)

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if IsLocalAdmin(r.Context()) {
			next.ServeHTTP(w, r)
			return
		}
		switch strings.ToLower(strings.TrimSpace(config.AppConfig.GetLive().Auth.Mode)) {
		case "", "none":
			next.ServeHTTP(w, r)
		case "x-auth-key", "oidc":
			http.Error(w, "authentication mode is not implemented", http.StatusNotImplemented)
		default:
			http.Error(w, "invalid authentication mode", http.StatusInternalServerError)
		}
	})
}
