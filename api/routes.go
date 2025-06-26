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
// Created on 5/12/25::2:02PM by joyider <andre(-at-)sess.se>
//
// This file: routes.go is part of the go53 authoritative DNS server.
package api

import (
	"github.com/gorilla/mux"
	"go53/config"
	"log"
	"net"
	"net/http"
	"strings"
)

func NewRouter(cfg config.BaseConfig) http.Handler {
	r := mux.NewRouter()
	// r.Use(AuthMiddleware)

	r.HandleFunc("/api/config", updateLiveConfigHandler).Methods("PATCH")
	r.HandleFunc("/api/config", getLiveConfigHandler).Methods("GET")

	r.HandleFunc("/api/zones", GetZonesHandler).Methods("GET")

	r.HandleFunc("/api/zones/{zone}/records/{rrtype}", disableSecondary(addRecordHandler)).Methods("POST")
	r.HandleFunc("/api/zones/{zone}/records/{rrtype}/{name}", disableSecondary(getRecordHandler)).Methods("GET")
	r.HandleFunc("/api/zones/{zone}/records/{rrtype}/{name}", disableSecondary(deleteRecordHandler)).Methods("DELETE")

	return r
}

func Start(cfg config.BaseConfig) error {
	router := NewRouter(cfg)

	addr := net.JoinHostPort(cfg.BindHost, strings.TrimPrefix(cfg.APIPort, ":"))
	log.Printf("Starting API server on %s", addr)

	return http.ListenAndServe(addr, router)
}

func disableSecondary(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if config.AppConfig.GetLive().Mode == "secondary" {
			http.Error(w, "Zone/record management is disabled in secondary mode", http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(w, r)
	}
}
