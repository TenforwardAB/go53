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
	"go53/api/handlers"
	"go53/config"
	"log"
	"net"
	"net/http"
	"strings"
)

// NewRouter builds the bare admin API router with no authentication. Auth must be
// applied at the TCP transport layer (see Start), NOT here: the local admin Unix
// socket reuses this same router and must stay unauthenticated so it can serve as the
// break-glass administration path when the external IdP is unreachable.
func NewRouter(cfg config.BaseConfig) http.Handler {
	r := mux.NewRouter()

	r.HandleFunc("/openapi.yaml", handlers.OpenAPIHandler).Methods("GET")
	r.HandleFunc("/swagger", handlers.SwaggerUIHandler).Methods("GET")
	r.HandleFunc("/swagger/", handlers.SwaggerUIHandler).Methods("GET")

	r.HandleFunc("/api/config", handlers.UpdateLiveConfigHandler).Methods("PATCH")
	r.HandleFunc("/api/config", handlers.GetLiveConfigHandler).Methods("GET")
	r.HandleFunc("/api/config/auth/x-auth-key", localAdminOnly(handlers.GetXAuthKeyHandler)).Methods("GET")
	r.HandleFunc("/api/config/auth/x-auth-key", localAdminOnly(handlers.SetXAuthKeyHandler)).Methods("PUT", "PATCH")
	r.HandleFunc("/api/backup", localAdminOnly(handlers.ExportBackupHandler)).Methods("GET")
	r.HandleFunc("/api/backup/wal", localAdminOnly(handlers.ExportWALHandler)).Methods("GET")
	r.HandleFunc("/api/backup/wal/status", localAdminOnly(handlers.GetWALStatusHandler)).Methods("GET")
	r.HandleFunc("/api/backup/wal/ack", localAdminOnly(handlers.AckWALHandler)).Methods("POST")
	r.HandleFunc("/api/restore", localAdminOnly(handlers.RestoreBackupHandler)).Methods("POST")
	r.HandleFunc("/api/restore/wal", localAdminOnly(handlers.RestoreWALHandler)).Methods("POST")
	r.HandleFunc("/.well-known/go53-node.json", handlers.GetWellKnownNodeHandler).Methods("GET")

	r.HandleFunc("/api/zones", handlers.GetZonesHandler).Methods("GET")

	r.HandleFunc("/api/zones/{zone}", disableSecondary(handlers.DeleteZoneHandler)).Methods("DELETE")
	r.HandleFunc("/api/zones/{zone}/records", handlers.ListZoneRecordsHandler).Methods("GET")
	r.HandleFunc("/api/zones/{zone}/records/{rrtype}", handlers.ListZoneRecordsByTypeHandler).Methods("GET")
	r.HandleFunc("/api/zones/{zone}/records/{rrtype}", disableSecondary(handlers.AddRecordHandler)).Methods("POST")
	r.HandleFunc("/api/zones/{zone}/records/{rrtype}/{name}", disableSecondary(handlers.UpdateRecordHandler)).Methods("PATCH")
	r.HandleFunc("/api/zones/{zone}/records/{rrtype}/{name}", disableSecondary(handlers.GetRecordHandler)).Methods("GET")
	r.HandleFunc("/api/zones/{zone}/records/{rrtype}/{name}", disableSecondary(handlers.DeleteRecordHandler)).Methods("DELETE")
	r.HandleFunc("/api/zones/{zone}/export", handlers.ExportZoneHandler).Methods("GET")
	r.HandleFunc("/api/zones/{zone}/import", disableSecondary(handlers.ImportZoneHandler)).Methods("POST")

	r.HandleFunc("/api/secondary/fetch/{zone}", handlers.TriggerSecondaryFetchHandler).Methods("POST")
	r.HandleFunc("/api/notify/{zone}", disableSecondary(handlers.TriggerNotifyHandler)).Methods("POST")
	r.HandleFunc("/api/catalog", handlers.GetCatalogStatusHandler).Methods("GET")
	r.HandleFunc("/api/catalog/members", handlers.GetCatalogMembersHandler).Methods("GET")

	r.HandleFunc("/api/tsig", handlers.ListTSIGKeysHandler).Methods("GET")
	r.HandleFunc("/api/tsig/{name}", handlers.AddTSIGKeyHandler).Methods("POST")
	r.HandleFunc("/api/tsig/{name}", handlers.DeleteTSIGKeyHandler).Methods("DELETE")

	r.HandleFunc("/api/dnskeys", disableSecondary(handlers.ListDNSKeysHandler)).Methods("GET")
	r.HandleFunc("/api/dnskeys/{keyid}", disableSecondary(handlers.GetDNSKeyHandler)).Methods("GET")
	r.HandleFunc("/api/dnskeys", disableSecondary(handlers.CreateDNSKeyHandler)).Methods("POST")
	r.HandleFunc("/api/dnskeys/import-private", disableSecondary(handlers.ImportPrivateDNSKeysHandler)).Methods("POST")
	r.HandleFunc("/api/dnskeys/rollover", disableSecondary(handlers.CreateRolloverDNSKeyHandler)).Methods("POST")
	r.HandleFunc("/api/dnskeys/{keyid}/lifecycle", disableSecondary(handlers.UpdateDNSKeyLifecycleHandler)).Methods("PATCH")
	r.HandleFunc("/api/dnskeys/{keyid}/retire", disableSecondary(handlers.RetireDNSKeyHandler)).Methods("POST")
	r.HandleFunc("/api/dnskeys/{keyid}/revoke", disableSecondary(handlers.RevokeDNSKeyHandler)).Methods("POST")
	r.HandleFunc("/api/dnskeys/{keyid}", disableSecondary(handlers.DeleteDNSKeyHandler)).Methods("DELETE")

	r.HandleFunc("/api/ds/{zone}", disableSecondary(handlers.GetDSHandler)).Methods("GET")
	r.HandleFunc("/api/cds/{zone}", disableSecondary(handlers.GetCDSHandler)).Methods("GET")
	r.HandleFunc("/api/cdnskey/{zone}", disableSecondary(handlers.GetCDNSKEYHandler)).Methods("GET")

	r.HandleFunc("/api/distributed/status", handlers.GetDistributedStatusHandler).Methods("GET")
	r.HandleFunc("/api/distributed/keypair", handlers.GenerateDistributedKeyPairHandler).Methods("POST")
	r.HandleFunc("/api/distributed/vector", handlers.GetDistributedVectorHandler).Methods("GET")
	r.HandleFunc("/api/distributed/events", handlers.GetDistributedEventsHandler).Methods("GET")
	r.HandleFunc("/api/distributed/events", handlers.PostDistributedEventHandler).Methods("POST")
	r.HandleFunc("/api/distributed/merkle/roots", handlers.GetDistributedMerkleRootsHandler).Methods("GET")
	r.HandleFunc("/api/distributed/merkle/branches", handlers.GetDistributedMerkleBranchesHandler).Methods("GET")
	r.HandleFunc("/api/distributed/merkle/leaves", handlers.PostDistributedMerkleLeavesHandler).Methods("POST")
	r.HandleFunc("/api/distributed/merkle/repair-events", handlers.PostDistributedMerkleRepairEventsHandler).Methods("POST")
	r.HandleFunc("/api/distributed/merkle/records", handlers.PostDistributedMerkleRecordsHandler).Methods("POST")
	r.HandleFunc("/api/distributed/dnssec-keys", handlers.PostDistributedDNSSECKeysHandler).Methods("POST")
	r.HandleFunc("/api/distributed/invites", handlers.PostDistributedInviteHandler).Methods("POST")
	r.HandleFunc("/api/distributed/invites/{jti}/consume", handlers.PostDistributedInviteConsumeHandler).Methods("POST")
	r.HandleFunc("/api/distributed/join-requests", handlers.GetDistributedJoinRequestsHandler).Methods("GET")
	r.HandleFunc("/api/distributed/join-requests/{node}/approve", handlers.PostDistributedJoinRequestApproveHandler).Methods("POST")

	return r
}

func Start(cfg config.BaseConfig) error {
	var handler http.Handler = AuthMiddleware(RestoreGuard(NewRouter(cfg)))

	addr := net.JoinHostPort(cfg.BindHost, strings.TrimPrefix(cfg.APIPort, ":"))
	log.Printf("Starting API server on %s", addr)

	return http.ListenAndServe(addr, handler)
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

func localAdminOnly(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !IsLocalAdmin(r.Context()) {
			http.Error(w, "local admin socket required", http.StatusForbidden)
			return
		}
		handler.ServeHTTP(w, r)
	}
}
