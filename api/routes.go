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
	// If in secondary mode, return a handler that always denies access
	if config.AppConfig.GetLive().Mode == "secondary" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "API is disabled in secondary mode", http.StatusServiceUnavailable)
		})
	}

	r := mux.NewRouter()
	// r.Use(AuthMiddleware)

	r.HandleFunc("/api/zones", GetZonesHandler).Methods("GET")
	r.HandleFunc("/api/zones/{zone}/records/{rrtype}", addRecordHandler).Methods("POST")
	r.HandleFunc("/api/zones/{zone}/records/{rrtype}/{name}", getRecordHandler).Methods("GET")
	r.HandleFunc("/api/zones/{zone}/records/{rrtype}/{name}", deleteRecordHandler).Methods("DELETE")

	r.HandleFunc("/api/config", updateLiveConfigHandler).Methods("PATCH")
	r.HandleFunc("/api/config", getLiveConfigHandler).Methods("GET")

	return r
}

func Start(cfg config.BaseConfig) error {
	router := NewRouter(cfg)

	addr := net.JoinHostPort(cfg.BindHost, strings.TrimPrefix(cfg.APIPort, ":"))
	log.Printf("Starting API server on %s", addr)

	return http.ListenAndServe(addr, router)
}
