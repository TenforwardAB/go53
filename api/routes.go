package api

import (
	"github.com/gorilla/mux"
	"go53/config"
	"net/http"
)

func NewRouter(cfg config.Config) *mux.Router {
	r := mux.NewRouter()
	//r.Use(AuthMiddleware)

	r.HandleFunc("/api/zones", GetZonesHandler).Methods("GET")
	r.HandleFunc("/api/zones/{zone}/records/{rrtype}", addRecordHandler).Methods("POST")
	r.HandleFunc("/api/zones/{zone}/records/{rrtype}/{name}", getRecordHandler).Methods("GET")
	r.HandleFunc("/api/zones/{zone}/records/{rrtype}/{name}", deleteRecordHandler).Methods("DELETE")

	return r
}

func Start(cfg config.Config) error {
	r := NewRouter(cfg)
	return http.ListenAndServe(cfg.APIPort, r)
}
