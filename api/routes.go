package api

import (
	"github.com/gorilla/mux"
	"go53/config"
	"net/http"
)

func NewRouter(cfg config.Config) *mux.Router {
	r := mux.NewRouter()
	r.Use(AuthMiddleware)

	r.HandleFunc("/zones", GetZonesHandler).Methods("GET")
	r.HandleFunc("/api/add-a", addARecordHandler).Methods("POST")

	return r
}

func Start(cfg config.Config) error {
	r := NewRouter(cfg)
	return http.ListenAndServe(cfg.APIPort, r)
}
