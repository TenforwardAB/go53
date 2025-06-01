package api

import (
	"net/http"
	"go53/config"
)

func Start(cfg *config.Config) error {
	http.HandleFunc("/api/add-a", addARecordHandler)
	return http.ListenAndServe(cfg.APIPort, nil)
}
