package api

import (
	"go53/config"
	"net/http"
)

func Start(cfg config.Config) error {
	http.HandleFunc("/api/add-a", addARecordHandler)
	return http.ListenAndServe(cfg.APIPort, nil)
}
