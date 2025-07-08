package handlers

import (
	"encoding/json"
	"fmt"
	"go53/internal"
	"go53/security"
	"go53/storage"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

type tsigKeyInput struct {
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"`
	Secret    string `json:"secret"`
}

func ListTSIGKeysHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("ListTSIGKeys called")
	keys := []map[string]string{}
	for name, key := range security.TSIGSecrets {
		keys = append(keys, map[string]string{
			"name":      name,
			"algorithm": key.Algorithm,
			"secret":    key.Secret,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(keys)
}

func AddTSIGKeyHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("AddTSIGKeyHandler called")
	vars := mux.Vars(r)
	nameParam := vars["name"]

	var input tsigKeyInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if nameParam == "" || input.Algorithm == "" || input.Secret == "" {
		http.Error(w, "missing required fields", http.StatusBadRequest)
		return
	}

	name, _ := internal.SanitizeFQDN(nameParam)
	value := []byte(fmt.Sprintf(`{"algorithm":"%s","secret":"%s"}`, input.Algorithm, input.Secret))

	const table = "tsig-keys"

	if err := storage.Backend.SaveTable(table, nameParam, value); err != nil {
		http.Error(w, "failed to save TSIG key", http.StatusInternalServerError)
		return
	}

	log.Printf("Saved TSIG key '%s', now reloading from backend...", nameParam)

	if err := security.LoadTSIGKeysFromStorage(); err != nil {
		http.Error(w, "failed to reload TSIG keys", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"name":      name,
		"algorithm": input.Algorithm,
		"secret":    input.Secret,
	})
}

func DeleteTSIGKeyHandler(w http.ResponseWriter, r *http.Request) {
	name, _ := internal.SanitizeFQDN(mux.Vars(r)["name"])

	if _, exists := security.TSIGSecrets[name]; !exists {
		http.Error(w, "TSIG key not found", http.StatusNotFound)
		return
	}

	delete(security.TSIGSecrets, name)
	w.WriteHeader(http.StatusNoContent)
}
