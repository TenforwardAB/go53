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
// Created on 6/4/25::10:44PM by joyider <andre(-at-)sess.se>
//
// This file: paseto.go is part of the go53 authoritative DNS server.
package auth

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"go53/storage"
	"log"
	"time"

	"github.com/o1egl/paseto"
)

type TokenPayload struct {
	Subject string    `json:"sub"`
	Roles   []string  `json:"roles"`
	Scopes  []string  `json:"scopes"`
	Exp     time.Time `json:"exp"`
}

func CreateToken(privateKey ed25519.PrivateKey, keyID string, payload TokenPayload) (string, error) {
	token := paseto.NewV2()
	footer := map[string]string{"kid": keyID}
	return token.Sign(privateKey, payload, footer)
}

func GetAllPublicKeys(store storage.Storage) map[string][]byte {
	result := make(map[string][]byte)

	data, err := store.LoadTable("paseto_keys")
	if err != nil {
		log.Printf("failed to load paseto_keys: %v", err)
		return result
	}

	for keyID, raw := range data {
		var key PasetoKey
		if err := json.Unmarshal(raw, &key); err != nil {
			log.Printf("invalid key entry for %s: %v", keyID, err)
			continue
		}

		if key.Revoked || len(key.PublicKey) == 0 {
			continue
		}

		result[key.KeyID] = key.PublicKey
	}

	return result
}

func VerifyToken(tokenStr string) (*TokenPayload, string, error) {
	var payload TokenPayload
	var footer map[string]string

	token := paseto.NewV2()
	for keyID, pubKey := range GetAllPublicKeys() {
		err := token.Verify(tokenStr, pubKey, &payload, &footer)
		if err == nil && footer["kid"] == keyID {
			if time.Now().After(payload.Exp) {
				return nil, "", errors.New("token expired")
			}
			return &payload, keyID, nil
		}
	}
	return nil, "", errors.New("invalid token or key")
}
