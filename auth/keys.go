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
// Created on 6/4/25::12:20PM by joyider <andre(-at-)sess.se>
//
// This file: keys.go is part of the go53 authoritative DNS server.
package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"go53/storage"
)

type PasetoKey struct {
	KeyID      string    `json:"keyid"`
	Purpose    string    `json:"purpose"` // e.g., "public" or "local"
	Version    string    `json:"version"` // e.g., "v2", "v4"
	Type       string    `json:"type"`    // "public", "private", or "symmetric"
	PublicKey  []byte    `json:"key"`
	PrivateKey []byte    `json:"key"` // private or symmetric key
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	Revoked    bool      `json:"revoked"`
}

func GenerateAndStoreEd25519(store storage.Storage, keyid string, expiresIn time.Duration) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ed25519 keypair: %w", err)
	}

	key := PasetoKey{
		KeyID:      keyid,
		Purpose:    "public",
		Version:    "v4",
		Type:       "private",
		PublicKey:  pub,
		PrivateKey: priv,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(expiresIn),
		Revoked:    false,
	}

	data, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("failed to marshal key entry: %w", err)
	}

	return store.SaveTable("paseto_keys", keyid, data)

}
