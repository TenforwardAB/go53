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
// Created on 6/6/25::9:10 AM by joyider <andre(-at-)sess.se>
//
// This file: gen_token.go is part of the go53 authoritative DNS server.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"time"

	"go53/auth"
)

func main() {
	privHex := "99999e9945b364a64082232753fbdd1053c91681e6719d6a36b7416c99ee9d1e31b94195087db2dfc9213f5b99b7e88630633974fa87da5da51c9dc06c3a6abe"
	priv, _ := hex.DecodeString(privHex)

	payload := auth.TokenPayload{
		Subject: "admin@solutrix.se",
		Roles:   []string{"admin"},
		Scopes:  []string{"zone:read:*"},
		Exp:     time.Now().Add(10 * time.Minute),
	}
	token, err := auth.CreateToken(ed25519.PrivateKey(priv), "key1", payload)
	if err != nil {
		panic(err)
	}
	fmt.Println("Bearer " + token)
}
