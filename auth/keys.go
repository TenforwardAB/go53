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
	"encoding/hex"
)

var publicKeys = map[string]ed25519.PublicKey{
	"key1": mustDecode("31b94195087db2dfc9213f5b99b7e88630633974fa87da5da51c9dc06c3a6abe"),
}

func GetAllPublicKeys() map[string]ed25519.PublicKey {
	return publicKeys
}

func mustDecode(hexStr string) ed25519.PublicKey {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(err)
	}
	return ed25519.PublicKey(bytes)
}
