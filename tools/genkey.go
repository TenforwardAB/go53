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
// Created on 6/6/25::9:08 AM by joyider <andre(-at-)sess.se>
//
// This file: genkey.go is part of the go53 authoritative DNS server.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
)

func main() {
	pub, priv, _ := ed25519.GenerateKey(nil)
	fmt.Println("Privat nyckel:", hex.EncodeToString(priv))
	fmt.Println("Publik nyckel:", hex.EncodeToString(pub))
}
