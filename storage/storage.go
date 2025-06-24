// Package storage
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
// Created on 6/8/25::11:21AM by joyider <andre(-at-)sess.se>
//
// This file: storage.go is part of the go53 authoritative DNS server.
package storage

import (
	"fmt"

	"go53/storage/badger"
)

// Storage defines an interface for a pluggable persistent storage backend,
// used for storing DNS zone data and generic key/value tables.
//
// All implementations must provide:
//   - Initialization and teardown (Init)
//   - Zone-level CRUD operations (SaveZone, LoadZone, DeleteZone, ListZones, LoadAllZones)
//   - Table-based key/value operations (LoadTable, SaveTable)
type Storage interface {
	// Init initializes the storage backend.
	Init() error

	// SaveZone persists a zone by name with its associated data.
	SaveZone(name string, data []byte) error

	// LoadZone retrieves raw zone data by name.
	LoadZone(name string) ([]byte, error)

	// DeleteZone removes the zone identified by name.
	DeleteZone(name string) error

	// ListZones returns a list of all stored zone names.
	ListZones() ([]string, error)

	// LoadAllZones returns all zones as a map of name to data.
	LoadAllZones() (map[string][]byte, error)

	// LoadTable loads a logical key/value table identified by prefix.
	LoadTable(table string) (map[string][]byte, error)

	// SaveTable saves a key/value pair into the given logical table.
	SaveTable(table string, key string, value []byte) error
}

// Backend is the globally available storage backend instance,
// assigned during application startup via Init().
var Backend Storage

// Init initializes the configured storage backend based on the backendType.
//
// Supported backend types:
//   - "badger": Uses BadgerDB for embedded local key-value storage.
//   - (others may be added in the future, e.g., "postgres").
//
// Parameters:
//   - backendType: A string identifier for the desired backend.
//
// Returns:
//   - error: If the backend type is unsupported or initialization fails.
func Init(backendType string) error {
	switch backendType {
	case "badger":
		Backend = badger.NewBadgerStorage()
	//case "postgres":
	//	Backend = postgres.NewPostgresStorage()
	default:
		return fmt.Errorf("unsupported backend type: %s", backendType)
	}
	return Backend.Init()
}
