// Package badger
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
// Created on 6/8/25::9:09AM by joyider <andre(-at-)sess.se>
//
// This file: badger.go is part of the go53 authoritative DNS server.
package badger

import (
	"bytes"
	"fmt"
	"github.com/dgraph-io/badger/v4"
	"os"
	"path/filepath"
)

// BadgerStorage provides a wrapper around BadgerDB for storing DNS zones
// and arbitrary key/value tables, used for persistent backend storage.
type BadgerStorage struct {
	db *badger.DB
}

// NewBadgerStorage returns a new instance of BadgerStorage.
// The underlying database must be initialized via Init() before use.
func NewBadgerStorage() *BadgerStorage {
	return &BadgerStorage{}
}

// Init initializes the BadgerDB instance at the default path "/data/go53".
// It creates the directory if it doesn't exist and opens the database
// without logging output.
//
// Returns:
//   - error: If directory creation or database opening fails.
func (b *BadgerStorage) Init() error {
	dir := filepath.Join("/data", "go53")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	db, err := badger.Open(badger.DefaultOptions(dir).WithLogger(nil))
	if err != nil {
		return err
	}
	b.db = db
	return nil
}

// SaveZone stores a zone's raw data under its name as the key.
//
// Parameters:
//   - name: The zone name (used as key).
//   - data: The serialized zone data to store.
//
// Returns:
//   - error: If the operation fails.
func (b *BadgerStorage) SaveZone(name string, data []byte) error {
	return b.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(name), data)
	})
}

// LoadZone retrieves raw data for the given zone name.
//
// Parameters:
//   - name: The zone name to load.
//
// Returns:
//   - []byte: The raw zone data.
//   - error:  If the zone does not exist or retrieval fails.
func (b *BadgerStorage) LoadZone(name string) ([]byte, error) {
	var valCopy []byte
	err := b.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(name))
		if err != nil {
			return err
		}
		valCopy, err = item.ValueCopy(nil)
		return err
	})
	return valCopy, err
}

// LoadAllZones returns a map of all stored zones and their corresponding data.
//
// Returns:
//   - map[string][]byte: A map where the key is the zone name.
//   - error: If iteration or reading fails.
func (b *BadgerStorage) LoadAllZones() (map[string][]byte, error) {
	zones := make(map[string][]byte)
	err := b.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			val, err := item.ValueCopy(nil)
			if err != nil {
				return err
			}
			zones[string(item.Key())] = val
		}
		return nil
	})
	return zones, err
}

// DeleteZone deletes a stored zone by its name.
//
// Parameters:
//   - name: The name of the zone to delete.
//
// Returns:
//   - error: If deletion fails or the zone does not exist.
func (b *BadgerStorage) DeleteZone(name string) error {
	return b.db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(name))
	})
}

// ListZones returns a list of all zone names stored in the database.
//
// Returns:
//   - []string: A list of zone names (keys).
//   - error: If reading fails.
func (b *BadgerStorage) ListZones() ([]string, error) {
	var keys []string
	err := b.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			keys = append(keys, string(item.Key()))
		}
		return nil
	})
	return keys, err
}

// LoadTable loads all key/value entries stored under a given table prefix.
// Keys are stored as "table/key" and stripped of the prefix before returning.
//
// Parameters:
//   - table: The logical table name (prefix).
//
// Returns:
//   - map[string][]byte: A map of key to value.
//   - error: If iteration or reading fails.
func (b *BadgerStorage) LoadTable(table string) (map[string][]byte, error) {
	result := make(map[string][]byte)
	prefix := []byte(fmt.Sprintf("%s/", table))

	err := b.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			k := item.Key()

			key := bytes.TrimPrefix(k, prefix)

			err := item.Value(func(v []byte) error {
				valCopy := append([]byte(nil), v...)
				result[string(key)] = valCopy
				return nil
			})
			if err != nil {
				return err
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}
	return result, nil
}

// SaveTable stores a key/value pair under a given table prefix.
//
// The full key will be stored as "table/key" internally.
//
// Parameters:
//   - table: The logical table name (prefix).
//   - key:   The specific key within the table.
//   - value: The data to store.
//
// Returns:
//   - error: If the write operation fails.
func (b *BadgerStorage) SaveTable(table string, key string, value []byte) error {
	fullKey := fmt.Sprintf("%s/%s", table, key)

	err := b.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(fullKey), value)
	})

	return err
}
