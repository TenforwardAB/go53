package badger

import (
	"bytes"
	"fmt"
	"github.com/dgraph-io/badger/v4"
	"os"
	"path/filepath"
)

type BadgerStorage struct {
	db *badger.DB
}

func NewBadgerStorage() *BadgerStorage {
	return &BadgerStorage{}
}

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

func (b *BadgerStorage) SaveZone(name string, data []byte) error {
	return b.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(name), data)
	})
}

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

func (b *BadgerStorage) DeleteZone(name string) error {
	return b.db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(name))
	})
}

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

func (b *BadgerStorage) SaveTable(table string, key string, value []byte) error {
	fullKey := fmt.Sprintf("%s/%s", table, key)

	err := b.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(fullKey), value)
	})

	return err
}
