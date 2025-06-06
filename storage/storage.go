package storage

import (
	"fmt"

	"go53/storage/badger"
)

type Storage interface {
	Init() error
	SaveZone(name string, data []byte) error
	LoadZone(name string) ([]byte, error)
	DeleteZone(name string) error
	ListZones() ([]string, error)
	LoadAllZones() (map[string][]byte, error)
	LoadTable(table string) (map[string][]byte, error)
	SaveTable(table string, key string, value []byte) error
}

var Backend Storage

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
