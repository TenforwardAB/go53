package zone

import (
	"go53/memory"
	"go53/storage"
)

var ZoneStore *memory.InMemoryZoneStore

func InitZoneStore() error {
	store, err := memory.NewZoneStore(storage.Backend)
	if err != nil {
		return err
	}
	ZoneStore = store
	return nil
}
