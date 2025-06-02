package types

import (
	"go53/memory"
)

var memStore *memory.InMemoryZoneStore

func InitMemoryStore(store *memory.InMemoryZoneStore) {
	memStore = store
}
