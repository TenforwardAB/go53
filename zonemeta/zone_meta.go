package zonemeta

import (
	"encoding/json"
	"fmt"
	"go53/internal"
	"go53/storage"
	"strings"
	"time"
)

const tableName = "zone_meta"

type ZoneMeta struct {
	Zone            string `json:"zone"`
	DNSSECMode      string `json:"dnssec_mode,omitempty"`
	ReadOnly        bool   `json:"read_only,omitempty"`
	ReadOnlyReason  string `json:"read_only_reason,omitempty"`
	ImportedAtUnix  int64  `json:"imported_at_unix,omitempty"`
	ImportedRecords int    `json:"imported_records,omitempty"`
}

func SetPreserveReadOnly(zoneName string, recordCount int) error {
	zoneName, err := internal.SanitizeFQDN(zoneName)
	if err != nil {
		return err
	}
	return Save(ZoneMeta{
		Zone:            zoneName,
		DNSSECMode:      "preserve",
		ReadOnly:        true,
		ReadOnlyReason:  "dnssec-preserve-import",
		ImportedAtUnix:  time.Now().Unix(),
		ImportedRecords: recordCount,
	})
}

func Save(meta ZoneMeta) error {
	if storage.Backend == nil {
		return fmt.Errorf("storage backend is not initialized")
	}
	zoneName, err := internal.SanitizeFQDN(meta.Zone)
	if err != nil {
		return err
	}
	meta.Zone = zoneName
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return storage.Backend.SaveTable(tableName, strings.TrimSuffix(zoneName, "."), data)
}

func Load(zoneName string) (ZoneMeta, error) {
	if storage.Backend == nil {
		return ZoneMeta{}, fmt.Errorf("storage backend is not initialized")
	}
	zoneName, err := internal.SanitizeFQDN(zoneName)
	if err != nil {
		return ZoneMeta{}, err
	}
	table, err := storage.Backend.LoadTable(tableName)
	if err != nil {
		return ZoneMeta{}, err
	}
	raw, ok := table[strings.TrimSuffix(zoneName, ".")]
	if !ok {
		return ZoneMeta{Zone: zoneName}, nil
	}
	var meta ZoneMeta
	if err := json.Unmarshal(raw, &meta); err != nil {
		return ZoneMeta{}, err
	}
	if meta.Zone == "" {
		meta.Zone = zoneName
	}
	return meta, nil
}

func ReadOnly(zoneName string) (ZoneMeta, bool) {
	meta, err := Load(zoneName)
	if err != nil {
		return ZoneMeta{}, false
	}
	return meta, meta.ReadOnly
}
