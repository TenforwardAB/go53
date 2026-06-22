package handlers

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go53/config"
	"go53/dns/dnsutils"
	"go53/memory"
	"go53/security"
	"go53/storage"
	"go53/wal"
	"go53/zone/rtypes"

	"github.com/miekg/dns"
)

type backupManifest struct {
	Format           string            `json:"format"`
	CreatedAt        int64             `json:"created_at"`
	Version          string            `json:"version"`
	SnapshotStartSeq uint64            `json:"snapshot_start_seq"`
	SnapshotEndSeq   uint64            `json:"snapshot_end_seq"`
	Zones            map[string]string `json:"zones"`
	Tables           map[string]string `json:"tables"`
}

func ExportBackupHandler(w http.ResponseWriter, r *http.Request) {
	if storage.Backend == nil {
		http.Error(w, "storage backend is not initialized", http.StatusInternalServerError)
		return
	}
	startSeq, err := wal.LastSeq()
	if err != nil {
		http.Error(w, "failed to read WAL sequence: "+err.Error(), http.StatusInternalServerError)
		return
	}

	zones, err := storage.Backend.LoadAllZones()
	if err != nil {
		http.Error(w, "failed to load zones: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tableNames := []string{"config", "tsig-keys", "dnssec_keys", wal.MetaTable}
	tables := make(map[string]map[string][]byte, len(tableNames))
	for _, name := range tableNames {
		table, err := storage.Backend.LoadTable(name)
		if err != nil {
			http.Error(w, "failed to load table "+name+": "+err.Error(), http.StatusInternalServerError)
			return
		}
		tables[name] = table
	}
	endSeq, err := wal.LastSeq()
	if err != nil {
		http.Error(w, "failed to read WAL sequence: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition", `attachment; filename="go53.backup.tar"`)
	tw := tar.NewWriter(w)
	defer tw.Close()

	manifest := backupManifest{
		Format:           "go53-backup-v1",
		CreatedAt:        time.Now().Unix(),
		Version:          config.AppConfig.GetLive().Version,
		SnapshotStartSeq: startSeq,
		SnapshotEndSeq:   endSeq,
		Zones:            map[string]string{},
		Tables:           map[string]string{},
	}
	for zoneName, data := range zones {
		path := "zones/" + pathToken(zoneName) + ".bin"
		manifest.Zones[zoneName] = path
		if err := writeTarFile(tw, path, data); err != nil {
			return
		}
	}
	for tableName, table := range tables {
		for key, data := range table {
			path := "tables/" + pathToken(tableName) + "/" + pathToken(key) + ".bin"
			manifest.Tables[tableName+"/"+key] = path
			if err := writeTarFile(tw, path, data); err != nil {
				return
			}
		}
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return
	}
	_ = writeTarFile(tw, "manifest.json", manifestData)
}

func ExportWALHandler(w http.ResponseWriter, r *http.Request) {
	after, err := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	if r.URL.Query().Get("after") == "" {
		after = 0
		err = nil
	}
	if err != nil {
		http.Error(w, "invalid after sequence", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="go53.wal"`)
	if err := wal.Export(after, w); err != nil {
		http.Error(w, "failed to export WAL: "+err.Error(), http.StatusInternalServerError)
	}
}

func GetWALStatusHandler(w http.ResponseWriter, r *http.Request) {
	seq, err := wal.LastSeq()
	if err != nil {
		http.Error(w, "failed to read WAL sequence: "+err.Error(), http.StatusInternalServerError)
		return
	}
	archived, err := wal.ArchivedSeq()
	if err != nil {
		http.Error(w, "failed to read archived WAL sequence: "+err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]uint64{"last_seq": seq, "archived_seq": archived})
}

// AckWALHandler advances the archived WAL watermark. An external archiver calls
// it after durably storing WAL up to `seq`, so retention will not prune events
// at or below `seq`. The watermark is monotonic, so retries and stale acks are
// safe.
func AckWALHandler(w http.ResponseWriter, r *http.Request) {
	seq, err := strconv.ParseUint(r.URL.Query().Get("seq"), 10, 64)
	if err != nil {
		http.Error(w, "invalid seq", http.StatusBadRequest)
		return
	}
	if err := wal.SetArchivedSeq(seq); err != nil {
		http.Error(w, "failed to set archived WAL sequence: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// quiesceSigning waits for any in-flight async DNSSEC signing goroutines to
// finish persisting before a restore replaces zone data, so a lingering
// persist() cannot clobber the restored state.
func quiesceSigning() {
	if store := rtypes.GetMemStore(); store != nil {
		store.WaitForSigning()
	}
}

// restoreBody caps the restore upload at the configured max_restore_bytes to
// bound memory (the whole backup/WAL is read into memory). 0 disables the cap.
func restoreBody(w http.ResponseWriter, r *http.Request) io.Reader {
	limit := config.AppConfig.GetLive().MaxRestoreBytes
	if limit <= 0 {
		return r.Body
	}
	return http.MaxBytesReader(w, r.Body, limit)
}

func RestoreBackupHandler(w http.ResponseWriter, r *http.Request) {
	quiesceSigning()
	files := map[string][]byte{}
	tr := tar.NewReader(restoreBody(w, r))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "invalid backup tar: "+err.Error(), http.StatusBadRequest)
			return
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			http.Error(w, "failed to read backup entry: "+err.Error(), http.StatusBadRequest)
			return
		}
		files[h.Name] = data
	}
	var manifest backupManifest
	if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
		http.Error(w, "invalid backup manifest: "+err.Error(), http.StatusBadRequest)
		return
	}
	if manifest.Format != "go53-backup-v1" {
		http.Error(w, "unsupported backup format", http.StatusBadRequest)
		return
	}
	if err := restoreZones(manifest, files); err != nil {
		http.Error(w, "failed to restore zones: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := restoreTables(manifest, files); err != nil {
		http.Error(w, "failed to restore tables: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := reloadRuntimeState(); err != nil {
		http.Error(w, "failed to reload runtime state: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func RestoreWALHandler(w http.ResponseWriter, r *http.Request) {
	quiesceSigning()
	events, err := wal.DecodeExport(restoreBody(w, r))
	if err != nil {
		http.Error(w, "invalid WAL: "+err.Error(), http.StatusBadRequest)
		return
	}
	for _, event := range events {
		if err := applyWALEvent(event); err != nil {
			http.Error(w, "failed to apply WAL event: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	// Drain signing spawned by the replayed events so persisted state is stable
	// before we rebuild the in-memory store from storage.
	quiesceSigning()
	if err := reloadRuntimeState(); err != nil {
		http.Error(w, "failed to reload runtime state: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeTarFile(tw *tar.Writer, name string, data []byte) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(data))}); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func pathToken(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

func restoreZones(manifest backupManifest, files map[string][]byte) error {
	current, err := storage.Backend.ListZones()
	if err != nil {
		return err
	}
	for _, zone := range current {
		if _, keep := manifest.Zones[zone]; !keep {
			if err := storage.Backend.DeleteZone(zone); err != nil {
				return err
			}
		}
	}
	for zone, path := range manifest.Zones {
		if err := storage.Backend.SaveZone(zone, files[path]); err != nil {
			return err
		}
	}
	return nil
}

func restoreTables(manifest backupManifest, files map[string][]byte) error {
	desired := map[string]map[string][]byte{}
	for tableKey, path := range manifest.Tables {
		table, key, ok := strings.Cut(tableKey, "/")
		if !ok {
			continue
		}
		if desired[table] == nil {
			desired[table] = map[string][]byte{}
		}
		desired[table][key] = files[path]
	}
	for _, table := range []string{"config", "tsig-keys", "dnssec_keys", wal.MetaTable} {
		current, err := storage.Backend.LoadTable(table)
		if err != nil {
			return err
		}
		for key := range current {
			if _, keep := desired[table][key]; !keep {
				if err := storage.Backend.DeleteFromTable(table, key); err != nil {
					return err
				}
			}
		}
		for key, data := range desired[table] {
			if err := storage.Backend.SaveTable(table, key, data); err != nil {
				return err
			}
		}
	}
	return nil
}

func applyWALEvent(event wal.Event) error {
	switch event.Kind {
	case wal.KindZoneRecord:
		store := rtypes.GetMemStore()
		if store == nil {
			return errors.New("memory store is not initialized")
		}
		switch event.Op {
		case wal.OpUpsert:
			var value any
			if len(event.Value) > 0 {
				if err := json.Unmarshal(event.Value, &value); err != nil {
					return err
				}
			}
			return store.PutRecordRaw(event.Zone, event.RRType, event.Name, value)
		case wal.OpDelete:
			return store.DeleteRecordRaw(event.Zone, event.RRType, event.Name)
		}
	case wal.KindZone:
		switch event.Op {
		case wal.OpDelete:
			store := rtypes.GetMemStore()
			if store != nil {
				return store.DeleteZone(event.Zone)
			}
		case wal.OpImport:
			parser := dns.NewZoneParser(bytes.NewReader(event.Value), event.Zone, "")
			var records []dns.RR
			for rr, ok := parser.Next(); ok; rr, ok = parser.Next() {
				records = append(records, rr)
			}
			if err := parser.Err(); err != nil {
				return err
			}
			return dnsutils.ImportRecords("", event.Zone, records)
		}
	case wal.KindConfig:
		if event.Op == wal.OpUpsert {
			return config.AppConfig.MergeUpdateLiveJSON(event.Value)
		}
	case wal.KindTSIGKey:
		switch event.Op {
		case wal.OpUpsert:
			if err := storage.Backend.SaveTable(event.Table, event.Key, event.Value); err != nil {
				return err
			}
			return security.LoadTSIGKeysFromStorage()
		case wal.OpDelete:
			if err := storage.Backend.DeleteFromTable(event.Table, event.Key); err != nil {
				return err
			}
			security.DeleteTSIGKey(event.Key)
			return nil
		}
	case wal.KindDNSSECKey:
		switch event.Op {
		case wal.OpUpsert:
			if err := storage.Backend.SaveTable(event.Table, event.Key, event.Value); err != nil {
				return err
			}
			return security.InitDNSSECKeyCache()
		case wal.OpDelete:
			if err := storage.Backend.DeleteFromTable(event.Table, event.Key); err != nil {
				return err
			}
			return security.InitDNSSECKeyCache()
		}
	}
	return nil
}

func reloadRuntimeState() error {
	store, err := memory.NewZoneStore(storage.Backend)
	if err != nil {
		return err
	}
	rtypes.InitMemoryStore(store)
	config.AppConfig.InitLiveConfig()
	if err := security.LoadTSIGKeysFromStorage(); err != nil {
		return err
	}
	// Reload the in-memory DNSSEC key cache so signing uses the restored keys
	// without requiring a process restart.
	return security.InitDNSSECKeyCache()
}
