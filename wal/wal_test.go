package wal

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"go53/storage"
)

func TestAppendAndExportBinaryWAL(t *testing.T) {
	backend := &storage.MockStorage{}
	if err := backend.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	storage.Backend = backend

	if seq, err := Append(KindZoneRecord, OpUpsert, "example.test.", "A", "www", "", "", []byte(`{"ip":"192.0.2.1"}`)); err != nil || seq != 1 {
		t.Fatalf("Append seq=%d err=%v, want seq 1 nil", seq, err)
	}
	if seq, err := Append(KindZoneRecord, OpDelete, "example.test.", "A", "old", "", "", nil); err != nil || seq != 2 {
		t.Fatalf("Append seq=%d err=%v, want seq 2 nil", seq, err)
	}

	var out bytes.Buffer
	if err := Export(1, &out); err != nil {
		t.Fatalf("Export: %v", err)
	}
	data := out.Bytes()
	if !bytes.HasPrefix(data, Magic) {
		t.Fatalf("export missing magic header: %q", data)
	}
	if len(data) <= len(Magic)+4 {
		t.Fatalf("export too short: %d", len(data))
	}
	recordLen := binary.BigEndian.Uint32(data[len(Magic) : len(Magic)+4])
	if int(recordLen) != len(data)-len(Magic)-4 {
		t.Fatalf("record len = %d, payload bytes = %d", recordLen, len(data)-len(Magic)-4)
	}

	events, err := EventsAfter(1)
	if err != nil {
		t.Fatalf("EventsAfter: %v", err)
	}
	if len(events) != 1 || events[0].Seq != 2 || events[0].Op != OpDelete {
		t.Fatalf("events = %#v, want seq 2 delete", events)
	}
}

func TestPruneOlderThan(t *testing.T) {
	backend := &storage.MockStorage{}
	if err := backend.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	storage.Backend = backend

	old := Event{Seq: 1, CreatedAt: time.Now().Add(-48 * time.Hour).Unix(), Kind: KindConfig, Op: OpUpsert}
	old.Checksum = checksum(old)
	oldData, err := encodeEvent(old)
	if err != nil {
		t.Fatalf("encode old: %v", err)
	}
	newer := Event{Seq: 2, CreatedAt: time.Now().Unix(), Kind: KindConfig, Op: OpUpsert}
	newer.Checksum = checksum(newer)
	newData, err := encodeEvent(newer)
	if err != nil {
		t.Fatalf("encode new: %v", err)
	}
	if err := backend.SaveTable(EventsTable, seqKey(old.Seq), oldData); err != nil {
		t.Fatalf("save old: %v", err)
	}
	if err := backend.SaveTable(EventsTable, seqKey(newer.Seq), newData); err != nil {
		t.Fatalf("save new: %v", err)
	}

	if err := PruneOlderThan(1); err != nil {
		t.Fatalf("PruneOlderThan: %v", err)
	}
	events, err := EventsAfter(0)
	if err != nil {
		t.Fatalf("EventsAfter: %v", err)
	}
	if len(events) != 1 || events[0].Seq != 2 {
		t.Fatalf("events after prune = %#v, want only seq 2", events)
	}
}
