package wal

import (
	"testing"
	"time"

	"go53/storage"
)

// writeAgedEvent stores a WAL event directly with a chosen sequence and age so
// retention behaviour can be exercised deterministically.
func writeAgedEvent(t *testing.T, seq uint64, ageDays int) {
	t.Helper()
	e := Event{
		Seq:       seq,
		CreatedAt: time.Now().Add(-time.Duration(ageDays) * 24 * time.Hour).Unix(),
		Kind:      KindConfig,
		Op:        OpUpsert,
	}
	e.Checksum = checksum(e)
	data, err := encodeEvent(e)
	if err != nil {
		t.Fatalf("encodeEvent: %v", err)
	}
	if err := storage.Backend.SaveTable(EventsTable, seqKey(seq), data); err != nil {
		t.Fatalf("SaveTable: %v", err)
	}
}

func remainingSeqs(t *testing.T) map[uint64]bool {
	t.Helper()
	events, err := EventsAfter(0)
	if err != nil {
		t.Fatalf("EventsAfter: %v", err)
	}
	out := map[uint64]bool{}
	for _, e := range events {
		out[e.Seq] = true
	}
	return out
}

func TestPruneRetentionRespectsArchivedWatermark(t *testing.T) {
	t.Run("no archiver: falls back to time-based pruning", func(t *testing.T) {
		storage.Backend = &storage.MockStorage{Zones: map[string][]byte{}, Tables: map[string]map[string][]byte{}}
		if err := storage.Backend.Init(); err != nil {
			t.Fatal(err)
		}
		writeAgedEvent(t, 1, 30) // old
		writeAgedEvent(t, 2, 1)  // fresh
		if err := PruneOlderThan(14); err != nil {
			t.Fatalf("PruneOlderThan: %v", err)
		}
		got := remainingSeqs(t)
		if got[1] {
			t.Error("old event should be pruned when no archiver is active")
		}
		if !got[2] {
			t.Error("fresh event must be kept")
		}
	})

	t.Run("archiver active: old but un-archived events are kept", func(t *testing.T) {
		storage.Backend = &storage.MockStorage{Zones: map[string][]byte{}, Tables: map[string]map[string][]byte{}}
		if err := storage.Backend.Init(); err != nil {
			t.Fatal(err)
		}
		writeAgedEvent(t, 1, 30) // old + archived
		writeAgedEvent(t, 2, 30) // old + NOT archived
		if err := SetArchivedSeq(1); err != nil {
			t.Fatalf("SetArchivedSeq: %v", err)
		}
		if err := PruneOlderThan(14); err != nil {
			t.Fatalf("PruneOlderThan: %v", err)
		}
		got := remainingSeqs(t)
		if got[1] {
			t.Error("old archived event should be pruned")
		}
		if !got[2] {
			t.Error("old un-archived event must be kept (export-status aware)")
		}
	})

	t.Run("SetArchivedSeq is monotonic", func(t *testing.T) {
		storage.Backend = &storage.MockStorage{Zones: map[string][]byte{}, Tables: map[string]map[string][]byte{}}
		if err := storage.Backend.Init(); err != nil {
			t.Fatal(err)
		}
		if err := SetArchivedSeq(10); err != nil {
			t.Fatal(err)
		}
		if err := SetArchivedSeq(5); err != nil { // stale ack
			t.Fatal(err)
		}
		got, err := ArchivedSeq()
		if err != nil {
			t.Fatal(err)
		}
		if got != 10 {
			t.Fatalf("archived_seq = %d, want 10 (must not move backward)", got)
		}
	})
}
