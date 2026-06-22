package wal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"go53/config"
	"go53/storage"
)

const (
	EventsTable = "wal-events"
	MetaTable   = "wal-meta"
	LastSeqKey  = "last_seq"
	// ArchivedSeqKey records the highest WAL sequence an external archiver has
	// confirmed durably stored. Retention never prunes events above it.
	ArchivedSeqKey = "archived_seq"

	KindZoneRecord = "zone_record"
	KindZone       = "zone"
	KindConfig     = "config"
	KindTSIGKey    = "tsig_key"
	KindDNSSECKey  = "dnssec_key"

	OpUpsert = "upsert"
	OpDelete = "delete"
	OpImport = "import"
)

var Magic = []byte("GO53WAL1")

type Event struct {
	Seq       uint64
	CreatedAt int64
	Kind      string
	Op        string
	Zone      string
	RRType    string
	Name      string
	Table     string
	Key       string
	Value     []byte
	Checksum  string
}

func Append(kind, op, zone, rrtype, name, table, key string, value []byte) (uint64, error) {
	if storage.Backend == nil {
		return 0, errors.New("storage backend is not initialized")
	}
	seq, err := nextSeq()
	if err != nil {
		return 0, err
	}
	e := Event{
		Seq:       seq,
		CreatedAt: time.Now().Unix(),
		Kind:      kind,
		Op:        op,
		Zone:      zone,
		RRType:    strings.ToUpper(strings.TrimSpace(rrtype)),
		Name:      name,
		Table:     table,
		Key:       key,
		Value:     append([]byte(nil), value...),
	}
	e.Checksum = checksum(e)
	data, err := encodeEvent(e)
	if err != nil {
		return 0, err
	}
	if err := storage.Backend.SaveTable(EventsTable, seqKey(seq), data); err != nil {
		return 0, err
	}
	if err := storage.Backend.SaveTable(MetaTable, LastSeqKey, []byte(strconv.FormatUint(seq, 10))); err != nil {
		return 0, err
	}
	if err := PruneOlderThan(config.AppConfig.GetLive().WALRetentionDays); err != nil {
		return 0, err
	}
	return seq, nil
}

func Export(after uint64, w io.Writer) error {
	events, err := EventsAfter(after)
	if err != nil {
		return err
	}
	if _, err := w.Write(Magic); err != nil {
		return err
	}
	var lenBuf [4]byte
	for _, e := range events {
		data, err := encodeEvent(e)
		if err != nil {
			return err
		}
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
		if _, err := w.Write(lenBuf[:]); err != nil {
			return err
		}
		if _, err := w.Write(data); err != nil {
			return err
		}
	}
	return nil
}

func DecodeExport(r io.Reader) ([]Event, error) {
	header := make([]byte, len(Magic))
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	if !bytes.Equal(header, Magic) {
		return nil, errors.New("invalid WAL magic header")
	}
	var events []Event
	var lenBuf [4]byte
	for {
		_, err := io.ReadFull(r, lenBuf[:])
		if err == io.EOF {
			return events, nil
		}
		if err != nil {
			return nil, err
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		data := make([]byte, n)
		if _, err := io.ReadFull(r, data); err != nil {
			return nil, err
		}
		event, err := decodeEvent(data)
		if err != nil {
			return nil, err
		}
		if event.Checksum != checksum(event) {
			return nil, fmt.Errorf("WAL event %d checksum mismatch", event.Seq)
		}
		events = append(events, event)
	}
}

func EventsAfter(after uint64) ([]Event, error) {
	if storage.Backend == nil {
		return nil, errors.New("storage backend is not initialized")
	}
	raw, err := storage.Backend.LoadTable(EventsTable)
	if err != nil {
		return nil, err
	}
	events := make([]Event, 0, len(raw))
	for key, data := range raw {
		seq, err := strconv.ParseUint(key, 10, 64)
		if err != nil || seq <= after {
			continue
		}
		event, err := decodeEvent(data)
		if err != nil {
			return nil, fmt.Errorf("decode WAL event %s: %w", key, err)
		}
		if event.Checksum != checksum(event) {
			return nil, fmt.Errorf("WAL event %s checksum mismatch", key)
		}
		events = append(events, event)
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Seq < events[j].Seq })
	return events, nil
}

func LastSeq() (uint64, error) {
	if storage.Backend == nil {
		return 0, errors.New("storage backend is not initialized")
	}
	meta, err := storage.Backend.LoadTable(MetaTable)
	if err != nil {
		return 0, err
	}
	if len(meta[LastSeqKey]) == 0 {
		return 0, nil
	}
	return strconv.ParseUint(string(meta[LastSeqKey]), 10, 64)
}

// ArchivedSeq returns the highest WAL sequence an external archiver has
// acknowledged as durably stored, or 0 when none has been recorded.
func ArchivedSeq() (uint64, error) {
	if storage.Backend == nil {
		return 0, errors.New("storage backend is not initialized")
	}
	meta, err := storage.Backend.LoadTable(MetaTable)
	if err != nil {
		return 0, err
	}
	if len(meta[ArchivedSeqKey]) == 0 {
		return 0, nil
	}
	return strconv.ParseUint(string(meta[ArchivedSeqKey]), 10, 64)
}

// SetArchivedSeq advances the archived watermark. It is monotonic: a sequence at
// or below the current value is ignored, so a stale or duplicate ack can never
// move the floor backward and expose un-archived events to pruning.
func SetArchivedSeq(seq uint64) error {
	if storage.Backend == nil {
		return errors.New("storage backend is not initialized")
	}
	cur, err := ArchivedSeq()
	if err != nil {
		return err
	}
	if seq <= cur {
		return nil
	}
	return storage.Backend.SaveTable(MetaTable, ArchivedSeqKey, []byte(strconv.FormatUint(seq, 10)))
}

// PruneOlderThan deletes internal WAL events older than the retention window.
// It is export-status aware: once an external archiver has acknowledged a
// sequence (archived_seq > 0), events above that watermark are kept regardless
// of age, so a lagging archiver can never lose un-archived WAL. When no archiver
// has acknowledged anything (archived_seq == 0), retention falls back to plain
// time-based pruning so non-archiving deployments stay bounded.
func PruneOlderThan(days int) error {
	if days <= 0 {
		return nil
	}
	if storage.Backend == nil {
		return errors.New("storage backend is not initialized")
	}
	archived, err := ArchivedSeq()
	if err != nil {
		return err
	}
	raw, err := storage.Backend.LoadTable(EventsTable)
	if err != nil {
		return err
	}
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour).Unix()
	for key, data := range raw {
		event, err := decodeEvent(data)
		if err != nil {
			return fmt.Errorf("decode WAL event %s: %w", key, err)
		}
		if event.CreatedAt >= cutoff {
			continue
		}
		if archived > 0 && event.Seq > archived {
			continue
		}
		if err := storage.Backend.DeleteFromTable(EventsTable, key); err != nil {
			return err
		}
	}
	return nil
}

func nextSeq() (uint64, error) {
	last, err := LastSeq()
	if err != nil {
		return 0, err
	}
	return last + 1, nil
}

func seqKey(seq uint64) string {
	return fmt.Sprintf("%020d", seq)
}

func encodeEvent(e Event) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte(1)
	writeUvarint(&buf, e.Seq)
	writeUvarint(&buf, uint64(e.CreatedAt))
	writeBytes(&buf, []byte(e.Kind))
	writeBytes(&buf, []byte(e.Op))
	writeBytes(&buf, []byte(e.Zone))
	writeBytes(&buf, []byte(e.RRType))
	writeBytes(&buf, []byte(e.Name))
	writeBytes(&buf, []byte(e.Table))
	writeBytes(&buf, []byte(e.Key))
	writeBytes(&buf, e.Value)
	writeBytes(&buf, []byte(e.Checksum))
	return buf.Bytes(), nil
}

func decodeEvent(data []byte) (Event, error) {
	r := bytes.NewReader(data)
	version, err := r.ReadByte()
	if err != nil {
		return Event{}, err
	}
	if version != 1 {
		return Event{}, fmt.Errorf("unsupported WAL event version %d", version)
	}
	seq, err := binary.ReadUvarint(r)
	if err != nil {
		return Event{}, err
	}
	createdAt, err := binary.ReadUvarint(r)
	if err != nil {
		return Event{}, err
	}
	fields := make([][]byte, 7)
	for i := range fields {
		fields[i], err = readBytes(r)
		if err != nil {
			return Event{}, err
		}
	}
	value, err := readBytes(r)
	if err != nil {
		return Event{}, err
	}
	checksumRaw, err := readBytes(r)
	if err != nil {
		return Event{}, err
	}
	return Event{
		Seq:       seq,
		CreatedAt: int64(createdAt),
		Kind:      string(fields[0]),
		Op:        string(fields[1]),
		Zone:      string(fields[2]),
		RRType:    string(fields[3]),
		Name:      string(fields[4]),
		Table:     string(fields[5]),
		Key:       string(fields[6]),
		Value:     value,
		Checksum:  string(checksumRaw),
	}, nil
}

func checksum(e Event) string {
	e.Checksum = ""
	data, _ := encodeEvent(e)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func writeUvarint(buf *bytes.Buffer, value uint64) {
	var tmp [10]byte
	n := binary.PutUvarint(tmp[:], value)
	buf.Write(tmp[:n])
}

func writeBytes(buf *bytes.Buffer, value []byte) {
	writeUvarint(buf, uint64(len(value)))
	buf.Write(value)
}

func readBytes(r *bytes.Reader) ([]byte, error) {
	n, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	if n > uint64(r.Len()) {
		return nil, io.ErrUnexpectedEOF
	}
	out := make([]byte, n)
	_, err = io.ReadFull(r, out)
	return out, err
}
