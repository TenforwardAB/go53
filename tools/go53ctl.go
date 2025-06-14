package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/dgraph-io/badger/v4"
)

func main() {
	var (
		dbPath    string
		listAll   bool
		listZone  string
		countOnly bool
	)

	flag.StringVar(&dbPath, "db", "../data/go53", "Path to BadgerDB")
	flag.BoolVar(&listAll, "list-all-zones", false, "List all zones with record type counts")
	flag.StringVar(&listZone, "list-zone", "", "List one specific zone")
	flag.BoolVar(&countOnly, "count-only", false, "Only print record counts")
	flag.Parse()

	if len(os.Args) == 1 {
		fmt.Println(`Usage: zone_stats [OPTIONS]

Options:
  --db PATH            Path to BadgerDB (default: ../data/go53)
  --list-all-zones     List all zones with their record rtypes and counts
  --list-zone ZONE     List a specific zone's records
  --count-only         Only show record counts instead of full record data

Examples:
  zone_stats --list-all-zones --count-only
  zone_stats --list-zone go53.test
  zone_stats --list-zone go53.test --count-only
`)
		os.Exit(0)
	}

	absPath, err := filepath.Abs(dbPath)
	if err != nil {
		log.Fatal(err)
	}

	opts := badger.DefaultOptions(absPath).WithLogger(nil)
	db, err := badger.Open(opts)
	if err != nil {
		log.Fatalf("Failed to open BadgerDB: %v", err)
	}
	defer db.Close()

	switch {
	case listAll:
		handleListAllZones(db, countOnly)
	case listZone != "":
		handleListZone(db, listZone, countOnly)
	default:
		dumpAll(db)
	}
}

func handleListAllZones(db *badger.DB, countOnly bool) {
	result := make(map[string]map[string]map[string]interface{})

	err := db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			zone := string(item.Key())

			err := item.Value(func(val []byte) error {
				// val holds JSON like: {"A": { ... }, "SOA": { ... }, …}
				var records map[string]map[string]interface{}
				if err := json.Unmarshal(val, &records); err != nil {
					fmt.Printf("Skipping %s: failed to unmarshal: %v\n", zone, err)
					return nil
				}

				result[zone] = make(map[string]map[string]interface{}, len(records))
				for rtype, entries := range records {
					result[zone][rtype] = entries
				}
				return nil
			})

			if err != nil {
				fmt.Printf("Error reading zone %s: %v\n", zone, err)
			}
		}
		return nil
	})

	if err != nil {
		log.Fatalf("DB read failed: %v", err)
	}

	if countOnly {
		for zone, types := range result {
			fmt.Printf("%s:\n", zone)
			for rtype, count := range types {
				fmt.Printf("  %s: %d\n", rtype, count)
			}
		}
	} else {
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
	}
}

func handleListZone(db *badger.DB, zone string, countOnly bool) {
	err := db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(zone))
		if err != nil {
			return fmt.Errorf("zone '%s' not found", zone)
		}

		return item.Value(func(val []byte) error {
			var records map[string]map[string]interface{}
			if err := json.Unmarshal(val, &records); err != nil {
				return fmt.Errorf("unmarshal error: %v", err)
			}

			if countOnly {
				fmt.Printf("%s:\n", zone)
				for rtype, entries := range records {
					fmt.Printf("  %s: %d\n", rtype, len(entries))
				}
			} else {
				out, _ := json.MarshalIndent(records, "", "  ")
				fmt.Println(string(out))
			}
			return nil
		})
	})

	if err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func dumpAll(db *badger.DB) {
	fmt.Println("Dumping all zones and all records...\n")
	err := db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			zone := string(item.Key())
			err := item.Value(func(val []byte) error {
				fmt.Printf("Zone: %s\n", zone)
				var raw json.RawMessage
				if err := json.Unmarshal(val, &raw); err != nil {
					fmt.Printf("  [Unparseable value]\n\n")
					return nil
				}
				out, _ := json.MarshalIndent(raw, "  ", "  ")
				fmt.Printf("  %s\n\n", out)
				return nil
			})
			if err != nil {
				fmt.Printf("Error reading zone %s: %v\n", zone, err)
			}
		}
		return nil
	})

	if err != nil {
		log.Fatalf("DB iteration failed: %v", err)
	}
}
