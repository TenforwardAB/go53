package main

import (
	"go53/api"
	"go53/config"
	"go53/dns"
	"go53/memory"
	"go53/storage"
	"go53/zone/rtypes"
	"log"
)

func main() {
	config.LoadConfig()

	// Initialize selected storage backend
	if err := storage.Init(config.AppConfig.StorageBackend); err != nil {
		log.Fatalf("Storage init failed: %v", err)
	}

	store, err := memory.NewZoneStore(storage.Backend)
	if err != nil {
		panic(err)
	}
	rtypes.InitMemoryStore(store)

	// Initialize the in-memory ZoneStore (loads from storage)
	//	if err := zone.InitZoneStore(); err != nil {
	//log.Fatalf("ZoneStore init failed: %v", err)
	//}

	go func() {
		log.Println("Starting DNS server on port: ", config.AppConfig.DNSPort)
		if err := dns.Start(config.AppConfig); err != nil {
			log.Fatal(err)
		}
	}()

	log.Println("Starting REST API on port: ", config.AppConfig.APIPort)
	if err := api.Start(config.AppConfig); err != nil {
		log.Fatal(err)
	}
}
