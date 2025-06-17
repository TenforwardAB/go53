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
	config.AppConfig.Init()
	config.AppConfig.InitLiveConfig()
	base := config.AppConfig.GetBase()

	store, err := memory.NewZoneStore(storage.Backend)
	if err != nil {
		log.Fatal(err)
	}
	rtypes.InitMemoryStore(store)

	go func() {
		log.Println("Starting DNS server on", base.DNSPort)
		if err := dns.Start(base); err != nil {
			log.Fatal(err)
		}
	}()

	log.Println("Starting REST API on", base.APIPort)
	if err := api.Start(base); err != nil {
		log.Fatal(err)
	}
}
