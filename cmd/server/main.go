package main

import (
	"flag"
	"fmt"
	"github.com/TenforwardAB/slog"
	"go53/api"
	"go53/config"
	"go53/dns"
	"go53/dns/dnsutils"
	"go53/memory"
	"go53/security"
	"go53/storage"
	"go53/zone/rtypes"
	"log"
)

var generateTSIG = flag.Bool("generate-tsig", false, "Generate TSIG key and store it if not present")

func main() {
	slog.SetLevel("debug")

	slog.Info("Application started")
	flag.Parse()

	config.AppConfig.Init()
	config.AppConfig.InitLiveConfig()
	base := config.AppConfig.GetBase()
	slog.Crazy("Live Config DNSSEC ENABLE is: %b", config.AppConfig.GetLive().DNSSECEnabled)

	const table = "tsig-keys"
	const keyName = "xxfr-key"

	if *generateTSIG {
		existing, err := storage.Backend.LoadTable(table)
		if err != nil {
			log.Fatalf("Failed to load TSIG table: %v", err)
		}

		if _, ok := existing[keyName]; ok {
			log.Printf("TSIG key '%s' already exists. Skipping generation.", keyName)
		} else {
			secret, err := security.GenerateTSIGSecret()
			if err != nil {
				log.Fatalf("Failed to generate TSIG key: %v", err)
			}

			value := []byte(fmt.Sprintf(`{"algorithm":"hmac-sha256.","secret":"%s"}`, secret))

			if err := storage.Backend.SaveTable(table, keyName, value); err != nil {
				log.Fatalf("Failed to save TSIG key: %v", err)
			}

			log.Printf("TSIG key '%s' generated and stored.", keyName)
			new, err := storage.Backend.LoadTable(table)
			if err != nil {
				log.Fatalf("Failed to load TSIG table: %v", err)
			}
			log.Println("TSIG key stored:", string(new[keyName]))
		}
	} else {
		log.Println("TSIG key generation skipped (generateTSIG flag not set).")
	}

	err := security.LoadTSIGKeysFromStorage()
	if err != nil {
		return
	}

	store, err := memory.NewZoneStore(storage.Backend)
	if err != nil {
		log.Fatal(err)
	}
	rtypes.InitMemoryStore(store)

	go dnsutils.ProcessFetchQueue()

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
