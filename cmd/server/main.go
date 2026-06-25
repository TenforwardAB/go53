package main

import (
	"context"
	"flag"
	"fmt"
	"go53/api"
	"go53/config"
	"go53/distributed"
	"go53/dns"
	"go53/dns/dnsutils"
	"go53/memory"
	"go53/security"
	"go53/storage"
	"go53/zone/rtypes"
	"log"

	"github.com/TenforwardAB/slog"
)

var generateTSIG = flag.Bool("generate-tsig", false, "Generate TSIG key and store it if not present")

func main() {
	slog.SetLevel("debug")

	slog.Info("Application started")
	flag.Parse()

	config.AppConfig.Init()
	config.AppConfig.InitLiveConfig()
	// Reset the loglevel from config
	config.ApplyLogLevel(config.AppConfig.GetLive().LogLevel)
	if err := security.InitDNSSECKeyCache(); err != nil {
		log.Fatalf("Failed to load DNSSEC key cache: %v", err)
	}
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
	distributed.Init(store)

	ctx := context.Background()
	go dnsutils.ProcessFetchQueue()
	// Secondary-mode startup + periodic AXFR refresh. No-op in primary/distributed mode.
	dnsutils.StartSecondaryRefresh(ctx)
	distributed.Start(ctx)

	go func() {
		log.Println("Starting DNS server on", base.DNSPort)
		if err := dns.Start(base); err != nil {
			log.Fatal(err)
		}
	}()

	// Local break-glass admin: the full API served over a Unix socket gated by
	// filesystem permissions (group go53_admin), usable when the IdP is unreachable.
	go api.StartAdminSocket(base)

	api.SetReady(true)
	log.Println("Starting REST API on", base.APIPort)
	if err := api.Start(base); err != nil {
		log.Fatal(err)
	}
}
