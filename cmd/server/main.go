package main

import (
    "log"
    "go53/config"
    "go53/dns"
    "go53/api"
)

func main() {
    cfg := config.Load()

    go func() {
        log.Println("Starting DNS server on port 53...")
        if err := dns.Start(cfg); err != nil {
            log.Fatal(err)
        }
    }()

    log.Println("Starting REST API on port 8080...")
    if err := api.Start(cfg); err != nil {
        log.Fatal(err)
    }
}
