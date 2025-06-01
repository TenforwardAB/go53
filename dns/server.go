package dns

import (
    "github.com/miekg/dns"
    "go53/config"
)

func Start(cfg *config.Config) error {
    dns.HandleFunc(".", handleRequest)

    server := &dns.Server{Addr: cfg.DNSPort, Net: "udp"}
    go func() {
        dns.ListenAndServe(cfg.DNSPort, "tcp", nil)
    }()
    return server.ListenAndServe()
}
