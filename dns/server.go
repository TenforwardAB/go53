package dns

import (
	"fmt"
	"github.com/miekg/dns"
	"go53/config"
	"log"
)

func Start(cfg config.BaseConfig) error {
	dns.HandleFunc(".", handleRequest)

	addr := fmt.Sprintf("%s%s", cfg.BindHost, cfg.DNSPort)

	server := &dns.Server{Addr: addr, Net: "udp"}

	go func() {
		tcpServer := &dns.Server{Addr: addr, Net: "tcp"}
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Printf("TCP DNS server error: %v", err)
		}
	}()

	log.Printf("Starting UDP DNS server on %s", addr)
	return server.ListenAndServe()
}
