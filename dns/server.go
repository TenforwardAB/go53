package dns

import (
	"fmt"
	"github.com/miekg/dns"
	"go53/config"
	"go53/security"
	"log"
	"time"
)

func Start(cfg config.BaseConfig) error {
	tsigSecrets := make(map[string]string)
	for k, v := range security.TSIGSecrets {
		tsigSecrets[k] = v.Secret
	}
	dns.HandleFunc(".", handleRequest)

	addr := fmt.Sprintf("%s%s", cfg.BindHost, cfg.DNSPort)

	udpServer := &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: dns.DefaultServeMux,
	}

	tcpServer := &dns.Server{
		Addr:          addr,
		Net:           "tcp",
		TsigSecret:    tsigSecrets,
		Handler:       dns.DefaultServeMux,
		ReadTimeout:   5 * time.Second,
		WriteTimeout:  5 * time.Second,
		MaxTCPQueries: 128,
		ReusePort:     true, // MAKE configurable not valid on all OS
	}

	go func() {
		log.Printf("Starting TCP DNS server on %s", addr)
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Printf("TCP DNS server error: %v", err)
		}
	}()

	log.Printf("Starting UDP DNS server on %s", addr)
	return udpServer.ListenAndServe()
}
