package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"sni-proxy/internal/config"
	"sni-proxy/internal/proxy"
	"sni-proxy/internal/resolver"
	"sni-proxy/internal/server"
	"sni-proxy/internal/upstream"
)

func main() {
	cfg := config.Load()

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Printf("[info] -- sni-proxy -------------------------------")
	log.Printf("[info]   HTTPS    : %s", cfg.ListenHTTPS)
	log.Printf("[info]   HTTP     : %s", cfg.ListenHTTP)
	log.Printf("[info]   SOCKS    : %s", cfg.SocksURL)
	log.Printf("[info]   DoH      : %s", cfg.DoHServer)
	log.Printf("[info]   DNS TTL  : %s", cfg.CacheTTL)
	log.Printf("[info] --------------------------------------------")

	if cfg.SocksURL == "" {
		log.Fatalf("[fatal] SOCKS_URL is required (e.g. socks5://user:pass@host:1080)")
	}

	socksDialer, err := upstream.NewSocksDialer(cfg.SocksURL)
	if err != nil {
		log.Fatalf("[fatal] socks dialer: %v", err)
	}

	dialer := upstream.NewSwappableDialer(socksDialer)

	res := resolver.NewDoHResolver(cfg.DoHServer, cfg.CacheTTL)
	tunnel := proxy.NewTunnel(res, dialer)
	srv := server.New(cfg, tunnel)

	listeners, err := srv.StartAll()
	if err != nil {
		log.Fatalf("[fatal] %v", err)
	}

	// Bind UDP on the same address as HTTPS to intercept QUIC/HTTP3 and
	// send back Version Negotiation — clients immediately fall back to TCP/TLS.
	udpConn, err := srv.StartUDPQuicRejector(cfg.ListenHTTPS)
	if err != nil {
		log.Printf("[warn] QUIC rejector: %v (UDP 443 will not be handled)", err)
	}

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch

	log.Println("[info] shutdown signal -- closing listeners")
	for _, listener := range listeners {
		_ = listener.Close()
	}
	if udpConn != nil {
		_ = udpConn.Close()
	}

	log.Println("[info] sni-proxy stopped")
}
