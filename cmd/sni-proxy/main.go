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

	// Probe SOCKS5 for UDP ASSOCIATE. If available — proxy QUIC through SOCKS;
	// otherwise keep Version Negotiation (TCP fallback).
	if dialer.SupportsUDP() {
		log.Printf("[info] SOCKS upstream supports UDP — QUIC will be proxied via UDP ASSOCIATE")
		udpTunnel := proxy.NewUDPTunnel(res, dialer)
		srv.SetUDPTunnel(udpTunnel)
	} else {
		log.Printf("[info] SOCKS upstream has no UDP — QUIC will get Version Negotiation (TCP fallback)")
	}

	listeners, err := srv.StartAll()
	if err != nil {
		log.Fatalf("[fatal] %v", err)
	}

	udpConn, err := srv.StartUDP(cfg.ListenHTTPS)
	if err != nil {
		log.Printf("[warn] UDP listener: %v (UDP 443 will not be handled)", err)
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
