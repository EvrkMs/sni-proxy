package config

import (
	"os"
	"time"
)

type Config struct {
	ListenHTTPS string
	ListenHTTP  string
	SocksURL    string
	DoHServer   string
	CacheTTL    time.Duration
}

func Load() Config {
	return Config{
		ListenHTTPS: envOr("LISTEN_HTTPS", "0.0.0.0:443"),
		ListenHTTP:  envOr("LISTEN_HTTP", "0.0.0.0:80"),
		SocksURL:    envOr("SOCKS_URL", ""),
		DoHServer:   envOr("DOH_SERVER", "https://a353d38e:%7E4UzAyVk@d.adguard-dns.com/dns-query"),
		CacheTTL:    durationOr("DNS_CACHE_TTL", 5*time.Minute),
	}
}

func envOr(key, def string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return def
}

func durationOr(key string, def time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return def
	}

	parsed, err := time.ParseDuration(value)
	if err != nil {
		return def
	}

	return parsed
}
