package main

import (
	"context"
	"flag"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"

	dns "sni_proxy/dns"
	tcpproxy "sni_proxy/internal/tcpproxy"
	udpproxy "sni_proxy/internal/udpproxy"
)

var logger *zap.Logger

func init() {
	var err error
	logger, err = zap.NewProduction()
	if err != nil {
		panic("failed to initialize logger: " + err.Error())
	}
}

// В твоей версии testutil.ToFloat64 возвращает только float64.
func gaugeValue(c prometheus.Collector) float64 {
	return testutil.ToFloat64(c)
}

func main() {
	// ─── Параметры командной строки ────────────────────────────────────────────
	addr := flag.String("addr", ":443", "TCP and UDP proxy listen address")
	globalLimit := flag.Int("global-limit", 8000, "Global connection limit")
	perIPLimit := flag.Int("per-ip-limit", 80, "Per-IP connection limit")
	flag.Parse()

	// ─── Контекст для graceful-shutdown ────────────────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ─── DNS-резолвер ──────────────────────────────────────────────────────────
	resolver := dns.NewResolver(dns.Config{
		DOHURLs:              []string{"https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query"},
		LookupTimeout:        4 * time.Second,
		CacheCleanupInterval: 10 * time.Minute,
		MinTTL:               1 * time.Minute,
		MaxTTL:               30 * time.Minute,
		HistoryTTL:           5 * time.Minute,
		Retries:              2,
		InitialBackoff:       500 * time.Millisecond,
	})

	// ─── TCP-прокси ────────────────────────────────────────────────────────────
	tcpProxy := tcpproxy.NewTCPProxy(resolver, *addr, logger, *globalLimit, *perIPLimit, 5*time.Minute)

	// ─── UDP-прокси ────────────────────────────────────────────────────────────
	udpProxy, err := udpproxy.NewProxy(*addr, resolver, logger, udpproxy.DefaultConfig())
	if err != nil {
		logger.Fatal("[UDP] proxy initialization error", zap.Error(err))
	}

	// ─── HTTP-сервер для метрик ────────────────────────────────────────────────
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	httpServer := &http.Server{Handler: mux}

	// ─── Запуск слушателей ────────────────────────────────────────────────────
	tcpLn, err := net.Listen("tcp", *addr)
	if err != nil {
		logger.Fatal("[TCP] listen error", zap.Error(err))
	}
	go tcpProxy.ListenWithListener(ctx, tcpLn)

	go udpProxy.Listen()

	httpLn, err := net.Listen("tcp", ":8080")
	if err != nil {
		logger.Fatal("[HTTP] listen error", zap.Error(err))
	}
	go func() {
		if err := httpServer.Serve(httpLn); err != nil && err != http.ErrServerClosed {
			logger.Error("[HTTP] server error", zap.Error(err))
		}
	}()

	// ─── Ожидание SIGINT ──────────────────────────────────────────────────────
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig

	logger.Info("shutdown signal received")
	cancel()

	// ─── Логируем метрики перед выходом ───────────────────────────────────────
	logger.Info("active connections",
		zap.Float64("tcp", gaugeValue(tcpproxy.TCPActiveConnections)),
		zap.Float64("udp", gaugeValue(udpproxy.UDPActiveConnections)),
	)

	// ─── Закрытие слушателей ──────────────────────────────────────────────────
	if err := tcpLn.Close(); err != nil {
		logger.Error("[TCP] close error", zap.Error(err))
	}
	if err := httpLn.Close(); err != nil {
		logger.Error("[HTTP] close error", zap.Error(err))
	}

	// ─── Корректное завершение HTTP-сервера ───────────────────────────────────
	shutdownCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("[HTTP] shutdown error", zap.Error(err))
	}

	logger.Info("shutdown complete")
	time.Sleep(1 * time.Second)
}
