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
	io_prometheus_client "github.com/prometheus/client_model/go" // dto
	"go.uber.org/zap"

	dns "sni_proxy/dns"
	tcpproxy "sni_proxy/internal/tcpproxy"
	udpproxy "sni_proxy/internal/udpproxy"
	ws "sni_proxy/internal/websocket"
)

// Глобальные метрики Prometheus
var (
	DnsRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_requests_total",
		Help: "Total number of DNS requests",
	}, []string{"domain", "status"})
	TcpActiveConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "tcp_active_connections",
		Help: "Current number of active TCP connections",
	})
	UdpActiveConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "udp_active_connections",
		Help: "Current number of active UDP connections",
	})
	UdpPacketErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "udp_packet_errors_total",
		Help: "Total number of UDP packet errors",
	}, []string{"type"})
	logger *zap.Logger
)

func init() {
	var err error
	logger, err = zap.NewProduction()
	if err != nil {
		panic("failed to initialize logger: " + err.Error())
	}

	// Безопасная регистрация: проверяет, не зарегистрирована ли уже
	registerOnce(DnsRequests)
	registerOnce(TcpActiveConnections)
	registerOnce(UdpActiveConnections)
	registerOnce(UdpPacketErrors)
}

func registerOnce(c prometheus.Collector) {
	if err := prometheus.DefaultRegisterer.Register(c); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			// Подменяем на уже зарегистрированную метрику
			_ = are.ExistingCollector
		} else {
			panic(err)
		}
	}
}

// getGaugeValue получает текущее значение метрики Gauge
func getGaugeValue(g prometheus.Gauge) float64 {
	ch := make(chan prometheus.Metric, 1)
	g.Collect(ch)
	metric := <-ch
	pb := &io_prometheus_client.Metric{}
	if err := metric.Write(pb); err != nil {
		return -1 // ошибка при сериализации
	}
	if pb.Gauge != nil && pb.Gauge.Value != nil {
		return *pb.Gauge.Value
	}
	return -1 // значение не найдено
}

func main() {
	// ─── Параметры командной строки ────────────────────────────────────────────
	addr         := flag.String("addr", ":443", "TCP and UDP proxy listen address")
	globalLimit  := flag.Int("global-limit", 8000, "Global connection limit")
	perIPLimit   := flag.Int("per-ip-limit", 80, "Per-IP connection limit")
	flag.Parse()

	// ─── Контекст для graceful‑shutdown ────────────────────────────────────────
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ─── DNS‑резолвер ──────────────────────────────────────────────────────────
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

	// ─── TCP‑прокси ────────────────────────────────────────────────────────────
	tcpProxy := tcpproxy.NewTCPProxy(resolver, *addr, logger, *globalLimit, *perIPLimit, 5*time.Minute)

	// ─── UDP‑прокси (внутри сразу открывает udp4+udp6 сокеты) ─────────────────
	udpProxy, err := udpproxy.NewProxy(*addr, resolver, logger, udpproxy.DefaultConfig())
	if err != nil {
		logger.Fatal("[UDP] proxy initialization error", zap.Error(err))
	}

	// ─── HTTP‑сервер для метрик ────────────────────────────────────────────────
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	httpServer := &http.Server{Handler: mux}

	// ─── WebSocket‑сервер (дэшборд/отладка) ────────────────────────────────────
	wsServer := ws.NewWebSocketServer(logger)

	// ─── Запуск всех слушателей ────────────────────────────────────────────────
	tcpLn, err := net.Listen("tcp", *addr)
	if err != nil {
		logger.Fatal("[TCP] listen error", zap.Error(err))
	}
	go tcpProxy.ListenWithListener(ctx, tcpLn)

	go udpProxy.Listen() // ← запускаем приём пакетов на уже открытых UDP‑сокетах

	httpLn, err := net.Listen("tcp", ":8080")
	if err != nil {
		logger.Fatal("[HTTP] listen error", zap.Error(err))
	}
	go func() {
		if err := httpServer.Serve(httpLn); err != nil && err != http.ErrServerClosed {
			logger.Error("[HTTP] server error", zap.Error(err))
		}
	}()

	wsLn, err := net.Listen("tcp", ":8081")
	if err != nil {
		logger.Fatal("[WS] listen error", zap.Error(err))
	}
	go wsServer.Start(ctx, wsLn)

	// ─── Ожидание Ctrl‑C / SIGINT ──────────────────────────────────────────────
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig

	logger.Info("shutdown signal received")
	cancel()

	// ─── Логируем метрики перед выходом ───────────────────────────────────────
	logger.Info("active connections",
		zap.Float64("tcp", getGaugeValue(TcpActiveConnections)),
		zap.Float64("udp", getGaugeValue(UdpActiveConnections)),
	)

	// ─── Закрываем TCP/HTTP/WS (UDP‑сокеты закроются внутри udpProxy) ─────────
	if err := tcpLn.Close(); err != nil {
		logger.Error("[TCP] close error", zap.Error(err))
	}
	if err := httpLn.Close(); err != nil {
		logger.Error("[HTTP] close error", zap.Error(err))
	}
	if err := wsLn.Close(); err != nil {
		logger.Error("[WS] close error", zap.Error(err))
	}

	// ─── Корректное завершение HTTP‑серверов ──────────────────────────────────
	shutdownCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("[HTTP] shutdown error", zap.Error(err))
	}

	logger.Info("shutdown complete")
	time.Sleep(1 * time.Second) // небольшой буфер, чтобы логи успели записаться
}
