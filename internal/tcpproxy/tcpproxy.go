package tcpproxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	dns "sni_proxy/dns"

	"github.com/prometheus/client_golang/prometheus"
	utls "github.com/refraction-networking/utls"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

// Метрики Prometheus
var (
	// Экспортируем, чтобы main мог читать текущее значение
	TCPActiveConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "tcp_active_connections",
		Help: "Current number of active TCP connections",
	})
	dnsRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_requests_total",
		Help: "Total number of DNS requests",
	}, []string{"domain", "status"})
)

func init() {
	prometheus.MustRegister(TCPActiveConnections, dnsRequests)
}

/* -------------------------------------------------------------------------- */
/*                              Configuration                                 */
/* -------------------------------------------------------------------------- */

type TCPProxy struct {
	resolver    *dns.Resolver
	addr        string
	log         *zap.Logger
	globalSem   chan struct{}
	perIP       int
	ipSem       sync.Map
	keepAlive   time.Duration
	limiter     *rate.Limiter
	cleanupOnce sync.Once
}

var bufPool = sync.Pool{
	New: func() any { return make([]byte, 32<<10) }, // 32 KB
}

func NewTCPProxy(r *dns.Resolver, addr string, log *zap.Logger,
	global, perIP int, keepAlive time.Duration) *TCPProxy {

	return &TCPProxy{
		resolver:  r,
		addr:      addr,
		log:       log,
		globalSem: make(chan struct{}, global),
		perIP:     perIP,
		keepAlive: keepAlive,
		limiter:   rate.NewLimiter(rate.Limit(global*2), global*2),
	}
}

/* -------------------------------------------------------------------------- */
/*                                   Serve                                    */
/* -------------------------------------------------------------------------- */

func (p *TCPProxy) ListenWithListener(ctx context.Context, ln net.Listener) {
	p.log.Info("[TCP] listening", zap.String("addr", p.addr))
	for {
		select {
		case <-ctx.Done():
			return
		default:
			conn, err := ln.Accept()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					p.log.Warn("[TCP] accept", zap.Error(err))
				}
				continue
			}
			go p.accept(conn)
		}
	}
}

func (p *TCPProxy) accept(cli net.Conn) {
	select {
	case p.globalSem <- struct{}{}:
	default:
		p.log.Warn("[TCP] global-limit drop", zap.String("client", cli.RemoteAddr().String()))
		_ = cli.Close()
		return
	}
	defer func() { <-p.globalSem }()

	ip, _, _ := net.SplitHostPort(cli.RemoteAddr().String())
	v, _ := p.ipSem.LoadOrStore(ip, make(chan struct{}, p.perIP))
	ipCh := v.(chan struct{})
	select {
	case ipCh <- struct{}{}:
	default:
		p.log.Warn("[TCP] per-IP limit", zap.String("ip", ip))
		_ = cli.Close()
		return
	}
	defer func() { <-ipCh }()

	p.cleanupOnce.Do(p.gcIPSem)

	if err := p.limiter.Wait(context.Background()); err != nil {
		_ = cli.Close()
		return
	}

	go p.session(cli)
}

/* -------------------------------------------------------------------------- */
/*                               One Session                                   */
/* -------------------------------------------------------------------------- */

func (p *TCPProxy) session(cli net.Conn) {
	TCPActiveConnections.Inc()
	defer TCPActiveConnections.Dec()

	id := cli.RemoteAddr().String()
	defer cli.Close()

	start := time.Now()
	var (
		reason   = "unknown"
		reasonMu sync.Mutex
	)
	setReason := func(r string) {
		reasonMu.Lock()
		if reason == "unknown" {
			reason = r
		}
		reasonMu.Unlock()
	}

	// Use bufio.Reader with a 32KB buffer
	r := bufio.NewReaderSize(cli, 32<<10)
	b, err := r.Peek(5) // Peek enough to check TLS header
	if err != nil {
		p.log.Debug("[TCP] peek fail", zap.String("client", id), zap.Error(err))
		setReason("peek_fail")
		return
	}

	var up net.Conn

	// --- TLS-ветка (wss://)
	if len(b) >= 5 && b[0] == 0x16 && b[1] == 0x03 {
		p.log.Debug("[TCP] detected TLS", zap.String("client", id))
		targetSNI, alpn, rawCH, err := readClientHello(r)
		if err != nil {
			p.log.Debug("[TCP] handshake fail", zap.String("client", id), zap.Error(err))
			if tcpAddr, ok := cli.RemoteAddr().(*net.TCPAddr); ok {
				last := p.resolver.GetLastKnownDomain(tcpAddr.IP.String())
				if last != "" {
					p.log.Info("[TCP] fallback domain", zap.String("client", id), zap.String("domain", last))
					targetSNI = last
				} else {
					setReason("handshake_fail")
					return
				}
			} else {
				setReason("handshake_fail")
				return
			}
		}
		p.log.Info("[TCP] SNI", zap.String("client", id), zap.String("sni", targetSNI), zap.String("alpn", alpn))

		if tcpAddr, ok := cli.RemoteAddr().(*net.TCPAddr); ok {
			ipStr := tcpAddr.IP.String()
			p.resolver.ForceHistory(ipStr, targetSNI)
			p.log.Debug("[TCP] history set", zap.String("ip", ipStr), zap.String("domain", targetSNI))
		}
		ips, err := p.resolver.LookupIPs(context.Background(), targetSNI)
		if err != nil || len(ips) == 0 {
			p.log.Debug("[TCP] DNS fail", zap.String("client", id), zap.Error(err))
			setReason("dns_fail")
			return
		}

		up, err = dialFirstAlive(context.Background(), ips, p.keepAlive)
		if err != nil {
			p.log.Debug("[TCP] dial fail", zap.String("client", id), zap.Error(err))
			setReason("dial_fail")
			return
		}
		defer up.Close()

		// Пересылаем целиком ClientHello
		if _, err := up.Write(rawCH); err != nil {
			p.log.Debug("[TCP] write ClientHello fail", zap.String("client", id), zap.Error(err))
			setReason("write_clienthello_fail")
			return
		}

	} else {
		// --- HTTP-ветка (в том числе ws://)
		p.log.Debug("[TCP] detected HTTP", zap.String("client", id), zap.Binary("first_bytes", b))

		// Читаем заголовки HTTP (GET /path HTTP/1.1)
		reqHeaders, err := readHTTPHeaders(r)
		if err != nil {
			p.log.Debug("[TCP] HTTP request fail", zap.String("client", id), zap.Error(err))
			setReason("http_request_fail")
			return
		}

		// Определяем Host
		host, ok := getHostFromHeaders(reqHeaders)
		if !ok {
			p.log.Debug("[TCP] No Host header", zap.String("client", id))
			setReason("no_host_header")
			return
		}

		p.log.Info("[TCP] Host", zap.String("client", id), zap.String("host", host))

		if tcpAddr, ok := cli.RemoteAddr().(*net.TCPAddr); ok {
			ipStr := tcpAddr.IP.String()
			p.resolver.ForceHistory(ipStr, host)
			p.log.Debug("[TCP] history set", zap.String("ip", ipStr), zap.String("domain", host))
		}

		ips, err := p.resolver.LookupIPs(context.Background(), host)
		if err != nil || len(ips) == 0 {
			p.log.Debug("[TCP] DNS fail", zap.String("client", id), zap.Error(err))
			setReason("dns_fail")
			return
		}

		up, err = dialFirstAlive(context.Background(), ips, p.keepAlive)
		if err != nil {
			p.log.Debug("[TCP] dial fail", zap.String("client", id), zap.Error(err))
			setReason("dial_fail")
			return
		}
		defer up.Close()

		// Отправляем HTTP-запрос на upstream
		for _, line := range reqHeaders {
			if _, err := up.Write([]byte(line + "\r\n")); err != nil {
				p.log.Debug("[TCP] write HTTP request fail", zap.String("client", id), zap.Error(err))
				setReason("write_http_request_fail")
				return
			}
		}
		if _, err := up.Write([]byte("\r\n")); err != nil {
			p.log.Debug("[TCP] write HTTP request end fail", zap.String("client", id), zap.Error(err))
			setReason("write_http_request_end_fail")
			return
		}

		// Читаем HTTP-ответ
		upR := bufio.NewReader(up)
		respHeaders, err := readHTTPHeaders(upR)
		if err != nil {
			p.log.Debug("[TCP] HTTP response fail", zap.String("client", id), zap.Error(err))
			setReason("http_response_fail")
			return
		}

		// Отдаём клиенту HTTP-ответ (может быть 101 Switching Protocols)
		for _, line := range respHeaders {
			if _, err := cli.Write([]byte(line + "\r\n")); err != nil {
				p.log.Debug("[TCP] write HTTP response fail", zap.String("client", id), zap.Error(err))
				setReason("write_http_response_fail")
				return
			}
		}
		if _, err := cli.Write([]byte("\r\n")); err != nil {
			p.log.Debug("[TCP] write HTTP response end fail", zap.String("client", id), zap.Error(err))
			setReason("write_http_response_end_fail")
			return
		}

	}

	// --- Теперь bidirectional data copy (TCP<->upstream)
	resetDeadline := func() {
		if p.keepAlive <= 0 {
			_ = cli.SetDeadline(time.Time{})
			_ = up.SetDeadline(time.Time{})
			return
		}
		d := time.Now().Add(p.keepAlive)
		_ = cli.SetDeadline(d)
		_ = up.SetDeadline(d)
	}
	resetDeadline()

	var wg sync.WaitGroup
	wg.Add(2)

	cp := func(dst net.Conn, src net.Conn, wg *sync.WaitGroup) {
		defer wg.Done()
		defer func() { setReason("client_disconnect") }()
		buf := bufPool.Get().([]byte)
		defer bufPool.Put(buf)

		for {
			n, err := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					setReason("write_error")
					return
				}
				resetDeadline()
			}
			if err != nil {
				if err != io.EOF {
					setReason("read_error")
				} else {
					setReason("client_disconnect")
				}
				return
			}
		}
	}

	go cp(up, cli, &wg)
	go cp(cli, up, &wg)
	wg.Wait()

	p.log.Info("[TCP] finished",
		zap.String("client", id),
		zap.Duration("dur", time.Since(start)),
		zap.String("reason", reason))
}

/* -------------------------------------------------------------------------- */
/*                                Helpers                                     */
/* -------------------------------------------------------------------------- */

func readClientHello(r io.Reader) (string, string, []byte, error) {
	h := make([]byte, 5)
	if _, err := io.ReadFull(r, h); err != nil {
		return "", "", nil, err
	}
	if h[0] != 0x16 { // not TLS Handshake
		return "", "", nil, errors.New("not TLS")
	}
	l := int(h[3])<<8 | int(h[4])
	b := make([]byte, l)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", "", nil, err
	}
	buf := make([]byte, 0, len(h)+len(b))
	buf = append(buf, h...)
	buf = append(buf, b...)

	ch := utls.UnmarshalClientHello(b)
	alpn := ""
	sni := ""
	if ch != nil {
		sni = ch.ServerName
		if len(ch.AlpnProtocols) > 0 {
			alpn = ch.AlpnProtocols[0]
		}
	}
	if sni == "" {
		return "", alpn, buf, errors.New("no SNI")
	}
	return sni, alpn, buf, nil
}

func readHTTPHeaders(r *bufio.Reader) ([]string, error) {
	var headers []string
	maxHeaders := 100  // Максимальное количество строк заголовков
	maxLineLen := 8192 // Максимальная длина одной строки (8KB)
	for i := 0; i < maxHeaders; i++ {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if len(line) > maxLineLen {
			return nil, errors.New("header line too long")
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		headers = append(headers, line)
	}
	if len(headers) >= maxHeaders {
		return nil, errors.New("too many headers")
	}
	return headers, nil
}

func getHostFromHeaders(headers []string) (string, bool) {
	for _, h := range headers {
		if strings.HasPrefix(strings.ToLower(h), "host:") {
			host := strings.TrimSpace(h[5:])
			return host, true
		}
	}
	return "", false
}

func dialFirstAlive(ctx context.Context, ips []net.IP, ka time.Duration) (net.Conn, error) {
	type dialResult struct {
		conn net.Conn
		err  error
	}
	results := make(chan dialResult, len(ips))
	d := &net.Dialer{KeepAlive: ka}

	for _, ip := range ips {
		go func(ip net.IP) {
			cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			conn, err := d.DialContext(cctx, "tcp", net.JoinHostPort(ip.String(), "443"))
			results <- dialResult{conn, err}
		}(ip)
	}

	for range ips {
		select {
		case res := <-results:
			if res.err == nil {
				return res.conn, nil
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, errors.New("all IPs failed")
}

/* -------------------------------------------------------------------------- */
/*                       Cleanup Goroutine for ipSem                          */
/* -------------------------------------------------------------------------- */

func (p *TCPProxy) gcIPSem() {
	go func() {
		t := time.NewTicker(30 * time.Minute)
		for range t.C {
			p.ipSem.Range(func(k, v any) bool {
				ch := v.(chan struct{})
				if len(ch) == 0 {
					p.ipSem.Delete(k)
				}
				return true
			})
		}
	}()
}
