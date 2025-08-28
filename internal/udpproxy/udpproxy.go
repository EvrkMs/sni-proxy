package udpproxy

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

// Config определяет настраиваемые параметры прокси
type Config struct {
	MaxSniffPkts int
	SniffTTL     time.Duration
	DTLSTTL      time.Duration
	ClientTTL    time.Duration
	DoQPort      int
}

// DefaultConfig возвращает конфигурацию по умолчанию
func DefaultConfig() Config {
	return Config{
		MaxSniffPkts: 8,
		SniffTTL:     3 * time.Second,
		DTLSTTL:      2 * time.Second,
		ClientTTL:    10 * time.Minute,
		DoQPort:      8853,
	}
}

type peekBuf struct {
	pkts    [][]byte
	created time.Time
}

type dtlsBuf struct {
	header         []byte
	totalLen       int
	messageBodyLen int
	frags          map[int][]byte
	created        time.Time
}

// clientInfo объединяет данные клиента для упрощения синхронизации
type clientInfo struct {
	addr     *net.UDPAddr
	domain   string
	alpn     string
	lastSeen time.Time
}

// Resolver определяет интерфейс для разрешения DNS
type Resolver interface {
	LookupCachedIP(fqdn string) (net.IP, error)
	GetLastKnownDomain(ip string) string
}

// Метрики Prometheus
var (
	activeConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "udp_active_connections",
		Help: "Current number of active UDP connections",
	})
	packetErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "udp_packet_errors_total",
		Help: "Total number of UDP packet errors",
	}, []string{"type"})
)

func init() {
	prometheus.MustRegister(activeConnections, packetErrors)
}

type Proxy struct {
	resolver   Resolver
	log        *zap.Logger
	cfg        Config
	conns      []*net.UDPConn
	unknownMu  sync.Mutex
	unknown    map[string]*peekBuf
	dtlsMu     sync.Mutex
	dtls       map[string]*dtlsBuf
	clients    sync.Map // map[string]*clientInfo
	upstreamMu sync.Mutex
	upstream   map[string]struct {
		addr     *net.UDPAddr
		lastSeen time.Time
	}
	bufPool     sync.Pool
	quit        chan struct{}
	cleanupOnce sync.Once
}

func NewProxy(listen string, res Resolver, log *zap.Logger, cfg Config) (*Proxy, error) {
	var conns []*net.UDPConn
	for _, nw := range []string{"udp4", "udp6"} {
		addr, err := net.ResolveUDPAddr(nw, listen)
		if err != nil {
			log.Warn("[UDP] resolve failed", zap.String("net", nw), zap.String("addr", listen), zap.Error(err))
			continue
		}
		c, err := net.ListenUDP(nw, addr)
		if err != nil {
			log.Warn("[UDP] listen failed", zap.String("net", nw), zap.String("addr", listen), zap.Error(err))
			continue
		}
		conns = append(conns, c)
		log.Info("[UDP] listening", zap.String("net", nw), zap.String("addr", listen))
	}
	if len(conns) == 0 {
		return nil, fmt.Errorf("no UDP listeners on %s", listen)
	}

	p := &Proxy{
		resolver: res,
		log:      log,
		cfg:      cfg,
		conns:    conns,
		unknown:  make(map[string]*peekBuf),
		dtls:     make(map[string]*dtlsBuf),
		upstream: make(map[string]struct {
			addr     *net.UDPAddr
			lastSeen time.Time
		}),
		bufPool: sync.Pool{New: func() any { return make([]byte, 65535) }},
		quit:    make(chan struct{}),
	}

	go p.cleanupLoop()
	return p, nil
}

func (p *Proxy) Listen() {
	for _, c := range p.conns {
		go p.listenLoop(c)
	}
	p.log.Info("[UDP] proxy started")
}

func (p *Proxy) listenLoop(conn *net.UDPConn) {
	for {
		select {
		case <-p.quit:
			return
		default:
			buf := p.bufPool.Get().([]byte)
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					p.bufPool.Put(buf)
					return
				}
				packetErrors.WithLabelValues("read").Inc()
				p.log.Error("[UDP] read error", zap.String("addr", conn.LocalAddr().String()), zap.Error(err))
				p.bufPool.Put(buf)
				continue
			}
			activeConnections.Inc()
			go func(data []byte, addr *net.UDPAddr) {
				defer activeConnections.Dec()
				p.handlePacket(conn, addr, data[:n])
				p.bufPool.Put(buf)
			}(buf[:n], addr)
		}
	}
}

func (p *Proxy) handlePacket(conn *net.UDPConn, addr *net.UDPAddr, data []byte) {
	if up := p.determineDestination(addr, data); up != nil {
		if _, err := conn.WriteToUDP(data, up); err != nil {
			packetErrors.WithLabelValues("write").Inc()
			p.log.Warn("[UDP] write error", zap.String("to", up.String()), zap.Error(err))
		}
		return
	}

	if p.isKnownClient(addr) {
		p.upstreamMu.Lock()
		for _, up := range p.upstream {
			if up.addr.IP.Equal(addr.IP) && up.addr.Port == addr.Port {
				continue
			}
			if _, err := conn.WriteToUDP(data, up.addr); err != nil {
				packetErrors.WithLabelValues("write").Inc()
				p.log.Debug("[UDP] broadcast write error", zap.String("to", up.addr.String()), zap.Error(err))
			}
		}
		p.upstreamMu.Unlock()
	} else {
		p.clients.Range(func(_, v interface{}) bool {
			info := v.(*clientInfo)
			if info.addr.IP.Equal(addr.IP) && info.addr.Port == addr.Port {
				return true
			}
			if _, err := conn.WriteToUDP(data, info.addr); err != nil {
				packetErrors.WithLabelValues("write").Inc()
				p.log.Debug("[UDP] broadcast write error", zap.String("to", info.addr.String()), zap.Error(err))
			}
			return true
		})
	}
}

func (p *Proxy) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-p.quit:
			return
		case <-ticker.C:
			now := time.Now()
			p.clients.Range(func(k, v interface{}) bool {
				info := v.(*clientInfo)
				if now.Sub(info.lastSeen) > p.cfg.ClientTTL {
					p.clients.Delete(k)
				}
				return true
			})
			p.unknownMu.Lock()
			for key, buf := range p.unknown {
				if now.Sub(buf.created) > p.cfg.SniffTTL {
					delete(p.unknown, key)
				}
			}
			p.unknownMu.Unlock()
			p.dtlsMu.Lock()
			for key, buf := range p.dtls {
				if now.Sub(buf.created) > p.cfg.DTLSTTL {
					delete(p.dtls, key)
				}
			}
			p.dtlsMu.Unlock()
			p.upstreamMu.Lock()
			for addr, up := range p.upstream {
				if now.Sub(up.lastSeen) > p.cfg.ClientTTL {
					delete(p.upstream, addr)
				}
			}
			p.upstreamMu.Unlock()
		}
	}
}

func (p *Proxy) isKnownClient(a *net.UDPAddr) bool {
	known := false
	p.clients.Range(func(_, v interface{}) bool {
		info := v.(*clientInfo)
		if a.IP.Equal(info.addr.IP) && a.Port == info.addr.Port {
			known = true
			return false
		}
		return true
	})
	return known
}

func (p *Proxy) getALPN(key string) string {
	if v, ok := p.clients.Load(key); ok {
		return v.(*clientInfo).alpn
	}
	return ""
}

func portFromALPN(alpn string) int {
	if strings.HasPrefix(strings.ToLower(alpn), "doq") {
		return DefaultConfig().DoQPort
	}
	return 443
}

func (p *Proxy) determineDestination(addr *net.UDPAddr, data []byte) *net.UDPAddr {
	cliKey := addr.String()

	if isQUIC(data) {
		dcid, scid, err := extractConnectionIDs(data, p.log)
		if err == nil && (len(dcid) > 0 || len(scid) > 0) {
			dcidHex := hex.EncodeToString(dcid)
			scidHex := hex.EncodeToString(scid)

			var infoD, infoS *clientInfo
			var okD, okS bool
			if dcidHex != "" {
				if v, ok := p.clients.Load(dcidHex); ok {
					infoD = v.(*clientInfo)
					okD = true
				}
			}
			if scidHex != "" {
				if v, ok := p.clients.Load(scidHex); ok {
					infoS = v.(*clientInfo)
					okS = true
				}
			}

			fromClient := false
			if okD && addr.IP.Equal(infoD.addr.IP) && addr.Port == infoD.addr.Port {
				fromClient = true
			}
			if okS && addr.IP.Equal(infoS.addr.IP) && addr.Port == infoS.addr.Port {
				fromClient = true
			}

			if !fromClient {
				p.upstreamMu.Lock()
				p.upstream[addr.String()] = struct {
					addr     *net.UDPAddr
					lastSeen time.Time
				}{addr, time.Now()}
				p.upstreamMu.Unlock()

				if infoD != nil || infoS != nil {
					info := infoD
					key := dcidHex
					if !okD {
						info = infoS
						key = scidHex
					}
					p.clients.Store(key, &clientInfo{
						addr:     info.addr,
						domain:   info.domain,
						alpn:     info.alpn,
						lastSeen: time.Now(),
					})
					return info.addr
				}
			}

			if isQUICInitial(data) {
				if dcidHex != "" {
					p.clients.Store(dcidHex, &clientInfo{
						addr:     addr,
						domain:   "",
						alpn:     "",
						lastSeen: time.Now(),
					})
				}
				if scidHex != "" {
					p.clients.Store(scidHex, &clientInfo{
						addr:     addr,
						domain:   "",
						alpn:     "",
						lastSeen: time.Now(),
					})
				}
				if dcidHex != "" {
					p.sniffInitial(dcidHex, addr, data)
				}
				if dcidHex != "" && scidHex != "" {
					if v, ok := p.clients.Load(dcidHex); ok {
						info := v.(*clientInfo)
						if info.domain != "" {
							p.clients.Store(scidHex, &clientInfo{
								addr:     addr,
								domain:   info.domain,
								alpn:     info.alpn,
								lastSeen: time.Now(),
							})
						}
					}
				}
			}

			var domain string
			if dcidHex != "" {
				if v, ok := p.clients.Load(dcidHex); ok {
					domain = v.(*clientInfo).domain
				}
			}
			if domain == "" && scidHex != "" {
				if v, ok := p.clients.Load(scidHex); ok {
					domain = v.(*clientInfo).domain
				}
			}

			if domain != "" {
				if upIP, err := p.resolver.LookupCachedIP(domain); err == nil && upIP != nil {
					port := 443
					if dcidHex != "" {
						port = portFromALPN(p.getALPN(dcidHex))
					}
					if port == 443 && scidHex != "" {
						if alt := p.getALPN(scidHex); alt != "" {
							port = portFromALPN(alt)
						}
					}
					upAddr := &net.UDPAddr{IP: upIP, Port: port}
					p.upstreamMu.Lock()
					p.upstream[upAddr.String()] = struct {
						addr     *net.UDPAddr
						lastSeen time.Time
					}{upAddr, time.Now()}
					p.upstreamMu.Unlock()
					return upAddr
				}
			}
		}
	}

	if isDTLSClientHello(data) {
		if sni, ok := p.feedDTLS(addr, data); ok {
			p.clients.Store(cliKey, &clientInfo{
				addr:     addr,
				domain:   sni,
				alpn:     "",
				lastSeen: time.Now(),
			})
			if upIP, err := p.resolver.LookupCachedIP(sni); err == nil && upIP != nil {
				port := portFromALPN(p.getALPN(cliKey))
				upAddr := &net.UDPAddr{IP: upIP, Port: port}
				p.upstreamMu.Lock()
				p.upstream[upAddr.String()] = struct {
					addr     *net.UDPAddr
					lastSeen time.Time
				}{upAddr, time.Now()}
				p.upstreamMu.Unlock()
				return upAddr
			}
		}
	}

	last := p.resolver.GetLastKnownDomain(cliKey)
	if last == "discord.com" {
		last = "gateway.discord.gg"
	}
	if last != "" {
		if upIP, err := p.resolver.LookupCachedIP(last); err == nil && upIP != nil {
			port := portFromALPN(p.getALPN(cliKey))
			upAddr := &net.UDPAddr{IP: upIP, Port: port}
			p.upstreamMu.Lock()
			p.upstream[upAddr.String()] = struct {
				addr     *net.UDPAddr
				lastSeen time.Time
			}{upAddr, time.Now()}
			p.upstreamMu.Unlock()
			return upAddr
		}
	}

	return nil
}
