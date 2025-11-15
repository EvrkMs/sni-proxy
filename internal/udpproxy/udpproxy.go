package udpproxy

import (
	"bytes"
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
		ClientTTL:    0,
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
	addr     net.UDPAddr
	domain   string
	alpn     string
	lastSeen time.Time
}

type connBinding struct {
	addr     net.UDPAddr
	addrKey  string
	isClient bool
	id       []byte
}

type clientRegistry struct {
	mu     sync.RWMutex
	byAddr map[string]clientInfo
	byConn map[string]connBinding
}

func newClientRegistry() *clientRegistry {
	return &clientRegistry{
		byAddr: make(map[string]clientInfo),
		byConn: make(map[string]connBinding),
	}
}

func (r *clientRegistry) upsert(addr *net.UDPAddr, domain, alpn string) {
	if addr == nil {
		return
	}
	key := addr.String()
	r.mu.Lock()
	info := r.byAddr[key]
	info.addr = cloneUDPAddrValue(addr)
	if domain != "" {
		info.domain = domain
	}
	if alpn != "" {
		info.alpn = alpn
	}
	info.lastSeen = time.Now()
	r.byAddr[key] = info
	r.mu.Unlock()
}

func (r *clientRegistry) linkConnID(id []byte, addr *net.UDPAddr, isClient bool) {
	if len(id) == 0 || addr == nil {
		return
	}
	r.upsert(addr, "", "")
	key := hex.EncodeToString(id)
	addrKey := addr.String()
	addrCopy := cloneUDPAddrValue(addr)
	r.mu.Lock()
	existing, ok := r.byConn[key]
	if ok && existing.isClient != isClient {
		r.mu.Unlock()
		return
	}
	if !ok || len(existing.id) == 0 {
		existing.id = append([]byte(nil), id...)
	}
	existing.addr = addrCopy
	existing.addrKey = addrKey
	existing.isClient = isClient
	r.byConn[key] = existing
	r.mu.Unlock()
}

func (r *clientRegistry) getByConnIDHex(id string) (clientInfo, bool, bool) {
	r.mu.RLock()
	binding, ok := r.byConn[id]
	if !ok {
		r.mu.RUnlock()
		return clientInfo{}, false, false
	}
	info, ok := r.byAddr[binding.addrKey]
	r.mu.RUnlock()
	return info, ok, binding.isClient
}

func (r *clientRegistry) getByConnIDBytes(id []byte) (clientInfo, bool, bool) {
	if len(id) == 0 {
		return clientInfo{}, false, false
	}
	return r.getByConnIDHex(hex.EncodeToString(id))
}

func (r *clientRegistry) matchByCIDPrefix(payload []byte) (clientInfo, bool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var (
		bestInfo     clientInfo
		bestFound    bool
		bestIsClient bool
		bestLen      = -1
	)
	for _, binding := range r.byConn {
		if len(binding.id) == 0 || len(payload) < len(binding.id) {
			continue
		}
		if !bytes.Equal(binding.id, payload[:len(binding.id)]) {
			continue
		}
		info, ok := r.byAddr[binding.addrKey]
		if !ok {
			continue
		}
		if len(binding.id) > bestLen {
			bestInfo = info
			bestFound = true
			bestIsClient = binding.isClient
			bestLen = len(binding.id)
		}
	}
	return bestInfo, bestFound, bestIsClient
}

func (r *clientRegistry) getByAddr(addr *net.UDPAddr) (clientInfo, bool) {
	if addr == nil {
		return clientInfo{}, false
	}
	r.mu.RLock()
	info, ok := r.byAddr[addr.String()]
	r.mu.RUnlock()
	return info, ok
}

func (r *clientRegistry) touch(addr *net.UDPAddr) bool {
	if addr == nil {
		return false
	}
	key := addr.String()
	r.mu.Lock()
	info, ok := r.byAddr[key]
	if ok {
		info.lastSeen = time.Now()
		r.byAddr[key] = info
	}
	r.mu.Unlock()
	return ok
}

func (r *clientRegistry) snapshot() []clientInfo {
	r.mu.RLock()
	out := make([]clientInfo, 0, len(r.byAddr))
	for _, info := range r.byAddr {
		out = append(out, info)
	}
	r.mu.RUnlock()
	return out
}

func (r *clientRegistry) cleanup(ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	cutoff := time.Now().Add(-ttl)
	r.mu.Lock()
	for key, info := range r.byAddr {
		if info.lastSeen.Before(cutoff) {
			delete(r.byAddr, key)
		}
	}
	for id, binding := range r.byConn {
		if info, ok := r.byAddr[binding.addrKey]; !ok || info.lastSeen.Before(cutoff) {
			delete(r.byConn, id)
		}
	}
	r.mu.Unlock()
}

// Resolver определяет интерфейс для разрешения DNS
type Resolver interface {
	LookupCachedIP(fqdn string) (net.IP, error)
	GetLastKnownDomain(ip string) string
}

// === Экспортируемые метрики Prometheus ===
var (
	UDPActiveConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "udp_active_connections",
		Help: "Current number of active UDP connections",
	})
	UDPPacketErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "udp_packet_errors_total",
		Help: "Total number of UDP packet errors",
	}, []string{"type"})
)

func init() {
	prometheus.MustRegister(UDPActiveConnections, UDPPacketErrors)
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
	clients    *clientRegistry
	upstreamMu sync.RWMutex
	upstream   map[string]upstreamInfo
	bufPool    sync.Pool
	quit       chan struct{}
}

type upstreamInfo struct {
	addr     *net.UDPAddr
	lastSeen time.Time
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
		clients:  newClientRegistry(),
		upstream: make(map[string]upstreamInfo),
		bufPool:  sync.Pool{New: func() any { return make([]byte, 65535) }},
		quit:     make(chan struct{}),
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
				UDPPacketErrors.WithLabelValues("read").Inc()
				p.log.Error("[UDP] read error", zap.String("addr", conn.LocalAddr().String()), zap.Error(err))
				p.bufPool.Put(buf)
				continue
			}
			UDPActiveConnections.Inc()
			go func(buf []byte, n int, addr *net.UDPAddr) {
				defer UDPActiveConnections.Dec()
				defer p.bufPool.Put(buf)
				p.handlePacket(conn, addr, buf[:n])
			}(buf, n, addr)
		}
	}
}

func (p *Proxy) handlePacket(conn *net.UDPConn, addr *net.UDPAddr, data []byte) {
	if up := p.determineDestination(addr, data); up != nil {
		if _, err := conn.WriteToUDP(data, up); err != nil {
			UDPPacketErrors.WithLabelValues("write").Inc()
			p.log.Warn("[UDP] write error", zap.String("to", up.String()), zap.Error(err))
		}
		return
	}

	if p.clients.touch(addr) {
		p.broadcastToUpstreams(conn, addr, data)
		return
	}

	p.broadcastToClients(conn, addr, data)
}

func (p *Proxy) broadcastToUpstreams(conn *net.UDPConn, addr *net.UDPAddr, data []byte) {
	p.upstreamMu.Lock()
	defer p.upstreamMu.Unlock()
	for _, up := range p.upstream {
		if addr != nil && up.addr.IP.Equal(addr.IP) && up.addr.Port == addr.Port {
			continue
		}
		if _, err := conn.WriteToUDP(data, up.addr); err != nil {
			UDPPacketErrors.WithLabelValues("write").Inc()
			p.log.Debug("[UDP] broadcast write error", zap.String("to", up.addr.String()), zap.Error(err))
		}
	}
}

func (p *Proxy) broadcastToClients(conn *net.UDPConn, addr *net.UDPAddr, data []byte) {
	for _, info := range p.clients.snapshot() {
		if addr != nil && addr.IP.Equal(info.addr.IP) && addr.Port == info.addr.Port {
			continue
		}
		dst := info.addr
		dstPtr := &dst
		if _, err := conn.WriteToUDP(data, dstPtr); err != nil {
			UDPPacketErrors.WithLabelValues("write").Inc()
			p.log.Debug("[UDP] broadcast write error", zap.String("to", dstPtr.String()), zap.Error(err))
		}
	}
}

func cloneUDPAddrValue(addr *net.UDPAddr) net.UDPAddr {
	if addr == nil {
		return net.UDPAddr{}
	}
	ip := make(net.IP, len(addr.IP))
	copy(ip, addr.IP)
	return net.UDPAddr{
		IP:   ip,
		Port: addr.Port,
		Zone: addr.Zone,
	}
}

func cloneUDPAddrPtr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	cp := cloneUDPAddrValue(addr)
	return &cp
}

func addrValueToPtr(v net.UDPAddr) *net.UDPAddr {
	ip := make(net.IP, len(v.IP))
	copy(ip, v.IP)
	return &net.UDPAddr{
		IP:   ip,
		Port: v.Port,
		Zone: v.Zone,
	}
}

func (p *Proxy) trackUpstream(addr *net.UDPAddr) {
	if addr == nil {
		return
	}
	p.upstreamMu.Lock()
	p.upstream[addr.String()] = upstreamInfo{
		addr:     cloneUDPAddrPtr(addr),
		lastSeen: time.Now(),
	}
	p.upstreamMu.Unlock()
}

func (p *Proxy) isUpstreamAddr(addr *net.UDPAddr) bool {
	if addr == nil {
		return false
	}
	p.upstreamMu.RLock()
	_, ok := p.upstream[addr.String()]
	p.upstreamMu.RUnlock()
	return ok
}

func (p *Proxy) routeByConnID(id []byte) *net.UDPAddr {
	info, ok, ownerIsClient := p.clients.getByConnIDBytes(id)
	if !ok {
		return nil
	}
	dest := addrValueToPtr(info.addr)
	if ownerIsClient {
		p.clients.touch(dest)
	} else {
		p.trackUpstream(dest)
	}
	return dest
}

func (p *Proxy) routeShortHeader(payload []byte) *net.UDPAddr {
	if len(payload) == 0 {
		return nil
	}
	info, ok, ownerIsClient := p.clients.matchByCIDPrefix(payload)
	if !ok {
		return nil
	}
	dest := addrValueToPtr(info.addr)
	if ownerIsClient {
		p.clients.touch(dest)
	} else {
		p.trackUpstream(dest)
	}
	return dest
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
			if p.cfg.ClientTTL > 0 {
				p.clients.cleanup(p.cfg.ClientTTL)
			}
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
			if p.cfg.ClientTTL > 0 {
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
}

func portFromALPN(alpn string) int {
	if strings.HasPrefix(strings.ToLower(alpn), "doq") {
		return DefaultConfig().DoQPort
	}
	return 443
}

func (p *Proxy) determineDestination(addr *net.UDPAddr, data []byte) *net.UDPAddr {
	fromClient := !p.isUpstreamAddr(addr)
	if fromClient {
		p.clients.touch(addr)
	} else {
		p.trackUpstream(addr)
	}

	if isQUICLongHeader(data) {
		dcid, scid, err := extractConnectionIDs(data, p.log)
		if err == nil && (len(dcid) > 0 || len(scid) > 0) {
			if dest := p.routeByConnID(dcid); dest != nil {
				return dest
			}
			if len(scid) > 0 {
				p.clients.linkConnID(scid, addr, fromClient)
			}
			if fromClient && len(dcid) > 0 {
				p.clients.linkConnID(dcid, addr, true)
			}

			if isQUICInitial(data) && fromClient && len(dcid) > 0 {
				p.sniffInitial(dcid, addr, data)
			}

			if fromClient {
				domain := ""
				alpn := ""
				if info, ok, ownerIsClient := p.clients.getByConnIDBytes(dcid); ok && ownerIsClient {
					domain = info.domain
					alpn = info.alpn
				}
				if domain == "" {
					if info, ok, ownerIsClient := p.clients.getByConnIDBytes(scid); ok && ownerIsClient {
						domain = info.domain
						if alpn == "" {
							alpn = info.alpn
						}
					}
				}

				if domain != "" {
					if upIP, err := p.resolver.LookupCachedIP(domain); err == nil && upIP != nil {
						port := portFromALPN(alpn)
						upAddr := &net.UDPAddr{IP: upIP, Port: port}
						p.trackUpstream(upAddr)
						return upAddr
					}
				}
			}
		}
	}

	if isQUICShortHeader(data) {
		if dest := p.routeShortHeader(data[1:]); dest != nil {
			return dest
		}
	}

	if isDTLSClientHello(data) && fromClient {
		if sni, ok := p.feedDTLS(addr, data); ok {
			p.clients.upsert(addr, sni, "")
			if upIP, err := p.resolver.LookupCachedIP(sni); err == nil && upIP != nil {
				port := 443
				if info, ok := p.clients.getByAddr(addr); ok {
					port = portFromALPN(info.alpn)
				}
				upAddr := &net.UDPAddr{IP: upIP, Port: port}
				p.trackUpstream(upAddr)
				return upAddr
			}
		}
	}

	return nil
}
