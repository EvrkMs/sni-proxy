package proxy

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"github.com/cuonglm/quicsni"

	"sni-proxy/internal/resolver"
	"sni-proxy/internal/sniff"
	"sni-proxy/internal/upstream"
)

const (
	udpSessionIdle   = 90 * time.Second
	udpSessionMax    = 4096
	udpReadBufSize   = 2048
)

// UDPTunnel proxies UDP/QUIC datagrams through a SOCKS5 UDP ASSOCIATE
// when the upstream supports it. Routing is based on SNI extracted from
// the QUIC Initial packet.
type UDPTunnel struct {
	resolver resolver.Resolver
	dialer   upstream.UDPCapableDialer

	mu       sync.Mutex
	sessions map[string]*udpSession // key = client UDP addr string
}

type udpSession struct {
	client     net.Addr
	target     *net.UDPAddr
	host       string // original SNI for logs
	socks      net.PacketConn
	lastActive time.Time
	closed     bool
}

func NewUDPTunnel(res resolver.Resolver, dialer upstream.UDPCapableDialer) *UDPTunnel {
	t := &UDPTunnel{
		resolver: res,
		dialer:   dialer,
		sessions: make(map[string]*udpSession),
	}
	go t.reaper()
	return t
}

// Serve listens on the given PacketConn and proxies datagrams.
// Blocks until the conn is closed.
func (t *UDPTunnel) Serve(conn net.PacketConn) {
	buf := make([]byte, udpReadBufSize)
	for {
		n, client, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go t.handlePacket(conn, client, pkt)
	}
}

func (t *UDPTunnel) handlePacket(local net.PacketConn, client net.Addr, pkt []byte) {
	key := client.String()

	t.mu.Lock()
	sess, ok := t.sessions[key]
	if ok && !sess.closed {
		sess.lastActive = time.Now()
		t.mu.Unlock()
		// Already have a session — just forward.
		if _, err := sess.socks.WriteTo(pkt, sess.target); err != nil {
			log.Printf("[warn] UDP forward %s -> %s: %v", client, sess.host, err)
			t.closeSession(key)
		}
		return
	}
	t.mu.Unlock()

	// New flow: only accept QUIC long-header (Initial) so we can extract SNI.
	hdr, err := sniff.ParseQUICLongHeader(pkt)
	if err != nil {
		return // drop non-QUIC / short-header
	}

	chi, err := quicsni.ReadClientHello(pkt)
	if err != nil || chi == nil || chi.ServerName == "" {
		// Cannot route without SNI — send Version Negotiation so client falls back to TCP.
		vn := sniff.BuildVersionNegotiation(hdr)
		if _, werr := local.WriteTo(vn, client); werr != nil {
			log.Printf("[warn] QUIC VN write to %s: %v", client, werr)
		}
		return
	}
	sni := chi.ServerName

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	ip, err := t.resolver.Resolve(ctx, sni)
	cancel()
	if err != nil {
		log.Printf("[warn] UDP DoH resolve %q: %v", sni, err)
		vn := sniff.BuildVersionNegotiation(hdr)
		_, _ = local.WriteTo(vn, client)
		return
	}

	target, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip, "443"))
	if err != nil {
		log.Printf("[warn] UDP resolve addr %s: %v", ip, err)
		return
	}

	socksPC, err := t.dialer.ListenPacket()
	if err != nil {
		log.Printf("[warn] SOCKS UDP ASSOCIATE for %s: %v", sni, err)
		vn := sniff.BuildVersionNegotiation(hdr)
		_, _ = local.WriteTo(vn, client)
		return
	}

	sess = &udpSession{
		client:     client,
		target:     target,
		host:       sni,
		socks:      socksPC,
		lastActive: time.Now(),
	}

	t.mu.Lock()
	if len(t.sessions) >= udpSessionMax {
		t.mu.Unlock()
		_ = socksPC.Close()
		log.Printf("[warn] UDP session limit reached, dropping %s", client)
		return
	}
	// Race: another packet may have created the session.
	if existing, ok := t.sessions[key]; ok && !existing.closed {
		t.mu.Unlock()
		_ = socksPC.Close()
		_, _ = existing.socks.WriteTo(pkt, existing.target)
		return
	}
	t.sessions[key] = sess
	t.mu.Unlock()

	log.Printf("[info] [QUIC] open: %s <-> %s (%s)", client, sni, target)

	// Reverse path: SOCKS -> client
	go t.relayBack(local, sess, key)

	if _, err := sess.socks.WriteTo(pkt, sess.target); err != nil {
		log.Printf("[warn] UDP initial forward %s -> %s: %v", client, sni, err)
		t.closeSession(key)
	}
}

func (t *UDPTunnel) relayBack(local net.PacketConn, sess *udpSession, key string) {
	buf := make([]byte, 65535)
	for {
		_ = sess.socks.SetReadDeadline(time.Now().Add(udpSessionIdle))
		n, _, err := sess.socks.ReadFrom(buf)
		if err != nil {
			t.closeSession(key)
			return
		}
		t.mu.Lock()
		if sess.closed {
			t.mu.Unlock()
			return
		}
		sess.lastActive = time.Now()
		t.mu.Unlock()

		if _, err := local.WriteTo(buf[:n], sess.client); err != nil {
			t.closeSession(key)
			return
		}
	}
}

func (t *UDPTunnel) closeSession(key string) {
	t.mu.Lock()
	sess, ok := t.sessions[key]
	if !ok || sess.closed {
		t.mu.Unlock()
		return
	}
	sess.closed = true
	delete(t.sessions, key)
	t.mu.Unlock()
	_ = sess.socks.Close()
	log.Printf("[info] [QUIC] closed: %s <-> %s", sess.client, sess.host)
}

func (t *UDPTunnel) reaper() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-udpSessionIdle)
		t.mu.Lock()
		var stale []string
		for k, s := range t.sessions {
			if s.lastActive.Before(cutoff) {
				stale = append(stale, k)
			}
		}
		t.mu.Unlock()
		for _, k := range stale {
			t.closeSession(k)
		}
	}
}
