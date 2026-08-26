package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"sni-proxy/internal/config"
	"sni-proxy/internal/proxy"
	"sni-proxy/internal/sniff"
)

const udpReadBuf = 2048

type Server struct {
	config    config.Config
	tunnel    *proxy.Tunnel
	udpTunnel *proxy.UDPTunnel // nil => only QUIC rejector
}

func New(cfg config.Config, tunnel *proxy.Tunnel) *Server {
	return &Server{
		config: cfg,
		tunnel: tunnel,
	}
}

// SetUDPTunnel enables QUIC/UDP proxying through SOCKS when the upstream
// supports UDP ASSOCIATE. If nil, the server falls back to Version Negotiation.
func (s *Server) SetUDPTunnel(u *proxy.UDPTunnel) {
	s.udpTunnel = u
}

func (s *Server) StartAll() ([]net.Listener, error) {
	httpsListener, err := s.startListener(s.config.ListenHTTPS, "443", "HTTPS")
	if err != nil {
		return nil, err
	}

	httpListener, err := s.startListener(s.config.ListenHTTP, "80", "HTTP")
	if err != nil {
		_ = httpsListener.Close()
		return nil, err
	}

	return []net.Listener{httpsListener, httpListener}, nil
}

func (s *Server) startListener(addr, defaultPort, label string) (net.Listener, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("cannot listen on %s: %w", addr, err)
	}

	log.Printf("[info] %s listener ready on %s", label, addr)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Temporary() {
					continue
				}
				break
			}

			go s.handleConn(conn, defaultPort)
		}

		log.Printf("[info] %s listener stopped", label)
	}()

	return listener, nil
}

func (s *Server) handleConn(conn net.Conn, defaultPort string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	// Read the first byte to determine the protocol.
	first := make([]byte, 1)
	if _, err := io.ReadFull(conn, first); err != nil {
		log.Printf("[warn] initial read from %s: %v", conn.RemoteAddr(), err)
		return
	}

	var peek []byte

	if sniff.IsTLS(first) {
		// TLS: read the 4-byte remainder of the record header, then the full record body.
		// Record header: type(1) + version(2) + length(2) = 5 bytes total.
		hdr := make([]byte, 4)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			log.Printf("[warn] TLS header read from %s: %v", conn.RemoteAddr(), err)
			return
		}

		recordLen := int(binary.BigEndian.Uint16(hdr[2:4]))
		if recordLen > 16384+2048 { // max TLS record is 16 KiB; 2 KiB slack
			log.Printf("[warn] TLS record too large (%d) from %s", recordLen, conn.RemoteAddr())
			return
		}

		body := make([]byte, recordLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			log.Printf("[warn] TLS record body read from %s: %v", conn.RemoteAddr(), err)
			return
		}

		// Reassemble the complete record so tunnel can replay it verbatim.
		peek = make([]byte, 0, 1+4+recordLen)
		peek = append(peek, first[0])
		peek = append(peek, hdr...)
		peek = append(peek, body...)

		sni, err := sniff.ExtractSNI(peek)
		if err != nil {
			log.Printf("[warn] SNI from %s: %v", conn.RemoteAddr(), err)
			return
		}

		log.Printf("[info] %s -> TLS SNI=%q", conn.RemoteAddr(), sni)
		s.tunnel.Open(conn, peek, sni, "443", "TLS")
		return
	}

	// Plain HTTP: read the rest up to 4095 more bytes.
	rest := make([]byte, 4095)
	n, err := conn.Read(rest)
	if err != nil && n == 0 {
		log.Printf("[warn] initial read from %s: %v", conn.RemoteAddr(), err)
		return
	}
	peek = append(first, rest[:n]...)

	host, port, err := sniff.ExtractHTTPHost(peek)
	if err != nil {
		log.Printf("[warn] HTTP Host from %s: %v", conn.RemoteAddr(), err)
		return
	}

	upstreamPort := defaultPort
	if port != "" {
		upstreamPort = port
	}

	log.Printf("[info] %s -> HTTP Host=%q (upstream port %s)", conn.RemoteAddr(), host, upstreamPort)
	s.tunnel.Open(conn, peek, host, upstreamPort, "HTTP")
}

// readFullTLSRecord is a compile-time reminder that the logic above must stay in sync.
var _ = binary.BigEndian

// StartUDP starts the UDP handler on addr.
// If a UDPTunnel was set (SOCKS supports UDP), QUIC is proxied through SOCKS.
// Otherwise every QUIC Initial gets a Version Negotiation reply (TCP fallback).
func (s *Server) StartUDP(addr string) (net.PacketConn, error) {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("cannot listen UDP on %s: %w", addr, err)
	}

	if s.udpTunnel != nil {
		log.Printf("[info] QUIC/UDP proxy ready on UDP %s (via SOCKS UDP ASSOCIATE)", addr)
		go s.udpTunnel.Serve(conn)
		return conn, nil
	}

	log.Printf("[info] QUIC rejector ready on UDP %s", addr)
	go s.runQuicRejector(conn)
	return conn, nil
}

// StartUDPQuicRejector is kept for compatibility; prefer StartUDP.
func (s *Server) StartUDPQuicRejector(addr string) (net.PacketConn, error) {
	return s.StartUDP(addr)
}

func (s *Server) runQuicRejector(conn net.PacketConn) {
	buf := make([]byte, udpReadBuf)
	for {
		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}

		pkt := buf[:n]
		hdr, err := sniff.ParseQUICLongHeader(pkt)
		if err != nil {
			continue
		}

		vn := sniff.BuildVersionNegotiation(hdr)
		if _, err := conn.WriteTo(vn, src); err != nil {
			log.Printf("[warn] QUIC VN write to %s: %v", src, err)
		}
	}
	log.Printf("[info] QUIC rejector stopped")
}
