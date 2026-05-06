package proxy

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"sni-proxy/internal/resolver"
	"sni-proxy/internal/upstream"
)

type Tunnel struct {
	resolver resolver.Resolver
	dialer   upstream.Dialer
}

func NewTunnel(resolver resolver.Resolver, dialer upstream.Dialer) *Tunnel {
	return &Tunnel{
		resolver: resolver,
		dialer:   dialer,
	}
}

func (t *Tunnel) Open(conn net.Conn, peekBuf []byte, host, upstreamPort, label string) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	ip, err := t.resolver.Resolve(ctx, host)
	if err != nil {
		log.Printf("[warn] DoH resolve %q: %v", host, err)
		return
	}
	log.Printf("[info] DoH: %s -> %s", host, ip)

	target := net.JoinHostPort(ip, upstreamPort)
	upstreamConn, err := t.dialer.Dial("tcp", target)
	if err != nil {
		log.Printf("[warn] upstream dial %s (%s): %v", host, target, err)
		return
	}
	defer upstreamConn.Close()

	log.Printf("[info] [%s] open: %s <-> %s (%s)", label, conn.RemoteAddr(), host, target)

	_ = conn.SetDeadline(time.Time{})
	_ = upstreamConn.SetDeadline(time.Time{})

	if _, err := upstreamConn.Write(peekBuf); err != nil {
		log.Printf("[warn] replay to %s: %v", target, err)
		return
	}

	errCh := make(chan error, 2)
	var shutdownOnce sync.Once
	shutdown := func() {
		shutdownOnce.Do(func() {
			halfCloseWrite(upstreamConn)
			halfCloseRead(conn)
			halfCloseWrite(conn)
			halfCloseRead(upstreamConn)
			_ = conn.SetDeadline(time.Now())
			_ = upstreamConn.SetDeadline(time.Now())
			_ = conn.Close()
			_ = upstreamConn.Close()
		})
	}

	go proxyStream(errCh, upstreamConn, conn)
	go proxyStream(errCh, conn, upstreamConn)

	firstErr := <-errCh
	shutdown()
	secondErr := <-errCh

	if loggableCopyErr(firstErr) {
		log.Printf("[warn] [%s] stream %s <-> %s: %v", label, conn.RemoteAddr(), host, firstErr)
	}
	if loggableCopyErr(secondErr) {
		log.Printf("[warn] [%s] stream %s <-> %s: %v", label, conn.RemoteAddr(), host, secondErr)
	}

	log.Printf("[info] [%s] closed: %s <-> %s", label, conn.RemoteAddr(), host)
}

func proxyStream(errCh chan<- error, dst, src net.Conn) {
	_, err := io.Copy(dst, src)
	errCh <- err
}

func loggableCopyErr(err error) bool {
	return err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed)
}

type closeWriter interface {
	CloseWrite() error
}

type closeReader interface {
	CloseRead() error
}

func halfCloseWrite(conn net.Conn) {
	if c, ok := conn.(closeWriter); ok {
		_ = c.CloseWrite()
	}
}

func halfCloseRead(conn net.Conn) {
	if c, ok := conn.(closeReader); ok {
		_ = c.CloseRead()
	}
}
