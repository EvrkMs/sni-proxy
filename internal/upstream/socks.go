package upstream

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"sync/atomic"

	"golang.org/x/net/proxy"
)

// Dialer abstracts a TCP dialer for the tunnel layer.
type Dialer interface {
	Dial(network, address string) (net.Conn, error)
}

// SocksDialer tunnels TCP connections through a SOCKS5 proxy.
type SocksDialer struct {
	rawURL string
	d      proxy.Dialer
}

// NewSocksDialer creates a dialer from a SOCKS5 URL.
// Examples:
//
//	socks5://host:1080
//	socks5://user:pass@host:1080
func NewSocksDialer(rawURL string) (*SocksDialer, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse socks url %q: %w", rawURL, err)
	}
	d, err := proxy.FromURL(u, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("socks dialer from url %q: %w", rawURL, err)
	}
	return &SocksDialer{rawURL: rawURL, d: d}, nil
}

// Dial opens a TCP connection through the SOCKS5 proxy.
func (d *SocksDialer) Dial(network, address string) (net.Conn, error) {
	return d.d.Dial(network, address)
}

// ---------- SwappableDialer ----------

// SwappableDialer wraps a Dialer that can be replaced at runtime (hot-swap).
// All methods are safe for concurrent use.
type SwappableDialer struct {
	inner atomic.Pointer[SocksDialer]
}

// NewSwappableDialer creates a SwappableDialer with an initial delegate.
func NewSwappableDialer(initial *SocksDialer) *SwappableDialer {
	sd := &SwappableDialer{}
	sd.inner.Store(initial)
	return sd
}

// Swap replaces the underlying dialer with a new SOCKS5 URL.
// In-flight connections keep using the old dialer.
func (s *SwappableDialer) Swap(rawURL string) error {
	d, err := NewSocksDialer(rawURL)
	if err != nil {
		return err
	}
	s.inner.Store(d)
	log.Printf("[info] dialer swapped -> %s", rawURL)
	return nil
}

// Dial delegates to the current underlying SocksDialer.
func (s *SwappableDialer) Dial(network, address string) (net.Conn, error) {
	return s.inner.Load().Dial(network, address)
}
