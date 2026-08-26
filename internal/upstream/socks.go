package upstream

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

// Dialer abstracts a TCP dialer for the tunnel layer.
type Dialer interface {
	Dial(network, address string) (net.Conn, error)
}

// UDPCapableDialer is a Dialer that can also open UDP associations.
type UDPCapableDialer interface {
	Dialer
	// SupportsUDP reports whether the upstream accepted UDP ASSOCIATE.
	SupportsUDP() bool
	// ListenPacket establishes a SOCKS5 UDP ASSOCIATE and returns a
	// PacketConn that talks to the SOCKS UDP relay. The returned conn
	// must be closed when no longer needed; closing it also tears down
	// the control TCP connection that keeps the association alive.
	ListenPacket() (net.PacketConn, error)
}

// SocksDialer tunnels TCP (and optionally UDP) connections through a SOCKS5 proxy.
type SocksDialer struct {
	rawURL   string
	host     string // host:port of the SOCKS server
	user     string
	password string
	d        proxy.Dialer

	udpOnce     sync.Once
	udpOK       bool
	udpProbeErr error
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
	if u.Scheme != "socks5" && u.Scheme != "socks5h" {
		return nil, fmt.Errorf("unsupported scheme %q (want socks5 or socks5h)", u.Scheme)
	}
	host := u.Host
	if host == "" {
		return nil, fmt.Errorf("socks url %q has empty host", rawURL)
	}
	user, pass := "", ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	d, err := proxy.FromURL(u, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("socks dialer from url %q: %w", rawURL, err)
	}
	return &SocksDialer{
		rawURL:   rawURL,
		host:     host,
		user:     user,
		password: pass,
		d:        d,
	}, nil
}

// Dial opens a TCP connection through the SOCKS5 proxy.
func (d *SocksDialer) Dial(network, address string) (net.Conn, error) {
	return d.d.Dial(network, address)
}

// SupportsUDP probes the SOCKS5 server for UDP ASSOCIATE and caches the result.
// On transient network errors (e.g. "no route to host" right after container start
// on MikroTik) the probe is retried several times before giving up.
// Safe for concurrent use.
func (d *SocksDialer) SupportsUDP() bool {
	d.udpOnce.Do(func() {
		const attempts = 8
		var lastErr error
		for i := 1; i <= attempts; i++ {
			pc, err := d.ListenPacket()
			if err == nil {
				_ = pc.Close()
				d.udpOK = true
				d.udpProbeErr = nil
				log.Printf("[info] SOCKS UDP ASSOCIATE OK — UDP is available")
				return
			}
			lastErr = err
			// Retry only likely-transient dial/route errors; permanent SOCKS
			// rejections (REP != 0) are not worth spinning on.
			if !isTransientNetErr(err) {
				break
			}
			backoff := time.Duration(i) * 500 * time.Millisecond
			log.Printf("[info] SOCKS UDP probe attempt %d/%d failed: %v — retry in %s",
				i, attempts, err, backoff)
			time.Sleep(backoff)
		}
		d.udpProbeErr = lastErr
		d.udpOK = false
		log.Printf("[info] SOCKS UDP ASSOCIATE probe failed: %v (UDP unavailable)", lastErr)
	})
	return d.udpOK
}

func isTransientNetErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, s := range []string{
		"no route to host",
		"network is unreachable",
		"connection refused",
		"i/o timeout",
		"timed out",
		"temporary failure",
		"host is down",
		"connection reset",
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// UDPProbeError returns the error from the last UDP probe (if any).
func (d *SocksDialer) UDPProbeError() error {
	d.SupportsUDP() // ensure probe ran
	return d.udpProbeErr
}

// ListenPacket performs SOCKS5 UDP ASSOCIATE and returns a PacketConn
// that sends/receives datagrams via the proxy's UDP relay.
func (d *SocksDialer) ListenPacket() (net.PacketConn, error) {
	ctrl, err := net.DialTimeout("tcp", d.host, 8*time.Second)
	if err != nil {
		return nil, fmt.Errorf("socks tcp dial: %w", err)
	}
	_ = ctrl.SetDeadline(time.Now().Add(8 * time.Second))

	if err := socks5Handshake(ctrl, d.user, d.password); err != nil {
		_ = ctrl.Close()
		return nil, fmt.Errorf("socks handshake: %w", err)
	}

	relayAddr, err := socks5UDPAssociate(ctrl)
	if err != nil {
		_ = ctrl.Close()
		return nil, fmt.Errorf("socks udp associate: %w", err)
	}

	// Clear deadline on the control connection — it must stay open for the
	// lifetime of the association (RFC 1928 §7).
	_ = ctrl.SetDeadline(time.Time{})

	udpConn, err := net.ListenPacket("udp", "")
	if err != nil {
		_ = ctrl.Close()
		return nil, fmt.Errorf("local udp listen: %w", err)
	}

	pc := &socksUDPConn{
		PacketConn: udpConn,
		ctrl:       ctrl,
		relay:      relayAddr,
	}

	// When the control TCP dies, close the UDP side too.
	go func() {
		buf := make([]byte, 1)
		_, _ = ctrl.Read(buf) // blocks until EOF / error
		_ = udpConn.Close()
	}()

	return pc, nil
}

// ---------- SOCKS5 wire helpers ----------


func socksRepString(rep byte) string {
	switch rep {
	case 0x00:
		return "succeeded"
	case 0x01:
		return "general failure"
	case 0x02:
		return "not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported (UDP likely disabled on SOCKS inbound)"
	case 0x08:
		return "address type not supported"
	default:
		return fmt.Sprintf("unknown REP %d", rep)
	}
}

func socks5Handshake(conn net.Conn, user, password string) error {
	var methods []byte
	if user != "" {
		methods = []byte{0x05, 0x02, 0x00, 0x02} // NO AUTH + USER/PASS
	} else {
		methods = []byte{0x05, 0x01, 0x00} // NO AUTH only
	}
	if _, err := conn.Write(methods); err != nil {
		return err
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("bad version %d", resp[0])
	}

	switch resp[1] {
	case 0x00: // no auth
		return nil
	case 0x02: // username/password
		if user == "" {
			return fmt.Errorf("server requires username/password auth")
		}
		// RFC 1929
		req := []byte{0x01, byte(len(user))}
		req = append(req, []byte(user)...)
		req = append(req, byte(len(password)))
		req = append(req, []byte(password)...)
		if _, err := conn.Write(req); err != nil {
			return err
		}
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			return err
		}
		if authResp[1] != 0x00 {
			return fmt.Errorf("auth failed (status %d)", authResp[1])
		}
		return nil
	case 0xFF:
		return fmt.Errorf("no acceptable auth method")
	default:
		return fmt.Errorf("unsupported auth method %d", resp[1])
	}
}

// socks5UDPAssociate sends CMD=UDP ASSOCIATE and returns the relay UDP address.
func socks5UDPAssociate(conn net.Conn) (*net.UDPAddr, error) {
	// DST.ADDR / DST.PORT = 0.0.0.0:0 (client does not know its address yet)
	req := []byte{
		0x05, // VER
		0x03, // CMD = UDP ASSOCIATE
		0x00, // RSV
		0x01, // ATYP = IPv4
		0, 0, 0, 0,
		0, 0,
	}
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	// Reply: VER REP RSV ATYP BND.ADDR BND.PORT
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	if hdr[0] != 0x05 {
		return nil, fmt.Errorf("bad version %d", hdr[0])
	}
	if hdr[1] != 0x00 {
		return nil, fmt.Errorf("UDP ASSOCIATE rejected: %s (REP=%d)", socksRepString(hdr[1]), hdr[1])
	}

	var host string
	switch hdr[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, err
		}
		host = net.IP(addr).String()
	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, err
		}
		host = net.IP(addr).String()
	case 0x03: // domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, err
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return nil, err
		}
		host = string(domain)
	default:
		return nil, fmt.Errorf("unknown ATYP %d", hdr[3])
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, err
	}
	port := int(binary.BigEndian.Uint16(portBuf))

	// Some servers return 0.0.0.0 — replace with the SOCKS TCP peer address.
	if host == "0.0.0.0" || host == "::" {
		if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			host = ta.IP.String()
		}
	}

	return net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
}

// socksUDPConn wraps a local UDP socket and a SOCKS5 UDP relay address.
// Every WriteTo prepends the SOCKS5 UDP request header; ReadFrom strips it.
type socksUDPConn struct {
	net.PacketConn
	ctrl  net.Conn
	relay *net.UDPAddr
	mu    sync.Mutex
}

func (c *socksUDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	host, port, err := splitHostPort(addr)
	if err != nil {
		return 0, err
	}

	header, err := buildUDPHeader(host, port)
	if err != nil {
		return 0, err
	}

	pkt := make([]byte, 0, len(header)+len(p))
	pkt = append(pkt, header...)
	pkt = append(pkt, p...)

	c.mu.Lock()
	n, err := c.PacketConn.WriteTo(pkt, c.relay)
	c.mu.Unlock()
	if err != nil {
		return 0, err
	}
	// Return only the payload length that was accepted.
	sent := n - len(header)
	if sent < 0 {
		sent = 0
	}
	if sent > len(p) {
		sent = len(p)
	}
	return sent, nil
}

func (c *socksUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, 65535)
	for {
		n, _, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		payload, addr, err := parseUDPHeader(buf[:n])
		if err != nil {
			// malformed — skip
			continue
		}
		copied := copy(p, payload)
		return copied, addr, nil
	}
}

func (c *socksUDPConn) Close() error {
	_ = c.ctrl.Close()
	return c.PacketConn.Close()
}

func splitHostPort(addr net.Addr) (string, int, error) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP.String(), a.Port, nil
	case *net.TCPAddr:
		return a.IP.String(), a.Port, nil
	default:
		host, portStr, err := net.SplitHostPort(addr.String())
		if err != nil {
			return "", 0, err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return "", 0, err
		}
		return host, port, nil
	}
}

func buildUDPHeader(host string, port int) ([]byte, error) {
	// RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT
	ip := net.ParseIP(host)
	var hdr []byte
	if ip4 := ip.To4(); ip4 != nil {
		hdr = make([]byte, 0, 10)
		hdr = append(hdr, 0x00, 0x00, 0x00, 0x01)
		hdr = append(hdr, ip4...)
	} else if ip16 := ip.To16(); ip16 != nil {
		hdr = make([]byte, 0, 22)
		hdr = append(hdr, 0x00, 0x00, 0x00, 0x04)
		hdr = append(hdr, ip16...)
	} else {
		// domain name
		if len(host) > 255 {
			return nil, fmt.Errorf("domain too long")
		}
		hdr = make([]byte, 0, 7+len(host))
		hdr = append(hdr, 0x00, 0x00, 0x00, 0x03, byte(len(host)))
		hdr = append(hdr, []byte(host)...)
	}
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(port))
	hdr = append(hdr, portBuf...)
	return hdr, nil
}

func parseUDPHeader(data []byte) ([]byte, net.Addr, error) {
	if len(data) < 4 {
		return nil, nil, fmt.Errorf("udp header too short")
	}
	// RSV RSV FRAG ATYP
	if data[2] != 0 {
		return nil, nil, fmt.Errorf("fragmented UDP not supported")
	}
	pos := 4
	var host string
	switch data[3] {
	case 0x01:
		if len(data) < pos+4+2 {
			return nil, nil, fmt.Errorf("truncated ipv4")
		}
		host = net.IP(data[pos : pos+4]).String()
		pos += 4
	case 0x04:
		if len(data) < pos+16+2 {
			return nil, nil, fmt.Errorf("truncated ipv6")
		}
		host = net.IP(data[pos : pos+16]).String()
		pos += 16
	case 0x03:
		if len(data) < pos+1 {
			return nil, nil, fmt.Errorf("truncated domain len")
		}
		l := int(data[pos])
		pos++
		if len(data) < pos+l+2 {
			return nil, nil, fmt.Errorf("truncated domain")
		}
		host = string(data[pos : pos+l])
		pos += l
	default:
		return nil, nil, fmt.Errorf("unknown ATYP %d", data[3])
	}
	port := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, nil, err
	}
	return data[pos:], addr, nil
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

// SupportsUDP delegates to the current dialer.
func (s *SwappableDialer) SupportsUDP() bool {
	return s.inner.Load().SupportsUDP()
}

// ListenPacket delegates to the current dialer.
func (s *SwappableDialer) ListenPacket() (net.PacketConn, error) {
	return s.inner.Load().ListenPacket()
}

// Current returns the underlying SocksDialer.
func (s *SwappableDialer) Current() *SocksDialer {
	return s.inner.Load()
}
