package udpproxy

import (
	"net"
	"testing"
	"time"

	"go.uber.org/zap"
)

type mockResolver struct{ ip net.IP }

func (m mockResolver) LookupCachedIP(fqdn string) (net.IP, error) { return m.ip, nil }
func (m mockResolver) GetLastKnownDomain(ip string) string        { return "" }

func TestForwarding(t *testing.T) {
	upAddr, _ := net.ResolveUDPAddr("udp4", "127.0.0.1:443")
	upstream, err := net.ListenUDP("udp4", upAddr)
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upstream.Close()

	proxy, err := NewProxy(":0", mockResolver{ip: upAddr.IP}, zap.NewNop(), DefaultConfig())
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	proxy.clients.Store("aa", &clientInfo{
		addr:     &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
		domain:   "test",
		alpn:     "",
		lastSeen: time.Now(),
	})

	go proxy.Listen()
	time.Sleep(100 * time.Millisecond)

	proxyAddr := proxy.conns[0].LocalAddr().(*net.UDPAddr)

	client, err := net.DialUDP("udp4", nil, proxyAddr)
	if err != nil {
		t.Fatalf("dial client: %v", err)
	}
	defer client.Close()

	pkt := []byte{0xc0, 0, 0, 0, 1, 1, 0xaa, 1, 0xbb}
	if _, err := client.Write(pkt); err != nil {
		t.Fatalf("write client: %v", err)
	}
	buf := make([]byte, 64)
	upstream.SetReadDeadline(time.Now().Add(time.Second))
	n, from, err := upstream.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if from.Port != proxyAddr.Port {
		t.Fatalf("unexpected source port")
	}
	if n != len(pkt) {
		t.Fatalf("bad len")
	}

	resp := []byte{0xc0, 0, 0, 0, 1, 1, 0xbb, 1, 0xcc}
	if _, err := upstream.WriteToUDP(resp, from); err != nil {
		t.Fatalf("upstream write: %v", err)
	}
	client.SetReadDeadline(time.Now().Add(time.Second))
	n2, _, err := client.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if n2 != len(resp) {
		t.Fatalf("client len")
	}
}

func TestBroadcast(t *testing.T) {
	upAddr, _ := net.ResolveUDPAddr("udp4", "127.0.0.1:443")
	upstream, err := net.ListenUDP("udp4", upAddr)
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upstream.Close()

	proxy, err := NewProxy(":0", mockResolver{ip: upAddr.IP}, zap.NewNop(), DefaultConfig())
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	go proxy.Listen()
	time.Sleep(100 * time.Millisecond)

	proxyAddr := proxy.conns[0].LocalAddr().(*net.UDPAddr)

	c1, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatalf("listen c1: %v", err)
	}
	defer c1.Close()

	c2, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatalf("listen c2: %v", err)
	}
	defer c2.Close()

	proxy.clients.Store("a", &clientInfo{
		addr:     c1.LocalAddr().(*net.UDPAddr),
		domain:   "",
		alpn:     "",
		lastSeen: time.Now(),
	})
	proxy.clients.Store("b", &clientInfo{
		addr:     c2.LocalAddr().(*net.UDPAddr),
		domain:   "",
		alpn:     "",
		lastSeen: time.Now(),
	})

	msg := []byte("hi")
	if _, err := upstream.WriteToUDP(msg, proxyAddr); err != nil {
		t.Fatalf("send upstream: %v", err)
	}

	buf := make([]byte, 16)
	c1.SetReadDeadline(time.Now().Add(time.Second))
	n1, _, err := c1.ReadFromUDP(buf)
	if err != nil || n1 != len(msg) {
		t.Fatalf("c1 recv fail")
	}
	c2.SetReadDeadline(time.Now().Add(time.Second))
	n2, _, err := c2.ReadFromUDP(buf)
	if err != nil || n2 != len(msg) {
		t.Fatalf("c2 recv fail")
	}
}

func TestALPNPort(t *testing.T) {
	upAddr, _ := net.ResolveUDPAddr("udp4", "127.0.0.1:8853")
	upstream, err := net.ListenUDP("udp4", upAddr)
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upstream.Close()

	proxy, err := NewProxy(":0", mockResolver{ip: upAddr.IP}, zap.NewNop(), DefaultConfig())
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	proxy.clients.Store("aa", &clientInfo{
		addr:     &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
		domain:   "test",
		alpn:     "doq",
		lastSeen: time.Now(),
	})

	go proxy.Listen()
	time.Sleep(100 * time.Millisecond)

	proxyAddr := proxy.conns[0].LocalAddr().(*net.UDPAddr)

	client, err := net.DialUDP("udp4", nil, proxyAddr)
	if err != nil {
		t.Fatalf("dial client: %v", err)
	}
	defer client.Close()

	pkt := []byte{0xc0, 0, 0, 0, 1, 1, 0xaa, 1, 0xbb}
	if _, err := client.Write(pkt); err != nil {
		t.Fatalf("write client: %v", err)
	}

	buf := make([]byte, 64)
	upstream.SetReadDeadline(time.Now().Add(time.Second))
	n, from, err := upstream.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if from.Port != proxyAddr.Port {
		t.Fatalf("unexpected source port")
	}
	if n != len(pkt) {
		t.Fatalf("bad len")
	}
}
