package resolver

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Resolver interface {
	Resolve(ctx context.Context, hostname string) (string, error)
}

type DoHResolver struct {
	serverURL string
	client    *http.Client
	cacheTTL  time.Duration

	mu    sync.RWMutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	ip        string
	expiresAt time.Time
}

func NewDoHResolver(serverURL string, cacheTTL time.Duration) *DoHResolver {
	return &DoHResolver{
		serverURL: serverURL,
		client:    &http.Client{Timeout: 5 * time.Second},
		cacheTTL:  cacheTTL,
		cache:     make(map[string]cacheEntry),
	}
}

func (r *DoHResolver) Resolve(ctx context.Context, hostname string) (string, error) {
	if ip, ok := r.lookupCache(hostname); ok {
		return ip, nil
	}

	ip, err := r.resolve(ctx, hostname)
	if err != nil {
		return "", err
	}

	r.storeCache(hostname, ip)
	return ip, nil
}

// resolve sends an RFC 8484 DNS-over-HTTPS request (GET with ?dns=<base64url wire>).
// This format is supported by all standard DoH servers: AdGuard, Cloudflare, Google, etc.
func (r *DoHResolver) resolve(ctx context.Context, hostname string) (string, error) {
	queryID := uint16(rand.Intn(0xFFFF) + 1) //nolint:gosec
	wire := buildDNSQuery(hostname, queryID)

	encoded := base64.RawURLEncoding.EncodeToString(wire)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.serverURL, nil)
	if err != nil {
		return "", err
	}

	// Preserve existing query params (e.g. auth tokens in the URL)
	q := req.URL.Query()
	q.Set("dns", encoded)
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Accept", "application/dns-message")

	resp, err := r.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("doh request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("doh read body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		preview := string(body)
		if len(preview) > 200 {
			preview = preview[:200] + "..."
		}
		return "", fmt.Errorf("doh server returned HTTP %d: %s", resp.StatusCode, preview)
	}

	return parseDNSResponse(body, queryID)
}

// buildDNSQuery builds a minimal DNS wire-format query for an A record.
func buildDNSQuery(hostname string, id uint16) []byte {
	buf := make([]byte, 0, 512)

	// Header
	buf = append(buf, byte(id>>8), byte(id)) // ID
	buf = append(buf, 0x01, 0x00)            // Flags: QR=0, RD=1
	buf = append(buf, 0x00, 0x01)            // QDCOUNT=1
	buf = append(buf, 0x00, 0x00)            // ANCOUNT=0
	buf = append(buf, 0x00, 0x00)            // NSCOUNT=0
	buf = append(buf, 0x00, 0x00)            // ARCOUNT=0

	// QNAME: label-encoded hostname
	hostname = strings.TrimSuffix(hostname, ".")
	for _, label := range strings.Split(hostname, ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0x00) // root label terminator

	// QTYPE=A (1), QCLASS=IN (1)
	buf = append(buf, 0x00, 0x01, 0x00, 0x01)

	return buf
}

// parseDNSResponse parses a DNS wire-format response and returns the first A record.
func parseDNSResponse(data []byte, queryID uint16) (string, error) {
	if len(data) < 12 {
		return "", fmt.Errorf("response too short (%d bytes)", len(data))
	}

	respID := binary.BigEndian.Uint16(data[0:2])
	if respID != queryID {
		return "", fmt.Errorf("response ID mismatch (got %d, want %d)", respID, queryID)
	}

	rcode := data[3] & 0x0F
	if rcode != 0 {
		return "", fmt.Errorf("DNS error RCODE=%d", rcode)
	}

	qdcount := int(binary.BigEndian.Uint16(data[4:6]))
	ancount := int(binary.BigEndian.Uint16(data[6:8]))
	if ancount == 0 {
		return "", fmt.Errorf("no A record in DNS response")
	}

	pos := 12

	// Skip question section
	for i := 0; i < qdcount; i++ {
		var err error
		pos, err = skipDNSName(data, pos)
		if err != nil {
			return "", fmt.Errorf("skip question name: %w", err)
		}
		pos += 4 // QTYPE + QCLASS
	}

	// Parse answer records
	for i := 0; i < ancount; i++ {
		var err error
		pos, err = skipDNSName(data, pos)
		if err != nil {
			return "", fmt.Errorf("skip answer name: %w", err)
		}

		if pos+10 > len(data) {
			return "", fmt.Errorf("truncated answer record")
		}

		rtype := binary.BigEndian.Uint16(data[pos : pos+2])
		rdlength := int(binary.BigEndian.Uint16(data[pos+8 : pos+10]))
		pos += 10

		if pos+rdlength > len(data) {
			return "", fmt.Errorf("truncated RDATA")
		}

		rdata := data[pos : pos+rdlength]
		pos += rdlength

		// Type A = 1, IPv4 is exactly 4 bytes
		if rtype == 1 && rdlength == 4 {
			return fmt.Sprintf("%d.%d.%d.%d", rdata[0], rdata[1], rdata[2], rdata[3]), nil
		}
	}

	return "", fmt.Errorf("no A record found in answer section")
}

// skipDNSName advances pos past a DNS name (handles label sequences and compression pointers).
func skipDNSName(data []byte, pos int) (int, error) {
	for {
		if pos >= len(data) {
			return 0, fmt.Errorf("name extends past end of data")
		}
		labelLen := int(data[pos])
		if labelLen == 0 {
			return pos + 1, nil
		}
		// Compression pointer (top 2 bits set)
		if labelLen&0xC0 == 0xC0 {
			return pos + 2, nil
		}
		pos += 1 + labelLen
	}
}

func (r *DoHResolver) lookupCache(hostname string) (string, bool) {
	r.mu.RLock()
	entry, ok := r.cache[hostname]
	r.mu.RUnlock()

	if !ok || time.Now().After(entry.expiresAt) {
		return "", false
	}

	return entry.ip, true
}

func (r *DoHResolver) storeCache(hostname, ip string) {
	if r.cacheTTL <= 0 {
		return
	}

	r.mu.Lock()
	r.cache[hostname] = cacheEntry{
		ip:        ip,
		expiresAt: time.Now().Add(r.cacheTTL),
	}
	r.mu.Unlock()
}
