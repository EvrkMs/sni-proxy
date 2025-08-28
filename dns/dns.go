package dns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Config struct {
	DOHURLs              []string
	LookupTimeout        time.Duration
	CacheCleanupInterval time.Duration
	MinTTL               time.Duration
	MaxTTL               time.Duration
	HistoryTTL           time.Duration
	Retries              int
	InitialBackoff       time.Duration
	UseIPv6              bool
}

type endpoint struct {
	scheme string
	addr   string
	client *http.Client
}

type cacheEntry struct {
	ips []net.IP
	exp time.Time
}

type domEntry struct {
	domain string
	exp    time.Time
}

type Resolver struct {
	cfg     Config
	eps     []endpoint
	tls     *dns.Client
	cache   sync.Map // fqdn -> cacheEntry
	hist    sync.Map // ip -> cacheEntry
	histDom sync.Map // ip -> domEntry
}

func NewResolver(cfg Config) *Resolver {
	if cfg.LookupTimeout == 0 {
		cfg.LookupTimeout = 4 * time.Second
	}
	if cfg.CacheCleanupInterval == 0 {
		cfg.CacheCleanupInterval = 10 * time.Minute
	}
	if cfg.MaxTTL == 0 {
		cfg.MaxTTL = 30 * time.Minute
	}
	if cfg.HistoryTTL == 0 {
		cfg.HistoryTTL = 5 * time.Minute
	}

	tlsCli := &dns.Client{Net: "tcp-tls", Timeout: cfg.LookupTimeout}
	var eps []endpoint
	for _, raw := range cfg.DOHURLs {
		if !strings.Contains(raw, "://") {
			raw = "https://" + raw
		}
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		switch u.Scheme {
		case "https":
			eps = append(eps, endpoint{
				scheme: "https",
				addr:   u.String(),
				client: &http.Client{Timeout: cfg.LookupTimeout},
			})
		case "tls":
			host := u.Host
			if !strings.Contains(host, ":") {
				host += ":853"
			}
			eps = append(eps, endpoint{scheme: "tls", addr: host})
		}
	}

	r := &Resolver{cfg: cfg, eps: eps, tls: tlsCli}
	go r.cleanupLoop()
	return r
}

func (r *Resolver) cleanupLoop() {
	ticker := time.NewTicker(r.cfg.CacheCleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		r.cache.Range(func(k, v any) bool {
			if now.After(v.(cacheEntry).exp) {
				r.cache.Delete(k)
			}
			return true
		})
		r.hist.Range(func(k, v any) bool {
			if now.After(v.(cacheEntry).exp) {
				r.hist.Delete(k)
			}
			return true
		})
		r.histDom.Range(func(k, v any) bool {
			if now.After(v.(domEntry).exp) {
				r.histDom.Delete(k)
			}
			return true
		})
	}
}

func (r *Resolver) LookupIPs(ctx context.Context, fqdn string) ([]net.IP, error) {
	return r.lookup(ctx, fqdn)
}

func (r *Resolver) GetLastKnownDomain(ip string) string {
	if v, ok := r.histDom.Load(ip); ok {
		e := v.(domEntry)
		if time.Now().Before(e.exp) {
			return e.domain
		}
	}
	if v, ok := r.hist.Load(ip); ok {
		if ent := v.(cacheEntry); time.Now().Before(ent.exp) && len(ent.ips) > 0 {
			return ent.ips[0].String()
		}
	}
	return ""
}

func (r *Resolver) LookupCachedIP(fqdn string) (net.IP, error) {
	if v, ok := r.cache.Load(fqdn); ok {
		c := v.(cacheEntry)
		if time.Now().Before(c.exp) {
			if len(c.ips) > 0 {
				return c.ips[0], nil
			}
			return nil, errors.New("cached no A records")
		}
	}
	return nil, errors.New("no cached IP for " + fqdn)
}

func (r *Resolver) ForceHistory(ip, fqdn string) {
	if net.ParseIP(ip) == nil || fqdn == "" {
		return
	}
	ttl := r.cfg.HistoryTTL
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	r.histDom.Store(ip, domEntry{
		domain: fqdn,
		exp:    time.Now().Add(ttl),
	})
}

func (r *Resolver) lookup(ctx context.Context, fqdn string) ([]net.IP, error) {
	if v, ok := r.cache.Load(fqdn); ok {
		c := v.(cacheEntry)
		if time.Now().Before(c.exp) {
			if len(c.ips) > 0 {
				return c.ips, nil
			}
			return nil, errors.New("cached no A records")
		}
	}

	retries := r.cfg.Retries
	if retries == 0 {
		retries = 2
	}
	backoff := r.cfg.InitialBackoff
	if backoff == 0 {
		backoff = 500 * time.Millisecond
	}

	types := []uint16{dns.TypeA}
	if r.cfg.UseIPv6 {
		types = append(types, dns.TypeAAAA)
	}

	type result struct {
		ips []net.IP
		err error
	}
	results := make(chan result, len(r.eps)*len(types))

	var wg sync.WaitGroup
	for attempt := 0; attempt <= retries; attempt++ {
		for _, t := range types {
			for _, ep := range r.eps {
				wg.Add(1)
				go func(ep endpoint, t uint16) {
					defer wg.Done()
					msg := new(dns.Msg)
					msg.SetQuestion(dns.Fqdn(fqdn), t)
					var resp *dns.Msg
					var err error
					switch ep.scheme {
					case "https":
						resp, err = r.sendDoH(ctx, ep.client, ep.addr, msg)
					case "tls":
						resp, _, err = r.tls.ExchangeContext(ctx, msg, ep.addr)
					default:
						err = errors.New("unknown scheme")
					}
					if err != nil || resp == nil || resp.Rcode != dns.RcodeSuccess {
						results <- result{nil, err}
						return
					}
					var ips []net.IP
					for _, rr := range resp.Answer {
						switch rr := rr.(type) {
						case *dns.A:
							ips = append(ips, rr.A)
							r.hist.Store(rr.A.String(), cacheEntry{
								ips: []net.IP{net.ParseIP(fqdn)},
								exp: time.Now().Add(r.cfg.HistoryTTL),
							})
						case *dns.AAAA:
							if r.cfg.UseIPv6 {
								ips = append(ips, rr.AAAA)
								r.hist.Store(rr.AAAA.String(), cacheEntry{
									ips: []net.IP{net.ParseIP(fqdn)},
									exp: time.Now().Add(r.cfg.HistoryTTL),
								})
							}
						}
					}
					results <- result{ips, nil}
				}(ep, t)
			}
		}

		go func() {
			wg.Wait()
			close(results)
		}()

		for res := range results {
			if res.err == nil && len(res.ips) > 0 {
				ttl := r.cfg.MaxTTL
				r.cache.Store(fqdn, cacheEntry{ips: res.ips, exp: time.Now().Add(ttl)})
				return res.ips, nil
			}
		}
		if attempt < retries {
			time.Sleep(backoff)
			backoff *= 2
		}
	}
	r.cache.Store(fqdn, cacheEntry{ips: nil, exp: time.Now().Add(30 * time.Second)})
	return nil, errors.New("no valid DNS response")
}

func (r *Resolver) sendDoH(ctx context.Context, client *http.Client, url string, msg *dns.Msg) (*dns.Msg, error) {
	buf, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH request failed with status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var reply dns.Msg
	if err := reply.Unpack(body); err != nil {
		return nil, err
	}
	return &reply, nil
}
