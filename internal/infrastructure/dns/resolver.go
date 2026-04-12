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
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	defaultCacheTTL = time.Minute
	maxCacheTTL     = 5 * time.Minute
)

type Config struct {
	DNS     string
	DoHURL  string
	Timeout time.Duration
}

type Resolver interface {
	LookupIP(context.Context, string) ([]net.IP, error)
}

type cacheEntry struct {
	ips       []net.IP
	expiresAt time.Time
}

type systemResolver struct {
	timeout time.Duration
}

type plainResolver struct {
	server   string
	timeout  time.Duration
	resolver *net.Resolver
}

type dohResolver struct {
	endpoint string
	client   *http.Client
	timeout  time.Duration

	mu    sync.RWMutex
	cache map[string]cacheEntry
}

func NewResolver(cfg Config) (Resolver, error) {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	if cfg.DoHURL != "" {
		return newDoHResolver(cfg.DoHURL, cfg.DNS, timeout)
	}
	if cfg.DNS != "" {
		return newPlainResolver(cfg.DNS, timeout), nil
	}
	return &systemResolver{timeout: timeout}, nil
}

func (r *systemResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	return lookupWithResolver(ctx, r.timeout, net.DefaultResolver, host)
}

func newPlainResolver(server string, timeout time.Duration) Resolver {
	address := normalizeResolverAddress(server)
	dialer := &net.Dialer{Timeout: timeout}

	return &plainResolver{
		server:  address,
		timeout: timeout,
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network string, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, address)
			},
		},
	}
}

func (r *plainResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	ips, err := lookupWithResolver(ctx, r.timeout, r.resolver, host)
	if err != nil {
		return nil, fmt.Errorf("plain DNS lookup via %s failed for %s: %w", r.server, host, err)
	}
	return ips, nil
}

func newDoHResolver(endpoint string, bootstrapResolver string, timeout time.Duration) (Resolver, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse DoH URL: %w", err)
	}

	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}
	if bootstrap := normalizeResolverAddress(bootstrapResolver); bootstrap != "" {
		dialer.Resolver = newBootstrapResolver(bootstrap, timeout)
	}

	transport := &http.Transport{
		Proxy:               nil,
		DialContext:         dialer.DialContext,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        32,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: timeout,
	}

	return &dohResolver{
		endpoint: parsed.String(),
		client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
		timeout: timeout,
		cache:   make(map[string]cacheEntry),
	}, nil
}

func (r *dohResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	host = normalizeHost(host)
	if host == "" {
		return nil, errors.New("host is empty")
	}
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	if shouldUseSystemResolver(host) {
		return lookupWithResolver(ctx, r.timeout, net.DefaultResolver, host)
	}
	if cached, ok := r.loadCache(host); ok {
		return cached, nil
	}

	type result struct {
		answers []dnsAnswer
		err     error
	}

	results := make(chan result, 2)
	for _, recordType := range []uint16{typeA, typeAAAA} {
		go func(recordType uint16) {
			answers, err := r.exchange(ctx, host, recordType)
			results <- result{answers: answers, err: err}
		}(recordType)
	}

	collected := make([]dnsAnswer, 0, 4)
	var errs []error
	for range 2 {
		result := <-results
		if result.err != nil {
			errs = append(errs, result.err)
			continue
		}
		collected = append(collected, result.answers...)
	}

	ips, ttl := mergeAnswers(collected)
	if len(ips) == 0 {
		return nil, fmt.Errorf("DoH lookup via %s failed for %s: %w", r.endpoint, host, errors.Join(errs...))
	}

	r.storeCache(host, ips, ttl)
	return cloneIPs(ips), nil
}

func (r *dohResolver) exchange(ctx context.Context, host string, recordType uint16) ([]dnsAnswer, error) {
	query, id, err := buildQuery(host, recordType)
	if err != nil {
		return nil, err
	}

	requestCtx, cancel := withTimeout(ctx, r.timeout)
	defer cancel()

	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, r.endpoint, bytes.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("build DoH request: %w", err)
	}
	request.Header.Set("Accept", "application/dns-message")
	request.Header.Set("Content-Type", "application/dns-message")

	response, err := r.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("execute DoH request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected DoH status %s", response.Status)
	}

	payload, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return nil, fmt.Errorf("read DoH response: %w", err)
	}

	answers, err := parseAnswers(payload, id)
	if err != nil {
		return nil, fmt.Errorf("parse DoH response: %w", err)
	}

	return answers, nil
}

func (r *dohResolver) loadCache(host string) ([]net.IP, bool) {
	r.mu.RLock()
	entry, ok := r.cache[host]
	r.mu.RUnlock()
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return cloneIPs(entry.ips), true
}

func (r *dohResolver) storeCache(host string, ips []net.IP, ttl time.Duration) {
	if ttl <= 0 {
		ttl = defaultCacheTTL
	}
	if ttl > maxCacheTTL {
		ttl = maxCacheTTL
	}

	r.mu.Lock()
	r.cache[host] = cacheEntry{
		ips:       cloneIPs(ips),
		expiresAt: time.Now().Add(ttl),
	}
	r.mu.Unlock()
}

func lookupWithResolver(ctx context.Context, timeout time.Duration, resolver *net.Resolver, host string) ([]net.IP, error) {
	host = normalizeHost(host)
	if host == "" {
		return nil, errors.New("host is empty")
	}
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	lookupCtx, cancel := withTimeout(ctx, timeout)
	defer cancel()

	addrs, err := resolver.LookupIPAddr(lookupCtx, host)
	if err != nil {
		return nil, err
	}

	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IP != nil {
			ips = append(ips, addr.IP)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolver returned no IPs for %s", host)
	}

	return orderIPs(deduplicateIPs(ips)), nil
}

func withTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(ctx)
	}
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

func newBootstrapResolver(address string, timeout time.Duration) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network string, _ string) (net.Conn, error) {
			if !strings.HasPrefix(network, "tcp") {
				network = "udp"
			}
			dialer := &net.Dialer{Timeout: timeout}
			return dialer.DialContext(ctx, network, address)
		},
	}
}

func shouldUseSystemResolver(host string) bool {
	return host == "localhost" ||
		host == "host.docker.internal" ||
		strings.HasSuffix(host, ".local") ||
		!strings.Contains(host, ".")
}

func normalizeResolverAddress(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(value); err == nil {
		return value
	}
	return net.JoinHostPort(value, "53")
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.TrimSpace(host), ".")
}

func mergeAnswers(answers []dnsAnswer) ([]net.IP, time.Duration) {
	ips := make([]net.IP, 0, len(answers))
	var minTTL uint32
	for _, answer := range answers {
		if answer.IP == nil {
			continue
		}
		ips = append(ips, answer.IP)
		if minTTL == 0 || answer.TTL < minTTL {
			minTTL = answer.TTL
		}
	}

	ttl := defaultCacheTTL
	if minTTL > 0 {
		ttl = time.Duration(minTTL) * time.Second
	}

	return orderIPs(deduplicateIPs(ips)), ttl
}

func cloneIPs(ips []net.IP) []net.IP {
	cloned := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		copied := make(net.IP, len(ip))
		copy(copied, ip)
		cloned = append(cloned, copied)
	}
	return cloned
}

func deduplicateIPs(ips []net.IP) []net.IP {
	seen := make(map[string]struct{}, len(ips))
	result := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		key := ip.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, ip)
	}
	return result
}

func orderIPs(ips []net.IP) []net.IP {
	ordered := slices.Clone(ips)
	slices.SortFunc(ordered, func(a net.IP, b net.IP) int {
		a4 := a.To4() != nil
		b4 := b.To4() != nil
		switch {
		case a4 && !b4:
			return -1
		case !a4 && b4:
			return 1
		default:
			return strings.Compare(a.String(), b.String())
		}
	})
	return ordered
}
