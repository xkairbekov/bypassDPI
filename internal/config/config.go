package config

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/xkairbekov/bypassdpi/internal/logging"
)

const (
	DefaultListen         = "0.0.0.0:8080"
	DefaultDNS            = "1.1.1.1"
	DefaultDoHURL         = "https://cloudflare-dns.com/dns-query"
	DefaultLogLevel       = "info"
	DefaultMaxConnections = 512
	DefaultSplitDelay     = 0 * time.Millisecond
)

type Config struct {
	Listen         string
	DNS            string
	DoHURL         string
	LogLevel       slog.Level
	Domains        []string
	MaxConnections int
	SplitDelay     time.Duration
}

func Parse(args []string) (Config, error) {
	var (
		listen     string
		dns        string
		dohURL     string
		logLevel   string
		domainsRaw string
		maxConns   int
		splitDelay time.Duration
	)

	fs := flag.NewFlagSet("bypassdpi", flag.ContinueOnError)
	fs.SetOutput(discardWriter{})
	fs.StringVar(&listen, "listen", DefaultListen, "Address to listen on.")
	fs.StringVar(&dns, "dns", DefaultDNS, "DNS resolver address. Accepts host, host:port, or \"system\". Used as the DoH bootstrap resolver.")
	fs.StringVar(&dohURL, "doh-url", DefaultDoHURL, "HTTPS DNS-over-HTTPS endpoint. Use \"disable\" to turn off DoH.")
	fs.StringVar(&logLevel, "log-level", DefaultLogLevel, "Log level. Supported: debug, info, error.")
	fs.StringVar(&domainsRaw, "domains", "", "Comma-separated list of domains to manipulate. If empty, bypass logic is applied to all proxied HTTP and HTTPS traffic.")
	fs.IntVar(&maxConns, "max-connections", DefaultMaxConnections, "Maximum number of simultaneous client connections. Use 0 to disable the limit.")
	fs.DurationVar(&splitDelay, "split-delay", DefaultSplitDelay, "Delay between the first and second split fragments.")
	fs.Usage = func() {}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return Config{}, flag.ErrHelp
		}
		return Config{}, fmt.Errorf("%w\n\n%s", err, Usage())
	}

	if fs.NArg() > 0 {
		return Config{}, fmt.Errorf("unexpected positional arguments: %s\n\n%s", strings.Join(fs.Args(), " "), Usage())
	}

	level, err := logging.ParseLevel(logLevel)
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		Listen:         strings.TrimSpace(listen),
		DNS:            normalizeDNSValue(dns),
		DoHURL:         normalizeDoHURL(dohURL),
		LogLevel:       level,
		Domains:        parseDomains(domainsRaw),
		MaxConnections: maxConns,
		SplitDelay:     splitDelay,
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (c Config) Validate() error {
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("invalid listen address %q: %w", c.Listen, err)
	}

	if c.DNS != "" {
		address := normalizeResolverAddress(c.DNS)
		if _, _, err := net.SplitHostPort(address); err != nil {
			return fmt.Errorf("invalid DNS resolver %q: %w", c.DNS, err)
		}
	}

	if c.DoHURL != "" {
		parsed, err := url.Parse(c.DoHURL)
		if err != nil {
			return fmt.Errorf("invalid DoH URL %q: %w", c.DoHURL, err)
		}
		if parsed.Scheme != "https" {
			return fmt.Errorf("invalid DoH URL %q: only https:// is supported", c.DoHURL)
		}
		if parsed.Host == "" {
			return fmt.Errorf("invalid DoH URL %q: missing host", c.DoHURL)
		}
	}

	if c.SplitDelay < 0 {
		return errors.New("split delay cannot be negative")
	}
	if c.MaxConnections < 0 {
		return errors.New("max connections cannot be negative")
	}

	return nil
}

func Usage() string {
	return strings.TrimSpace(`USAGE:
  bypassdpi [options]

OPTIONS:
  --listen string
        Proxy listen address.
        (default: "0.0.0.0:8080")

  --dns string <ip[:port]|"system">
        Bootstrap DNS server used to resolve the DoH endpoint.
        Use "system" to use the OS resolver.
        (default: "1.1.1.1")

  --doh-url string <https_url|"disable">
        DNS-over-HTTPS endpoint used for regular DNS lookups.
        Use "disable" to turn off DoH.
        (default: "https://cloudflare-dns.com/dns-query")

  --domains string
        Comma-separated domains where bypass should be applied.
        If empty, bypass is applied to all proxied traffic.

  --split-delay duration
        Delay between split fragments.
        (default: "0ms")

  --max-connections int
        Maximum simultaneous client connections.
        Use 0 to disable the limit.
        (default: 512)

  --log-level string <"error"|"info"|"debug">
        Set log verbosity.
        (default: "info")

  --help
        Show help.
`)
}

func parseDomains(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}

	seen := make(map[string]struct{})
	domains := make([]string, 0, 8)
	for _, part := range strings.Split(value, ",") {
		domain := strings.ToLower(strings.Trim(strings.TrimSpace(part), "."))
		if domain == "" {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
	}

	return domains
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

func normalizeDNSValue(value string) string {
	value = strings.TrimSpace(value)
	if strings.EqualFold(value, "system") {
		return ""
	}
	return value
}

func normalizeDoHURL(value string) string {
	value = strings.TrimSpace(value)
	if strings.EqualFold(value, "disable") {
		return ""
	}
	return value
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) {
	return len(p), nil
}
