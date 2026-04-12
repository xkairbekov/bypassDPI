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
	DefaultMode               = "http"
	DefaultListen             = "0.0.0.0:8080"
	DefaultDNS                = "1.1.1.1"
	DefaultDoHURL             = "https://cloudflare-dns.com/dns-query"
	DefaultLogLevel           = "info"
	DefaultMaxConnections     = 512
	DefaultDialTimeout        = 10 * time.Second
	DefaultIdleTimeout        = 2 * time.Minute
	DefaultClientHelloTimeout = 5 * time.Second
	DefaultSplitDelay         = 0 * time.Millisecond
)

type Config struct {
	Mode               string
	Listen             string
	DNS                string
	DoHURL             string
	LogLevel           slog.Level
	Domains            []string
	MaxConnections     int
	DialTimeout        time.Duration
	IdleTimeout        time.Duration
	ClientHelloTimeout time.Duration
	SplitDelay         time.Duration
}

func Parse(args []string) (Config, error) {
	var (
		mode       string
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
	fs.StringVar(&mode, "mode", DefaultMode, "Proxy mode. Supported: http.")
	fs.StringVar(&listen, "listen", DefaultListen, "Address to listen on.")
	fs.StringVar(&dns, "dns", DefaultDNS, "DNS resolver address. Accepts host or host:port. Used as the DoH bootstrap resolver.")
	fs.StringVar(&dohURL, "doh-url", DefaultDoHURL, "RFC 8484 DNS-over-HTTPS endpoint.")
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
		Mode:               strings.TrimSpace(mode),
		Listen:             strings.TrimSpace(listen),
		DNS:                strings.TrimSpace(dns),
		DoHURL:             strings.TrimSpace(dohURL),
		LogLevel:           level,
		Domains:            parseDomains(domainsRaw),
		MaxConnections:     maxConns,
		DialTimeout:        DefaultDialTimeout,
		IdleTimeout:        DefaultIdleTimeout,
		ClientHelloTimeout: DefaultClientHelloTimeout,
		SplitDelay:         splitDelay,
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (c Config) Validate() error {
	if c.Mode != DefaultMode {
		return fmt.Errorf("unsupported mode %q: only %s is implemented", c.Mode, DefaultMode)
	}

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
		if parsed.Scheme != "https" && parsed.Scheme != "http" {
			return fmt.Errorf("unsupported DoH URL scheme %q", parsed.Scheme)
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
	return strings.TrimSpace(`bypassdpi is a fast HTTP proxy for DPI-sensitive networks.

Usage:
  bypassdpi --mode http --listen 0.0.0.0:8080 --dns 1.1.1.1 --doh-url https://cloudflare-dns.com/dns-query --max-connections 512 --split-delay 0ms --log-level info --domains example.com,youtube.com

Flags:
  --mode http
  --listen 0.0.0.0:8080
  --dns 1.1.1.1
  --doh-url https://cloudflare-dns.com/dns-query
  --max-connections 512
  --split-delay 0ms
  --log-level info
  --domains example.com,youtube.com
  --help

Log levels:
  debug  detailed diagnostics, including TLS split events
  info   startup and high-level runtime information
  error  request-level failures
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

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) {
	return len(p), nil
}
