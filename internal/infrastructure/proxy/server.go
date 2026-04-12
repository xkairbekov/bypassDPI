package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/xkairbekov/bypassdpi/internal/domain/policy"
	"github.com/xkairbekov/bypassdpi/internal/infrastructure/dns"
)

type Options struct {
	Listen             string
	MaxConnections     int
	DialTimeout        time.Duration
	IdleTimeout        time.Duration
	ClientHelloTimeout time.Duration
	SplitDelay         time.Duration
}

type Server struct {
	options       Options
	logger        *slog.Logger
	startupLogger *slog.Logger
	resolver      dns.Resolver
	matcher       *policy.Matcher
	dialer        *outboundDialer
	transport     http.RoundTripper
}

type outboundDialer struct {
	timeout  time.Duration
	resolver dns.Resolver
}

func NewServer(options Options, resolver dns.Resolver, matcher *policy.Matcher, logger *slog.Logger, startupLogger *slog.Logger) *Server {
	dialer := &outboundDialer{
		timeout:  options.DialTimeout,
		resolver: resolver,
	}

	return &Server{
		options:       options,
		logger:        logger,
		startupLogger: startupLogger,
		resolver:      resolver,
		matcher:       matcher,
		dialer:        dialer,
		transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          64,
			MaxIdleConnsPerHost:   16,
			IdleConnTimeout:       options.IdleTimeout,
			ResponseHeaderTimeout: 30 * time.Second,
			TLSHandshakeTimeout:   options.DialTimeout,
			ExpectContinueTimeout: time.Second,
		},
	}
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.options.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.options.Listen, err)
	}
	defer listener.Close()
	listener = newLimitedListener(listener, s.options.MaxConnections)

	server := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       s.options.IdleTimeout,
		MaxHeaderBytes:    1 << 20,
	}

	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	startupLogger := s.startupLogger
	if startupLogger == nil {
		startupLogger = s.logger
	}

	startupLogger.Info("proxy listening",
		"listen", listener.Addr().String(),
		"mode", "http",
		"max_connections", maxConnectionsForLog(s.options.MaxConnections),
	)

	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		<-shutdownDone
		return nil
	}
	return err
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	s.handleHTTP(w, r)
}

func (d *outboundDialer) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("split dial address %q: %w", address, err)
	}

	ips, err := d.resolver.LookupIP(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}

	var lastErr error
	for _, ip := range ips {
		target := net.JoinHostPort(ip.String(), port)
		conn, err := (&net.Dialer{
			Timeout:   d.timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext(ctx, network, target)
		if err != nil {
			lastErr = err
			continue
		}

		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetNoDelay(true)
			_ = tcpConn.SetKeepAlive(true)
			_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
		}

		return conn, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("resolver returned no dialable IPs for %s", host)
	}
	return nil, fmt.Errorf("connect to %s: %w", address, lastErr)
}

func isCanceled(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

type limitedListener struct {
	net.Listener
	sem       chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

type limitedConn struct {
	net.Conn
	releaseOnce sync.Once
	release     func()
}

func newLimitedListener(listener net.Listener, maxConnections int) net.Listener {
	if maxConnections <= 0 {
		return listener
	}
	return &limitedListener{
		Listener: listener,
		sem:      make(chan struct{}, maxConnections),
		done:     make(chan struct{}),
	}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	if err := l.acquire(); err != nil {
		return nil, err
	}

	conn, err := l.Listener.Accept()
	if err != nil {
		l.release()
		return nil, err
	}

	return &limitedConn{
		Conn:    conn,
		release: l.release,
	}, nil
}

func (l *limitedListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.done)
	})
	return l.Listener.Close()
}

func (l *limitedListener) acquire() error {
	select {
	case l.sem <- struct{}{}:
		return nil
	case <-l.done:
		return net.ErrClosed
	}
}

func (l *limitedListener) release() {
	select {
	case <-l.sem:
	default:
	}
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.releaseOnce.Do(c.release)
	return err
}

func (c *limitedConn) CloseWrite() error {
	type closeWriter interface {
		CloseWrite() error
	}

	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

func maxConnectionsForLog(value int) any {
	if value <= 0 {
		return "unlimited"
	}
	return value
}
