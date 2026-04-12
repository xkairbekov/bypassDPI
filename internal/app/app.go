package app

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/xkairbekov/bypassdpi/internal/config"
	"github.com/xkairbekov/bypassdpi/internal/domain/policy"
	"github.com/xkairbekov/bypassdpi/internal/infrastructure/dns"
	"github.com/xkairbekov/bypassdpi/internal/infrastructure/proxy"
)

func Run(ctx context.Context, cfg config.Config, logger *slog.Logger, startupLogger *slog.Logger) error {
	resolver, err := dns.NewResolver(dns.Config{
		DNS:     cfg.DNS,
		DoHURL:  cfg.DoHURL,
		Timeout: cfg.DialTimeout,
	})
	if err != nil {
		return fmt.Errorf("build resolver: %w", err)
	}

	server := proxy.NewServer(
		proxy.Options{
			Listen:             cfg.Listen,
			MaxConnections:     cfg.MaxConnections,
			DialTimeout:        cfg.DialTimeout,
			IdleTimeout:        cfg.IdleTimeout,
			ClientHelloTimeout: cfg.ClientHelloTimeout,
			SplitDelay:         cfg.SplitDelay,
		},
		resolver,
		policy.New(cfg.Domains),
		logger,
		startupLogger,
	)

	if err := server.ListenAndServe(ctx); err != nil {
		return fmt.Errorf("serve proxy: %w", err)
	}

	return nil
}
