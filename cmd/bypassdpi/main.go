package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/xkairbekov/bypassdpi/internal/app"
	"github.com/xkairbekov/bypassdpi/internal/config"
	"github.com/xkairbekov/bypassdpi/internal/logging"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Parse(os.Args[1:])
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stdout, config.Usage())
			return nil
		}
		return err
	}

	startupLogger := logging.Startup()
	logger := logging.New(cfg.LogLevel)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	startupLogger.Info("starting bypassdpi",
		"mode", cfg.Mode,
		"listen", cfg.Listen,
		"dns", fallback(cfg.DNS, "system"),
		"doh_url", fallback(cfg.DoHURL, "disable"),
		"max_connections", maxConnectionsForLog(cfg.MaxConnections),
		"split_delay", cfg.SplitDelay,
		"log_level", strings.ToLower(cfg.LogLevel.String()),
		"domains", domainsForLog(cfg.Domains),
	)

	return app.Run(ctx, cfg, logger, startupLogger)
}

func fallback(value string, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
}

func domainsForLog(domains []string) any {
	if len(domains) == 0 {
		return "all"
	}
	return strings.Join(domains, ",")
}

func maxConnectionsForLog(value int) any {
	if value <= 0 {
		return "unlimited"
	}
	return value
}
