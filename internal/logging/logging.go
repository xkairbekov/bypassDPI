package logging

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

func New(level slog.Level) *slog.Logger {
	return newLogger(level)
}

func Always() *slog.Logger {
	return newLogger(slog.LevelDebug)
}

func newLogger(level slog.Level) *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))
}

func ParseLevel(value string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return slog.LevelDebug, nil
	case "", "info":
		return slog.LevelInfo, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unsupported log level %q", value)
	}
}
