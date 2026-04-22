package proxy

import "time"

const (
	maxInitialPayload = 32 << 10
	maxPeekBuffer     = 64 << 10
	maxHTTPHeaderSize = 1 << 20
)

const (
	defaultDialTimeout            = 10 * time.Second
	defaultIdleTimeout            = 2 * time.Minute
	defaultClientHelloTimeout     = 5 * time.Second
	serverReadHeaderTimeout       = 10 * time.Second
	serverShutdownTimeout         = 10 * time.Second
	upstreamResponseHeaderTimeout = 30 * time.Second
	upstreamExpectContinueTimeout = 1 * time.Second
)
