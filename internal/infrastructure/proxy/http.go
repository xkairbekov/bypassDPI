package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/xkairbekov/bypassdpi/internal/domain/tlshello"
)

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	startedAt := time.Now()

	targetURL, err := outboundURL(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	outboundRequest := r.Clone(r.Context())
	outboundRequest.URL = targetURL
	outboundRequest.RequestURI = ""
	if outboundRequest.Host == "" {
		outboundRequest.Host = targetURL.Host
	}
	removeHopByHopHeaders(outboundRequest.Header)

	if strings.EqualFold(targetURL.Scheme, "http") && s.matcher.Match(targetURL.Hostname()) {
		if handled := s.handleBypassedHTTP(w, outboundRequest, startedAt); handled {
			return
		}
	}

	response, err := s.transport.RoundTrip(outboundRequest)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		if isCanceled(err) {
			s.logger.Debug("HTTP request ended before upstream response",
				"method", r.Method,
				"host", targetURL.Host,
				"error", err,
			)
		} else {
			s.logger.Error("failed to proxy HTTP request",
				"method", r.Method,
				"host", targetURL.Host,
				"error", err,
				"duration", time.Since(startedAt),
			)
		}
		return
	}
	defer response.Body.Close()

	removeHopByHopHeaders(response.Header)
	copyHeaders(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)

	written, err := io.Copy(w, response.Body)
	if err != nil {
		s.logger.Debug("HTTP response stream ended with error",
			"method", r.Method,
			"host", targetURL.Host,
			"status", response.StatusCode,
			"bytes", written,
			"error", err,
			"duration", time.Since(startedAt),
		)
		return
	}

	s.logger.Debug("proxied HTTP request",
		"method", r.Method,
		"host", targetURL.Host,
		"status", response.StatusCode,
		"bytes", written,
		"duration", time.Since(startedAt),
	)
}

func (s *Server) handleBypassedHTTP(w http.ResponseWriter, request *http.Request, startedAt time.Time) bool {
	targetAddress := normalizeHTTPAddress(request.URL.Host)

	conn, err := s.dialer.DialContext(request.Context(), "tcp", targetAddress)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		if isCanceled(err) {
			s.logger.Debug("HTTP bypass request ended before upstream was ready",
				"method", request.Method,
				"host", request.URL.Host,
				"error", err,
			)
		} else {
			s.logger.Error("failed to establish HTTP bypass upstream",
				"method", request.Method,
				"host", request.URL.Host,
				"error", err,
				"duration", time.Since(startedAt),
			)
		}
		return true
	}
	defer conn.Close()

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-done:
		case <-request.Context().Done():
			_ = conn.Close()
		}
	}()

	rawRequest, splitOffset, manipulated, err := buildManipulatedHTTPRequest(request)
	if err != nil {
		s.logger.Debug("failed to build manipulated HTTP request",
			"method", request.Method,
			"host", request.URL.Host,
			"error", err,
		)
		return false
	}
	if !manipulated {
		return false
	}

	if err := writeSplit(conn, rawRequest, splitOffset, s.options.SplitDelay); err != nil {
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		s.logger.Error("failed to send manipulated HTTP request",
			"method", request.Method,
			"host", request.URL.Host,
			"error", err,
			"duration", time.Since(startedAt),
		)
		return true
	}

	response, err := http.ReadResponse(bufio.NewReaderSize(conn, 32<<10), request)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		s.logger.Error("failed to read manipulated HTTP response",
			"method", request.Method,
			"host", request.URL.Host,
			"error", err,
			"duration", time.Since(startedAt),
		)
		return true
	}
	defer response.Body.Close()

	removeHopByHopHeaders(response.Header)
	copyHeaders(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)

	written, err := io.Copy(w, response.Body)
	if err != nil {
		s.logger.Debug("manipulated HTTP response stream ended with error",
			"method", request.Method,
			"host", request.URL.Host,
			"status", response.StatusCode,
			"bytes", written,
			"error", err,
			"duration", time.Since(startedAt),
		)
		return true
	}

	s.logger.Debug("applied HTTP Host bypass",
		"method", request.Method,
		"host", request.URL.Host,
		"status", response.StatusCode,
		"bytes", written,
		"split_offset", splitOffset,
		"duration", time.Since(startedAt),
	)

	return true
}

func buildManipulatedHTTPRequest(request *http.Request) ([]byte, int, bool, error) {
	cloned := request.Clone(request.Context())
	cloned.RequestURI = ""
	cloned.Close = true

	var raw bytes.Buffer
	if err := cloned.Write(&raw); err != nil {
		return nil, 0, false, fmt.Errorf("serialize request: %w", err)
	}

	payload := raw.Bytes()
	hostHeaderIndex := bytes.Index(payload, []byte("\r\nHost:"))
	if hostHeaderIndex < 0 {
		return payload, 0, false, nil
	}

	headerStart := hostHeaderIndex + 2
	valueStart := headerStart + len("Host:")
	for valueStart < len(payload) && (payload[valueStart] == ' ' || payload[valueStart] == '\t') {
		valueStart++
	}

	valueEndRel := bytes.Index(payload[valueStart:], []byte("\r\n"))
	if valueEndRel < 0 {
		return nil, 0, false, fmt.Errorf("locate Host header terminator")
	}
	valueEnd := valueStart + valueEndRel
	hostValue := string(payload[valueStart:valueEnd])
	hostOffset := preferredHTTPHostOffset(hostValue)
	if hostOffset <= 0 {
		hostOffset = 1
	}

	rewritten := make([]byte, 0, len(payload)-1)
	rewritten = append(rewritten, payload[:headerStart]...)
	rewritten = append(rewritten, []byte("hOSt:")...)
	rewritten = append(rewritten, payload[valueStart:valueEnd]...)
	rewritten = append(rewritten, payload[valueEnd:]...)

	splitOffset := headerStart + len("hOSt:") + hostOffset
	if splitOffset <= 0 || splitOffset >= len(rewritten) {
		splitOffset = 0
	}

	return rewritten, splitOffset, true, nil
}

func preferredHTTPHostOffset(hostValue string) int {
	host := strings.TrimSpace(hostValue)
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return 1
	}
	if ip := net.ParseIP(host); ip != nil {
		return 1
	}

	offset := tlshello.PreferredHostOffset(host)
	if offset <= 0 || offset >= len(host) {
		return 1
	}
	return offset
}

func normalizeHTTPAddress(host string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, "80")
}

func outboundURL(r *http.Request) (*url.URL, error) {
	if r.URL == nil {
		return nil, fmt.Errorf("request URL is missing")
	}

	clone := *r.URL
	if clone.Scheme == "" {
		clone.Scheme = "http"
	}
	if clone.Host == "" {
		clone.Host = r.Host
	}
	if clone.Host == "" {
		return nil, fmt.Errorf("request host is missing")
	}
	if clone.Path == "" {
		clone.Path = "/"
	}

	return &clone, nil
}

func copyHeaders(dst http.Header, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func removeHopByHopHeaders(header http.Header) {
	connectionValues := append([]string(nil), header.Values("Connection")...)

	for _, key := range []string{
		"Connection",
		"Proxy-Connection",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Keep-Alive",
		"TE",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		header.Del(key)
	}

	for _, value := range connectionValues {
		for _, token := range strings.Split(value, ",") {
			header.Del(strings.TrimSpace(token))
		}
	}
}
