package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/xkairbekov/bypassdpi/internal/domain/tlshello"
)

var connectEstablishedResponse = []byte("HTTP/1.1 200 Connection Established\r\n\r\n")

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	target, host, port, err := normalizeConnectTarget(r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	upstreamConn, err := s.dialer.DialContext(r.Context(), "tcp", target)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		if isCanceled(err) {
			s.logger.Debug("CONNECT request ended before upstream was ready",
				"target", target,
				"error", err,
			)
		} else {
			s.logger.Error("failed to establish CONNECT upstream",
				"target", target,
				"error", err,
			)
		}
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = upstreamConn.Close()
		http.Error(w, "server does not support connection hijacking", http.StatusInternalServerError)
		return
	}

	clientConn, rw, err := hijacker.Hijack()
	if err != nil {
		_ = upstreamConn.Close()
		s.logger.Error("failed to hijack CONNECT client connection",
			"target", target,
			"error", err,
		)
		return
	}
	defer clientConn.Close()
	defer upstreamConn.Close()

	buffered, err := drainBuffered(rw.Reader)
	if err != nil {
		s.logger.Error("failed to drain buffered CONNECT bytes",
			"target", target,
			"error", err,
		)
		return
	}

	if _, err := clientConn.Write(connectEstablishedResponse); err != nil {
		s.logger.Debug("failed to write CONNECT established response",
			"target", target,
			"error", err,
		)
		return
	}

	clientReader := bufio.NewReaderSize(io.MultiReader(bytes.NewReader(buffered), clientConn), maxPeekBuffer)
	if err := s.relayConnect(clientConn, clientReader, upstreamConn, host, port, target, r.RemoteAddr); err != nil && !isIgnorableNetworkError(err) {
		s.logger.Debug("CONNECT tunnel closed with error",
			"target", target,
			"error", err,
		)
	}
}

func (s *Server) relayConnect(clientConn net.Conn, clientReader *bufio.Reader, upstreamConn net.Conn, host string, port string, target string, remoteAddr string) error {
	errs := make(chan error, 2)

	go func() {
		errs <- copyAndCloseWrite(clientConn, upstreamConn)
	}()

	go func() {
		errs <- s.copyClientToUpstream(clientConn, clientReader, upstreamConn, host, port, target, remoteAddr)
		closeWrite(upstreamConn)
	}()

	var firstErr error
	for range 2 {
		err := <-errs
		if isIgnorableNetworkError(err) {
			continue
		}
		if firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

func (s *Server) copyClientToUpstream(clientConn net.Conn, reader *bufio.Reader, upstreamConn net.Conn, host string, port string, target string, remoteAddr string) error {
	if s.shouldInspectTLS(host, port) {
		initialPayload, err := s.readInitialTLSPayload(clientConn, reader)
		if err != nil {
			return err
		}
		if len(initialPayload) > 0 {
			if err := s.writeInitialPayload(upstreamConn, initialPayload, host, port, target, remoteAddr); err != nil {
				return fmt.Errorf("write initial CONNECT payload: %w", err)
			}
		}
	}

	_, err := io.CopyBuffer(upstreamConn, reader, make([]byte, 32<<10))
	return err
}

func (s *Server) shouldInspectTLS(host string, port string) bool {
	if port != "443" {
		return false
	}
	if s.matcher == nil || s.matcher.Match(host) {
		return true
	}
	return net.ParseIP(host) != nil
}

func (s *Server) readInitialTLSPayload(clientConn net.Conn, reader *bufio.Reader) ([]byte, error) {
	if s.options.ClientHelloTimeout > 0 {
		_ = clientConn.SetReadDeadline(time.Now().Add(s.options.ClientHelloTimeout))
		defer func() {
			_ = clientConn.SetReadDeadline(time.Time{})
		}()
	}

	payload := make([]byte, 0, maxInitialPayload)
	chunk := make([]byte, 4<<10)

	for len(payload) < maxInitialPayload {
		n, err := reader.Read(chunk)
		if n > 0 {
			payload = append(payload, chunk[:n]...)

			_, inspectErr := tlshello.Inspect(payload)
			switch {
			case inspectErr == nil:
				return payload, nil
			case errors.Is(inspectErr, tlshello.ErrIncompleteHello):
			default:
				return payload, nil
			}
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				return payload, nil
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return payload, nil
			}
			return payload, err
		}
	}

	return payload, nil
}

func (s *Server) writeInitialPayload(upstream io.Writer, payload []byte, host string, port string, target string, remoteAddr string) error {
	if len(payload) == 0 {
		return nil
	}
	if port != "443" {
		return writeAll(upstream, payload)
	}

	inspection, err := tlshello.Inspect(payload)
	if err != nil {
		return writeAll(upstream, payload)
	}
	if !s.matcher.Match(host) && !s.matcher.Match(inspection.ServerName) {
		return writeAll(upstream, payload)
	}

	splitOffset, err := tlshello.PreferredSplitOffset(inspection)
	if err != nil {
		return writeAll(upstream, payload)
	}

	s.logger.Debug("applied SNI-aware split",
		"target", target,
		"server_name", inspection.ServerName,
		"split_offset", splitOffset,
		"split_delay", s.options.SplitDelay,
		"remote_addr", remoteAddr,
	)

	return writeTLSSplit(upstream, payload, splitOffset, s.options.SplitDelay)
}

func writeSplit(w io.Writer, payload []byte, splitOffset int, splitDelay time.Duration) error {
	if splitOffset <= 0 || splitOffset >= len(payload) {
		return writeAll(w, payload)
	}

	if err := writeAll(w, payload[:splitOffset]); err != nil {
		return err
	}
	if splitDelay > 0 {
		time.Sleep(splitDelay)
	}
	return writeAll(w, payload[splitOffset:])
}

func writeTLSSplit(w io.Writer, payload []byte, splitOffset int, splitDelay time.Duration) error {
	if splitOffset <= 5 || splitOffset >= len(payload) {
		return writeSplit(w, payload, splitOffset, splitDelay)
	}
	if len(payload) < 5 || payload[0] != 0x16 {
		return writeSplit(w, payload, splitOffset, splitDelay)
	}

	recordLength := int(payload[3])<<8 | int(payload[4])
	recordEnd := 5 + recordLength
	if recordEnd > len(payload) || splitOffset >= recordEnd {
		return writeSplit(w, payload, splitOffset, splitDelay)
	}

	firstFragmentLength := splitOffset - 5
	secondFragmentLength := recordEnd - splitOffset
	if firstFragmentLength <= 0 || secondFragmentLength <= 0 {
		return writeAll(w, payload)
	}

	firstRecord := make([]byte, 5+firstFragmentLength)
	copy(firstRecord[:3], payload[:3])
	firstRecord[3] = byte(firstFragmentLength >> 8)
	firstRecord[4] = byte(firstFragmentLength)
	copy(firstRecord[5:], payload[5:splitOffset])

	secondRecord := make([]byte, 5+secondFragmentLength)
	copy(secondRecord[:3], payload[:3])
	secondRecord[3] = byte(secondFragmentLength >> 8)
	secondRecord[4] = byte(secondFragmentLength)
	copy(secondRecord[5:], payload[splitOffset:recordEnd])

	if err := writeAll(w, firstRecord); err != nil {
		return err
	}
	if splitDelay > 0 {
		time.Sleep(splitDelay)
	}
	if err := writeAll(w, secondRecord); err != nil {
		return err
	}
	if recordEnd < len(payload) {
		return writeAll(w, payload[recordEnd:])
	}
	return nil
}

func writeAll(w io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := w.Write(payload)
		if err != nil {
			return err
		}
		payload = payload[n:]
	}
	return nil
}

func copyAndCloseWrite(dst net.Conn, src io.Reader) error {
	_, err := io.CopyBuffer(dst, src, make([]byte, 32<<10))
	closeWrite(dst)
	return err
}

func closeWrite(conn net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}

	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

func drainBuffered(reader *bufio.Reader) ([]byte, error) {
	if reader == nil || reader.Buffered() == 0 {
		return nil, nil
	}

	buffered := make([]byte, reader.Buffered())
	_, err := io.ReadFull(reader, buffered)
	return buffered, err
}

func normalizeConnectTarget(value string) (target string, host string, port string, err error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", "", errors.New("CONNECT target is empty")
	}

	if parsedHost, parsedPort, splitErr := net.SplitHostPort(value); splitErr == nil {
		return value, strings.Trim(parsedHost, "[]"), parsedPort, nil
	}

	trimmed := strings.Trim(value, "[]")
	if ip := net.ParseIP(trimmed); ip != nil {
		return net.JoinHostPort(ip.String(), "443"), ip.String(), "443", nil
	}

	return net.JoinHostPort(value, "443"), value, "443", nil
}

func isIgnorableNetworkError(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}

	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
