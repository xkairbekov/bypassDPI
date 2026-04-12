package tlshello

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrNotTLS            = errors.New("payload is not a TLS record")
	ErrNotClientHello    = errors.New("payload is not a TLS ClientHello")
	ErrIncompleteHello   = errors.New("incomplete TLS ClientHello")
	ErrMissingServerName = errors.New("TLS ClientHello does not contain SNI")
)

type Inspection struct {
	ServerName    string
	HostnameStart int
	HostnameEnd   int
}

func Inspect(payload []byte) (Inspection, error) {
	if len(payload) < 5 {
		return Inspection{}, ErrIncompleteHello
	}
	if payload[0] != 0x16 {
		return Inspection{}, ErrNotTLS
	}

	recordLength := int(binary.BigEndian.Uint16(payload[3:5]))
	recordEnd := 5 + recordLength
	if len(payload) < recordEnd {
		return Inspection{}, ErrIncompleteHello
	}
	if recordEnd < 9 {
		return Inspection{}, ErrIncompleteHello
	}
	if payload[5] != 0x01 {
		return Inspection{}, ErrNotClientHello
	}

	handshakeLength := int(payload[6])<<16 | int(payload[7])<<8 | int(payload[8])
	bodyEnd := 9 + handshakeLength
	if bodyEnd > recordEnd || len(payload) < bodyEnd {
		return Inspection{}, ErrIncompleteHello
	}

	offset := 9
	offset += 2  // client version
	offset += 32 // random
	if offset >= bodyEnd {
		return Inspection{}, ErrIncompleteHello
	}

	sessionIDLength := int(payload[offset])
	offset++
	offset += sessionIDLength
	if offset+2 > bodyEnd {
		return Inspection{}, ErrIncompleteHello
	}

	cipherSuitesLength := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2 + cipherSuitesLength
	if offset >= bodyEnd {
		return Inspection{}, ErrIncompleteHello
	}

	compressionMethodsLength := int(payload[offset])
	offset++
	offset += compressionMethodsLength
	if offset+2 > bodyEnd {
		return Inspection{}, ErrIncompleteHello
	}

	extensionsLength := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2
	extensionsEnd := offset + extensionsLength
	if extensionsEnd > bodyEnd {
		return Inspection{}, ErrIncompleteHello
	}

	for offset+4 <= extensionsEnd {
		extensionType := binary.BigEndian.Uint16(payload[offset : offset+2])
		extensionLength := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		dataStart := offset + 4
		dataEnd := dataStart + extensionLength
		if dataEnd > extensionsEnd {
			return Inspection{}, ErrIncompleteHello
		}

		if extensionType == 0x0000 {
			return inspectServerName(payload, dataStart, dataEnd)
		}

		offset = dataEnd
	}

	return Inspection{}, ErrMissingServerName
}

func PreferredSplitOffset(inspection Inspection) (int, error) {
	if inspection.HostnameEnd-inspection.HostnameStart < 2 {
		return 0, fmt.Errorf("SNI host %q is too short to split safely", inspection.ServerName)
	}

	offset := inspection.HostnameStart + PreferredHostOffset(inspection.ServerName)
	if offset <= inspection.HostnameStart || offset >= inspection.HostnameEnd {
		offset = inspection.HostnameStart + 1
	}
	if offset <= inspection.HostnameStart || offset >= inspection.HostnameEnd {
		return 0, fmt.Errorf("unable to resolve split point inside %q", inspection.ServerName)
	}

	return offset, nil
}

func inspectServerName(payload []byte, start int, end int) (Inspection, error) {
	if start+2 > end {
		return Inspection{}, ErrIncompleteHello
	}

	serverNameListLength := int(binary.BigEndian.Uint16(payload[start : start+2]))
	offset := start + 2
	listEnd := offset + serverNameListLength
	if listEnd > end {
		return Inspection{}, ErrIncompleteHello
	}

	for offset+3 <= listEnd {
		nameType := payload[offset]
		nameLength := int(binary.BigEndian.Uint16(payload[offset+1 : offset+3]))
		offset += 3
		if offset+nameLength > listEnd {
			return Inspection{}, ErrIncompleteHello
		}
		if nameType == 0 {
			host := strings.ToLower(string(payload[offset : offset+nameLength]))
			return Inspection{
				ServerName:    host,
				HostnameStart: offset,
				HostnameEnd:   offset + nameLength,
			}, nil
		}
		offset += nameLength
	}

	return Inspection{}, ErrMissingServerName
}

func PreferredHostOffset(host string) int {
	if host == "" {
		return 1
	}

	labels := strings.Split(host, ".")
	offset := 0
	for index, label := range labels {
		if label == "" {
			offset++
			continue
		}

		isLast := index == len(labels)-1
		if !isLast && !isGenericLabel(label) && len(label) >= 2 {
			return offset + 1
		}

		offset += len(label)
		if !isLast {
			offset++
		}
	}

	return 1
}

func isGenericLabel(label string) bool {
	switch label {
	case "www", "ww", "w", "m", "mobile", "amp", "cdn", "static", "img", "images", "assets", "edge", "api", "app":
		return true
	default:
		return false
	}
}
