package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
)

const (
	typeA    uint16 = 1
	typeAAAA uint16 = 28
	classIN  uint16 = 1
)

type dnsAnswer struct {
	IP  net.IP
	TTL uint32
}

var queryID atomic.Uint32

func buildQuery(host string, recordType uint16) ([]byte, uint16, error) {
	host = normalizeHost(host)
	if host == "" {
		return nil, 0, errors.New("empty DNS host")
	}

	id := uint16(queryID.Add(1))
	message := make([]byte, 12)
	binary.BigEndian.PutUint16(message[0:2], id)
	binary.BigEndian.PutUint16(message[2:4], 0x0100)
	binary.BigEndian.PutUint16(message[4:6], 1)

	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return nil, 0, fmt.Errorf("invalid DNS name %q", host)
		}
		if len(label) > 63 {
			return nil, 0, fmt.Errorf("label %q is longer than 63 bytes", label)
		}
		message = append(message, byte(len(label)))
		message = append(message, label...)
	}

	message = append(message, 0x00)
	message = appendUint16(message, recordType)
	message = appendUint16(message, classIN)

	return message, id, nil
}

func parseAnswers(message []byte, expectedID uint16) ([]dnsAnswer, error) {
	if len(message) < 12 {
		return nil, errors.New("DNS response is too short")
	}

	if responseID := binary.BigEndian.Uint16(message[0:2]); expectedID != 0 && responseID != expectedID {
		return nil, fmt.Errorf("unexpected DNS response ID %d", responseID)
	}

	flags := binary.BigEndian.Uint16(message[2:4])
	if flags&0x8000 == 0 {
		return nil, errors.New("DNS response bit is not set")
	}
	if rcode := flags & 0x000F; rcode != 0 {
		return nil, fmt.Errorf("DNS response returned rcode=%d", rcode)
	}

	questionCount := int(binary.BigEndian.Uint16(message[4:6]))
	answerCount := int(binary.BigEndian.Uint16(message[6:8]))

	offset := 12
	for range questionCount {
		next, err := skipName(message, offset)
		if err != nil {
			return nil, err
		}
		offset = next + 4
		if offset > len(message) {
			return nil, errors.New("DNS response question section is truncated")
		}
	}

	answers := make([]dnsAnswer, 0, answerCount)
	for range answerCount {
		next, err := skipName(message, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		if offset+10 > len(message) {
			return nil, errors.New("DNS answer header is truncated")
		}

		recordType := binary.BigEndian.Uint16(message[offset : offset+2])
		recordClass := binary.BigEndian.Uint16(message[offset+2 : offset+4])
		ttl := binary.BigEndian.Uint32(message[offset+4 : offset+8])
		rdLength := int(binary.BigEndian.Uint16(message[offset+8 : offset+10]))
		offset += 10

		if offset+rdLength > len(message) {
			return nil, errors.New("DNS answer data is truncated")
		}

		if recordClass == classIN {
			switch recordType {
			case typeA:
				if rdLength == net.IPv4len {
					answers = append(answers, dnsAnswer{
						IP:  net.IPv4(message[offset], message[offset+1], message[offset+2], message[offset+3]),
						TTL: ttl,
					})
				}
			case typeAAAA:
				if rdLength == net.IPv6len {
					ip := make(net.IP, net.IPv6len)
					copy(ip, message[offset:offset+rdLength])
					answers = append(answers, dnsAnswer{IP: ip, TTL: ttl})
				}
			}
		}

		offset += rdLength
	}

	if len(answers) == 0 {
		return nil, errors.New("DNS response did not contain A or AAAA answers")
	}

	return answers, nil
}

func skipName(message []byte, offset int) (int, error) {
	steps := 0
	originalOffset := offset
	jumped := false

	for {
		if offset >= len(message) {
			return 0, errors.New("DNS name is truncated")
		}

		length := int(message[offset])
		switch {
		case length == 0:
			if !jumped {
				return offset + 1, nil
			}
			return originalOffset, nil
		case length&0xC0 == 0xC0:
			if offset+1 >= len(message) {
				return 0, errors.New("DNS compression pointer is truncated")
			}
			if !jumped {
				originalOffset = offset + 2
				jumped = true
			}
			offset = ((length & 0x3F) << 8) | int(message[offset+1])
			steps++
			if steps > len(message) {
				return 0, errors.New("DNS compression pointer loop detected")
			}
		default:
			offset++
			if offset+length > len(message) {
				return 0, errors.New("DNS label is truncated")
			}
			offset += length
			if !jumped {
				originalOffset = offset
			}
		}
	}
}

func appendUint16(dst []byte, value uint16) []byte {
	return append(dst, byte(value>>8), byte(value))
}
