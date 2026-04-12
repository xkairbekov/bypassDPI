package policy

import (
	"net"
	"strings"
)

type Matcher struct {
	matchAll bool
	domains  []string
}

func New(domains []string) *Matcher {
	normalized := make([]string, 0, len(domains))
	seen := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		value := normalize(domain)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}

	return &Matcher{
		matchAll: len(normalized) == 0,
		domains:  normalized,
	}
}

func (m *Matcher) Match(host string) bool {
	if m == nil || m.matchAll {
		return true
	}

	candidate := normalize(host)
	if candidate == "" {
		return false
	}
	if ip := net.ParseIP(candidate); ip != nil {
		return false
	}

	for _, domain := range m.domains {
		if candidate == domain || strings.HasSuffix(candidate, "."+domain) {
			return true
		}
	}

	return false
}

func normalize(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	value = strings.Trim(value, "[]")
	value = strings.TrimSuffix(value, ".")
	return strings.ToLower(value)
}
